/*
MIT License

Copyright (c) 2024 Tobias Staack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define MBEDTLS_STATUS( x ) \
    set_last_status( x )

#define CHUNK_SIZE 8192

#include <websocket/core/byte_stream.hpp>
#include <websocket/core/handshake.hpp>
#include <websocket/core/websocket.hpp>

#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

#include <mbedtls/build_info.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/timing.h>
#include <mbedtls/x509.h>
#ifdef MBEDTLS_SSL_CACHE_C
#include <mbedtls/ssl_cache.h>
#endif

struct ssl_t
{
    mbedtls_ssl_config context; /**< ssl settings context. */
    mbedtls_entropy_context entropy; /**< entropy context for random number generation. */
    mbedtls_x509_crt cert; /**< certificate context. */
    mbedtls_pk_context private_key; /**< private key context. */
    mbedtls_ssl_cache_context cache; /**< ssl cache context. */
    mbedtls_ctr_drbg_context drbg; /**< drbg context for random number generation. */

    ssl_t();

    ~ssl_t();
};

struct addr_t
{
    unsigned char bytes[ 18 ]; /**< address in byte format. */
    size_t len; /**< length of the address. */
    bool is_raw; /**< flag indicating if the address is in raw format. */
    std::string raw; /**< address in string format. */

    addr_t();

    addr_t( unsigned char *in_bytes, size_t in_len );

    addr_t( const char *in_raw );

    addr_t( const std::string &in_raw );

    void
    from_string( const std::string &in_string );

    std::string
    to_string() const;
};

struct network_stream_t
{
    c_byte_stream input;
    c_byte_stream output;

    void
    close();
};

enum class e_file_descriptor_type : unsigned char
{
    any = 0x0, /**< any type of file descriptor (non-binding). */
    bind = 0x1, /**< binding file descriptor (used to accept further connections). */
};

enum class e_file_descriptor_state : unsigned char
{
    await,
    handshake,
    open,
    close,
    terminate
};

struct file_descriptor_context
{
    mbedtls_net_context net; /**< network context for the file descriptor. */
    mbedtls_ssl_context ssl; /**< ssl context for the file descriptor. */

    addr_t addr; /**< address associated with the file descriptor. */

    e_file_descriptor_type type; /**< type of the file descriptor. */
    e_file_descriptor_state state; /**< state of the file descriptor. */

    bool was_open;

    network_stream_t stream;

    std::string sec_websocket_accept;

    c_ws_frame frame;

    mbedtls_timing_delay_context timer_ping_ctx;
    mbedtls_timing_delay_context timer_ping_pong_ctx;

    file_descriptor_context();

    ~file_descriptor_context();

    void
    timer_ping( unsigned int ms );

    void
    timer_pong( unsigned int ms );

    void
    reset_timer_pong();
};

struct c_websocket::impl_t
{
    c_websocket *instance;

    e_ws_mode mode; /**< operation mode */

    unsigned int read_timeout; /**< read timeout in milliseconds. */
    unsigned int poll_timeout; /**< poll timeout in milliseconds. */

    size_t fd_limit; /**< maximum number of file descriptors to manage. */

    mutable std::recursive_mutex mutex; /**< mutex for thread-safe operations. */

    int last_status; /**< last status code returned by an operation. */
    std::string last_error; /**< last error message. */

    ssl_t ssl;

    std::map< int, file_descriptor_context > fd_map;

    e_ws_endpoint_type endpoint;

    std::string host;
    std::string allowed_origin;

    unsigned int ping_interval;
    unsigned int ping_timeout;

    bool
    try_lock() const;

    void
    wait_lock() const;

    void
    unlock() const;

    int
    set_last_status( const int status );

    void
    set_last_error( const std::string message );

    e_ws_status
    setup( ws_settings_t *settings );

    int
    poll( file_descriptor_context *ctx );

    void
    accept( file_descriptor_context *ctx );

    void
    communicate( file_descriptor_context *ctx );

    e_ws_status
    bind( const char *bind_ip, const char *bind_port, int *out_fd );

    e_ws_status
    open( const char *host_name, const char *host_port, int *out_fd );

    void
    terminate( file_descriptor_context *ctx );

    int
    operate();

    void
    async_ws_frame( int fd, c_ws_frame frame );

    impl_t()
    {
        instance = nullptr;

        mode = e_ws_mode::mode_unsecured;

        read_timeout = 0;
        poll_timeout = 0;

        fd_limit = 0;

        last_status = 0;
        last_error = "";

        ssl = {};

        endpoint = e_ws_endpoint_type::endpoint_server;

        host = "";
        allowed_origin = "";

        ping_interval = 60 * 1000;
        ping_timeout = 30 * 1000;
    }

    ~impl_t()
    {
    }
};

ssl_t::ssl_t()
{
    mbedtls_ssl_config_init( &context );

    mbedtls_entropy_init( &entropy );
    mbedtls_x509_crt_init( &cert );
    mbedtls_pk_init( &private_key );

#ifdef MBEDTLS_SSL_CACHE_C
    mbedtls_ssl_cache_init( &cache );
#endif

    mbedtls_ctr_drbg_init( &drbg );
}

ssl_t::~ssl_t()
{
    mbedtls_ssl_config_free( &context );

    mbedtls_entropy_free( &entropy );
    mbedtls_x509_crt_free( &cert );
    mbedtls_pk_free( &private_key );

#ifdef MBEDTLS_SSL_CACHE_C
    mbedtls_ssl_cache_free( &cache );
#endif

    mbedtls_ctr_drbg_free( &drbg );
}

addr_t::addr_t()
{
    std::memset( bytes, 0, sizeof( bytes ) );
    len = 0;

    is_raw = false;
    raw = {};
}

addr_t::addr_t( unsigned char *in_bytes, size_t in_len )
{
    std::memcpy( bytes, in_bytes, sizeof( bytes ) );
    len = in_len;

    is_raw = false;
    raw = {};
}

addr_t::addr_t( const char *in_raw ) :
    addr_t()
{
    is_raw = true;
    raw = in_raw;
}

addr_t::addr_t( const std::string &in_raw ) :
    addr_t()
{
    is_raw = true;
    raw = in_raw;
}

void
addr_t::from_string( const std::string &in_string )
{
    std::memset( bytes, 0, sizeof( bytes ) );
    len = 0;

    if ( in_string.find( '.' ) != std::string::npos )
    {
        // IPv4
        len = 4;
        std::istringstream iss( in_string );
        std::string part;
        size_t i = 0;
        while ( std::getline( iss, part, '.' ) && i < len )
        {
            int byte = std::stoi( part );
            bytes[ i++ ] = static_cast< unsigned char >( byte );
        }
        if ( i != 4 )
        {
            len = 0;
            std::memset( bytes, 0, sizeof( bytes ) );
        }
    }
    else if ( in_string.find( ':' ) != std::string::npos )
    {
        // IPv6
        len = 16;
        std::istringstream iss( in_string );
        std::string part;
        size_t i = 0;
        while ( std::getline( iss, part, ':' ) && i < len )
        {
            int byte = std::stoi( part, nullptr, 16 );
            bytes[ i++ ] = static_cast< unsigned char >( byte );
        }
        if ( i != 16 )
        {
            len = 0;
            std::memset( bytes, 0, sizeof( bytes ) );
        }
    }
}

std::string
addr_t::to_string() const
{
    if ( is_raw )
    {
        return raw;
    }

    std::ostringstream oss;

    if ( len == 4 )
    {
        for ( size_t i = 0; i < len; ++i )
        {
            if ( i != 0 )
            {
                oss << '.';
            }
            oss << static_cast< int >( bytes[ i ] );
        }
    }
    else if ( len == 16 )
    {
        for ( size_t i = 0; i < len; ++i )
        {
            if ( i != 0 )
            {
                oss << ':';
            }
            oss << std::hex << static_cast< int >( bytes[ i ] );
        }
    }
    else
    {
        for ( size_t i = 0; i < len; ++i )
        {
            oss << static_cast< int >( bytes[ i ] );
        }
    }

    return oss.str();
}

void
network_stream_t::close()
{
    input.close();
    output.close();
}

file_descriptor_context::file_descriptor_context()
{
    net = {};
    ssl = {};

    addr = {};

    type = e_file_descriptor_type::any;
    state = e_file_descriptor_state::handshake;

    was_open = false;

    mbedtls_timing_set_delay( &timer_ping_ctx, 0, 0 );
    mbedtls_timing_set_delay( &timer_ping_pong_ctx, 0, 0 );
}

file_descriptor_context::~file_descriptor_context()
{
    stream.close();
}

void
file_descriptor_context::timer_ping( unsigned int ms )
{
    mbedtls_timing_set_delay( &timer_ping_ctx, 0, ms );
}

void
file_descriptor_context::timer_pong( unsigned int ms )
{
    mbedtls_timing_set_delay( &timer_ping_pong_ctx, 0, ms );
}

void
file_descriptor_context::reset_timer_pong()
{
    mbedtls_timing_set_delay( &timer_ping_pong_ctx, 0, 0 );
}

bool
c_websocket::impl_t::try_lock() const
{
    return mutex.try_lock();
}

void
c_websocket::impl_t::wait_lock() const
{
    mutex.lock();
}

void
c_websocket::impl_t::unlock() const
{
    mutex.unlock();
}

int
c_websocket::impl_t::set_last_status( const int status )
{
    last_status = status;

    if ( status < 0 )
    {
        char buffer[ 512 ];
        mbedtls_strerror( status, buffer, sizeof( buffer ) - 1 );
        set_last_error( buffer );
    }

    return status;
}

void
c_websocket::impl_t::set_last_error( const std::string message )
{
    last_error = message;

    instance->on_error( last_error.c_str() );
}

e_ws_status
c_websocket::impl_t::setup( ws_settings_t *settings )
{
    if ( settings == nullptr )
    {
        return e_ws_status::status_error;
    }

    endpoint = settings->endpoint;

    read_timeout = settings->read_timeout;
    poll_timeout = settings->poll_timeout;

    fd_limit = settings->fd_limit;

    if ( mode == e_ws_mode::mode_secured )
    {
        if ( MBEDTLS_STATUS( mbedtls_entropy_add_source( &ssl.entropy, mbedtls_platform_entropy_poll, nullptr, 32, MBEDTLS_ENTROPY_SOURCE_STRONG ) ) != 0 )
        {
            return e_ws_status::status_error;
        }

        if ( MBEDTLS_STATUS( mbedtls_ctr_drbg_seed( &ssl.drbg, mbedtls_entropy_func, &ssl.entropy, reinterpret_cast< const unsigned char * >( settings->ssl_seed ? settings->ssl_seed : "" ), settings->ssl_seed ? std::strlen( settings->ssl_seed ) : 0 ) ) != 0 )
        {
            return e_ws_status::status_error;
        }

        if ( MBEDTLS_STATUS( mbedtls_x509_crt_parse( &ssl.cert, reinterpret_cast< const unsigned char * >( settings->ssl_ca_cert ? settings->ssl_ca_cert : "" ), settings->ssl_ca_cert ? std::strlen( settings->ssl_ca_cert ) : 0 ) ) != 0 )
        {
            return e_ws_status::status_error;
        }

        if ( MBEDTLS_STATUS( mbedtls_x509_crt_parse( &ssl.cert, reinterpret_cast< const unsigned char * >( settings->ssl_own_cert ? settings->ssl_own_cert : "" ), settings->ssl_own_cert ? std::strlen( settings->ssl_own_cert ) : 0 ) ) != 0 )
        {
            return e_ws_status::status_error;
        }

        if ( MBEDTLS_STATUS( mbedtls_pk_parse_key( &ssl.private_key, reinterpret_cast< const unsigned char * >( settings->ssl_private_key ? settings->ssl_private_key : "" ), settings->ssl_private_key ? std::strlen( settings->ssl_private_key ) : 0, nullptr, 0, mbedtls_ctr_drbg_random, &ssl.drbg ) ) != 0 )
        {
            return e_ws_status::status_error;
        }

        if ( MBEDTLS_STATUS( mbedtls_ssl_config_defaults( &ssl.context, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
        {
            return e_ws_status::status_error;
        }

        mbedtls_ssl_conf_ca_chain( &ssl.context, &ssl.cert, nullptr );

        if ( MBEDTLS_STATUS( mbedtls_ssl_conf_own_cert( &ssl.context, ssl.cert.next, &ssl.private_key ) ) != 0 )
        {
            return e_ws_status::status_error;
        }

        mbedtls_ssl_conf_rng( &ssl.context, mbedtls_ctr_drbg_random, &ssl.drbg );

#ifdef MBEDTLS_SSL_CACHE_C
        mbedtls_ssl_conf_session_cache( &ssl.context, &ssl.cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set );
#endif

        mbedtls_ssl_conf_authmode( &ssl.context, MBEDTLS_SSL_VERIFY_REQUIRED );

        mbedtls_ssl_conf_read_timeout( &ssl.context, read_timeout );
    }

    host = settings->host ? settings->host : "";
    allowed_origin = settings->allowed_origin ? settings->allowed_origin : "";

    ping_interval = settings->ping_interval;
    ping_timeout = settings->ping_timeout;

    return e_ws_status::status_ok;
}

int
c_websocket::impl_t::poll( file_descriptor_context *ctx )
{
    return mbedtls_net_poll( &ctx->net, MBEDTLS_NET_POLL_READ | MBEDTLS_NET_POLL_WRITE, poll_timeout );
}

void
c_websocket::impl_t::accept( file_descriptor_context *ctx )
{
    int state = poll( ctx );

    if ( !( state & MBEDTLS_NET_POLL_READ ) )
    {
        return;
    }

    unsigned char client_addr[ 18 ];
    size_t client_addr_len = 0;
    std::memset( client_addr, 0, sizeof( client_addr ) );

    mbedtls_net_context net;
    mbedtls_net_init( &net );

    int status = MBEDTLS_STATUS( mbedtls_net_accept( &ctx->net, &net, &client_addr, sizeof( client_addr ), &client_addr_len ) );

    if ( status == MBEDTLS_ERR_SSL_WANT_READ || status == MBEDTLS_ERR_SSL_WANT_WRITE )
    {
        mbedtls_net_free( &net );
        return;
    }

    if ( MBEDTLS_STATUS( status ) != 0 )
    {
        mbedtls_net_free( &net );
        return;
    }

    if ( MBEDTLS_STATUS( mbedtls_net_set_nonblock( &net ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return;
    }

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init( &ssl );

    if ( mode == e_ws_mode::mode_secured )
    {
        if ( MBEDTLS_STATUS( mbedtls_ssl_setup( &ssl, &this->ssl.context ) ) != 0 )
        {
            mbedtls_ssl_free( &ssl );
            mbedtls_net_free( &net );
            return;
        }

        mbedtls_ssl_set_bio( &ssl, &net, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );
    }

    file_descriptor_context new_fd;
    new_fd.net = net;
    new_fd.ssl = ssl;
    new_fd.addr = { client_addr, client_addr_len };
    new_fd.type = e_file_descriptor_type::any;
    new_fd.state = e_file_descriptor_state::await;
    fd_map.emplace( std::make_pair( net.fd, new_fd ) );
}

void
c_websocket::impl_t::communicate( file_descriptor_context *ctx )
{
    int state = poll( ctx );

    if ( ctx->state == e_file_descriptor_state::await )
    {
        if ( mode == e_ws_mode::mode_secured )
        {
            if ( !( state & MBEDTLS_NET_POLL_WRITE ) )
            {
                return;
            }

            int status = MBEDTLS_STATUS( mbedtls_ssl_handshake( &ctx->ssl ) );

            if ( status == MBEDTLS_ERR_SSL_WANT_READ || status == MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                return;
            }

            if ( status != 0 )
            {
                terminate( ctx );
                return;
            }

            if ( MBEDTLS_STATUS( mbedtls_ssl_get_verify_result( &ctx->ssl ) ) != 0 )
            {
                terminate( ctx );
                return;
            }
        }

        ctx->state = e_file_descriptor_state::handshake;

        switch ( endpoint )
        {
            case e_ws_endpoint_type::endpoint_server:
                break;

            case e_ws_endpoint_type::endpoint_client:
            {
                if ( c_ws_handshake::create( host.c_str(), allowed_origin.c_str(), "/", &ctx->stream.output, ctx->sec_websocket_accept ) != c_ws_handshake::e_status::ok )
                {
                    terminate( ctx );
                    return;
                }

                break;
            }
        }

        return;
    }

    if ( ctx->state == e_file_descriptor_state::open )
    {
        if ( mbedtls_timing_get_delay( &ctx->timer_ping_pong_ctx ) == 2 )
        {
            terminate( ctx );
        }

        if ( mbedtls_timing_get_delay( &ctx->timer_ping_ctx ) == 2 )
        {
            if ( c_ws_frame( e_ws_frame_opcode::opcode_ping ).write( &ctx->stream.output ) == e_ws_frame_status::status_ok )
            {
                ctx->timer_pong( ping_timeout );
            }
        }
    }

    if ( state & MBEDTLS_NET_POLL_READ )
    {
        unsigned char buffer[ CHUNK_SIZE ];

        int status = -1;

        if ( mode == e_ws_mode::mode_secured )
        {
            status = MBEDTLS_STATUS( mbedtls_ssl_read( &ctx->ssl, buffer, CHUNK_SIZE ) );
        }
        else
        {
            status = MBEDTLS_STATUS( mbedtls_net_recv_timeout( &ctx->net, buffer, CHUNK_SIZE, read_timeout ) );
        }

        if ( status > 0 )
        {
            if ( ctx->stream.input.push_back( buffer, status ) == c_byte_stream::e_status::ok )
            {
                do
                {
                    if ( ctx->state == e_file_descriptor_state::handshake )
                    {
                        c_ws_handshake::e_status status = c_ws_handshake::e_status::ok;

                        switch ( endpoint )
                        {
                            case e_ws_endpoint_type::endpoint_server:
                                status = c_ws_handshake::server( host.c_str(), allowed_origin.c_str(), &ctx->stream.input, &ctx->stream.output );
                                break;

                            case e_ws_endpoint_type::endpoint_client:
                                status = c_ws_handshake::client( ctx->sec_websocket_accept.c_str(), &ctx->stream.input, &ctx->stream.output );
                                break;

                            default:
                                break;
                        }

                        switch ( status )
                        {
                            case e_ws_status::status_busy:
                            {
                                return;
                            }

                            case e_ws_status::status_ok:
                            {
                                ctx->state = e_file_descriptor_state::open;

                                ctx->was_open = true;

                                ctx->timer_ping( ping_interval );

                                instance->on_open( ctx->net.fd, ctx->addr.to_string().c_str() );

                                break;
                            }

                            case e_ws_status::status_error:
                            {
                                terminate( ctx );
                                return;
                            }

                            default:
                            {
                                terminate( ctx );
                                return;
                            }
                        }
                    }
                    else
                    {
                        e_ws_frame_status status = ctx->frame.read( &ctx->stream.input );

                        switch ( status )
                        {
                            case e_ws_frame_status::status_incomplete:
                            {
                                return;
                            }

                            case e_ws_frame_status::status_fragment:
                            {
                                break;
                            }

                            case e_ws_frame_status::status_final:
                            {
                                e_ws_frame_opcode opcode = ctx->frame.get_opcode();

                                switch ( opcode )
                                {
                                    case e_ws_frame_opcode::opcode_text:
                                    case e_ws_frame_opcode::opcode_binary:
                                    {
                                        std::thread( &c_websocket::impl_t::async_ws_frame, this, ctx->net.fd, std::move( ctx->frame ) ).detach();
                                        break;
                                    }

                                    case e_ws_frame_opcode::opcode_ping:
                                    {
                                        if ( c_ws_frame( e_ws_frame_opcode::opcode_pong ).write( &ctx->stream.output ) != e_ws_frame_status::status_ok )
                                        {
                                            terminate( ctx );
                                        }

                                        break;
                                    }

                                    case e_ws_frame_opcode::opcode_pong:
                                    {
                                        ctx->reset_timer_pong();
                                        ctx->timer_ping( ping_interval );
                                        break;
                                    }

                                    case e_ws_frame_opcode::opcode_close:
                                    {
                                        if ( ctx->state == e_file_descriptor_state::close )
                                        {
                                            terminate( ctx );
                                        }
                                        else
                                        {
                                            if ( c_ws_frame( e_ws_frame_opcode::opcode_close ).write( &ctx->stream.output ) != e_ws_frame_status::status_ok )
                                            {
                                                terminate( ctx );
                                            }
                                        }

                                        return;
                                    }

                                    default:
                                    {
                                        terminate( ctx );
                                        return;
                                    }
                                }

                                break;
                            }

                            case e_ws_frame_status::status_error:
                            {
                                terminate( ctx );
                                return;
                            }

                            default:
                            {
                                terminate( ctx );
                                return;
                            }
                        }
                    }
                }
                while ( ctx->stream.input.available() );
            }
        }
        else
        {
            switch ( status )
            {
                case 0:
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                case MBEDTLS_ERR_SSL_TIMEOUT:
                case MBEDTLS_ERR_NET_CONN_RESET:
                    terminate( ctx );
                    break;

                default:
                case MBEDTLS_ERR_SSL_WANT_READ:
                case MBEDTLS_ERR_SSL_WANT_WRITE:
                    // pipe is busy
                    break;
            }
        }
    }

    if ( state & MBEDTLS_NET_POLL_WRITE )
    {
        if ( ctx->stream.output.available() )
        {
            size_t length = ctx->stream.output.size() > CHUNK_SIZE ? CHUNK_SIZE : ctx->stream.output.size();

            int status = -1;

            if ( mode == e_ws_mode::mode_secured )
            {
                status = MBEDTLS_STATUS( mbedtls_ssl_write( &ctx->ssl, ctx->stream.output.pointer(), length ) );
            }
            else
            {
                status = MBEDTLS_STATUS( mbedtls_net_send( &ctx->net, ctx->stream.output.pointer(), length ) );
            }

            if ( status > 0 )
            {
                if ( ctx->stream.output.pop( status ) != c_byte_stream::e_status::ok )
                {
                    ctx->stream.output.flush();
                }
            }
            else
            {
                switch ( status )
                {
                    case 0:
                    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    case MBEDTLS_ERR_NET_CONN_RESET:
                        terminate( ctx );

                    case MBEDTLS_ERR_SSL_WANT_READ:
                    case MBEDTLS_ERR_SSL_WANT_WRITE:
                        // pipe is busy
                        break;
                }
            }
        }
    }
}

e_ws_status
c_websocket::impl_t::bind( const char *bind_ip, const char *bind_port, int *out_fd )
{
    mbedtls_net_context net;
    mbedtls_net_init( &net );

    if ( MBEDTLS_STATUS( mbedtls_net_bind( &net, bind_ip, bind_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return e_ws_status::status_error;
    }

    if ( MBEDTLS_STATUS( mbedtls_net_set_nonblock( &net ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return e_ws_status::status_error;
    }

    file_descriptor_context new_fd;
    new_fd.net = net;
    new_fd.addr = bind_ip ? bind_ip : "0.0.0.0";
    new_fd.type = e_file_descriptor_type::bind;
    new_fd.state = e_file_descriptor_state::open;
    fd_map.emplace( std::make_pair( net.fd, new_fd ) );

    if ( out_fd )
    {
        ( *out_fd ) = net.fd;
    }

    return e_ws_status::status_ok;
}

e_ws_status
c_websocket::impl_t::open( const char *host_name, const char *host_port, int *out_fd )
{
    mbedtls_net_context net;
    mbedtls_net_init( &net );

    if ( MBEDTLS_STATUS( mbedtls_net_connect( &net, host_name, host_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return e_ws_status::status_error;
    }

    if ( MBEDTLS_STATUS( mbedtls_net_set_nonblock( &net ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return e_ws_status::status_error;
    }

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init( &ssl );

    if ( mode == e_ws_mode::mode_secured )
    {
        if ( MBEDTLS_STATUS( mbedtls_ssl_setup( &ssl, &this->ssl.context ) ) != 0 )
        {
            mbedtls_ssl_free( &ssl );
            mbedtls_net_free( &net );
            return e_ws_status::status_error;
        }

        mbedtls_ssl_set_bio( &ssl, &net, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );
    }

    file_descriptor_context new_fd;
    new_fd.net = net;
    new_fd.ssl = ssl;
    new_fd.addr = host_name;
    new_fd.type = e_file_descriptor_type::any;
    new_fd.state = e_file_descriptor_state::await;
    fd_map.emplace( std::make_pair( net.fd, new_fd ) );

    if ( out_fd )
    {
        ( *out_fd ) = net.fd;
    }

    return e_ws_status::status_ok;
}

void
c_websocket::impl_t::terminate( file_descriptor_context *ctx )
{
    ctx->stream.input.flush();
    ctx->stream.output.flush();
    ctx->state = e_file_descriptor_state::terminate;
}

int
c_websocket::impl_t::operate()
{
    wait_lock();

    for ( auto it = fd_map.begin(); it != fd_map.end(); )
    {
        file_descriptor_context *ctx = &it->second;

        if ( ctx->state != e_file_descriptor_state::terminate )
        {
            ++it;
            continue;
        }

        if ( ctx->stream.output.available() )
        {
            ++it;
            continue;
        }

        if ( ctx->type != e_file_descriptor_type::bind && ctx->state == e_file_descriptor_state::open )
        {
            int state = poll( ctx );

            if ( !( state & MBEDTLS_NET_POLL_WRITE ) )
            {
                ++it;
                continue;
            }

            if ( mode == e_ws_mode::mode_secured )
            {
                int status = MBEDTLS_STATUS( mbedtls_ssl_close_notify( &ctx->ssl ) );
                if ( status == MBEDTLS_ERR_SSL_WANT_READ || status == MBEDTLS_ERR_SSL_WANT_WRITE )
                {
                    ++it;
                    continue;
                }

                MBEDTLS_STATUS( mbedtls_ssl_session_reset( &ctx->ssl ) );
            }
        }

        if ( ctx->was_open )
        {
            instance->on_close( ctx->net.fd );
        }

        mbedtls_net_close( &ctx->net );

        mbedtls_net_free( &ctx->net );
        mbedtls_ssl_free( &ctx->ssl );

        it = fd_map.erase( it );
    }

    for ( auto it = fd_map.begin(); it != fd_map.end(); ++it )
    {
        file_descriptor_context *ctx = &it->second;

        switch ( ctx->type )
        {
            case e_file_descriptor_type::bind:
            {
                // do not accept further file descriptors, if limit is exceeded.
                if ( fd_limit != 0 )
                {
                    if ( fd_map.size() == fd_limit )
                    {
                        break;
                    }
                }

                accept( ctx );
                break;
            }

            case e_file_descriptor_type::any:
            {
                communicate( ctx );
                break;
            }

            default:
            {
                terminate( ctx );
                break;
            }
        }
    }

    unlock();

    return fd_map.size() != 0;
}

void
c_websocket::impl_t::async_ws_frame( int fd, c_ws_frame frame )
{
    e_ws_frame_opcode opcode = frame.get_opcode();
    unsigned char *payload = frame.get_payload();
    size_t payload_size = frame.get_payload_size();

    instance->on_frame( fd, opcode, payload, payload_size );
}

void
c_websocket::on_open( int fd, const char *addr )
{
    if ( event_open_callback )
    {
        ( *event_open_callback )( this, fd, addr );
    }
}

void
c_websocket::on_frame( int fd, e_ws_frame_opcode opcode, unsigned char *payload, size_t size )
{
    if ( event_frame_callback )
    {
        ( *event_frame_callback )( this, fd, opcode, payload, size );
    }
}

void
c_websocket::on_close( int fd )
{
    if ( event_close_callback )
    {
        ( *event_close_callback )( this, fd );
    }
}

void
c_websocket::on_error( const char *message )
{
    if ( event_error_callback )
    {
        ( *event_error_callback )( this, message );
    }
}

c_websocket::c_websocket()
{
    event_open_callback = nullptr;
    event_close_callback = nullptr;
    event_frame_callback = nullptr;
    event_error_callback = nullptr;

    impl = new impl_t();
    impl->instance = this;
}

c_websocket::~c_websocket()
{
    delete impl;
}

e_ws_status
c_websocket::setup( ws_settings_t *settings )
{
    return impl->setup( settings );
}

e_ws_status
c_websocket::bind( const char *bind_ip, const char *bind_port, int *out_fd )
{
    return impl->bind( bind_ip, bind_port, out_fd );
}

e_ws_status
c_websocket::bind( const char *bind_port, int *out_fd )
{
    return impl->bind( NULL, bind_port, out_fd );
}

e_ws_status
c_websocket::open( const char *host_name, const char *host_port, int *out_fd )
{
    return impl->open( host_name, host_port, out_fd );
}

void
c_websocket::close( int fd )
{
    impl->wait_lock();

    if ( fd == -1 )
    {
        for ( auto it = impl->fd_map.begin(); it != impl->fd_map.end(); ++it )
        {
            close( it->first );
        }

        return;
    }

    auto it = impl->fd_map.find( fd );
    if ( it == impl->fd_map.end() )
    {
        impl->unlock();

        return;
    }

    file_descriptor_context *ctx = &it->second;

    if ( ctx->type == e_file_descriptor_type::bind )
    {
        impl->terminate( ctx );

        impl->unlock();

        return;
    }

    if ( ctx->state == e_file_descriptor_state::open )
    {
        if ( c_ws_frame( e_ws_frame_opcode::opcode_close ).write( &ctx->stream.output ) != e_ws_frame_status::status_ok )
        {
            impl->terminate( ctx );
        }
        else
        {
            ctx->state = e_file_descriptor_state::close;
        }

        impl->unlock();

        return;
    }

    impl->terminate( ctx );

    impl->unlock();
}

e_ws_status
c_websocket::on( const char *event, void *callback )
{
    if ( !std::strcmp( event, WS_EVENT_OPEN ) )
    {
        event_open_callback = reinterpret_cast< t_event_open >( callback );
        return e_ws_status::status_ok;
    }

    if ( !std::strcmp( event, WS_EVENT_CLOSE ) )
    {
        event_close_callback = reinterpret_cast< t_event_close >( callback );
        return e_ws_status::status_ok;
    }

    if ( !std::strcmp( event, WS_EVENT_FRAME ) )
    {
        event_frame_callback = reinterpret_cast< t_event_frame >( callback );
        return e_ws_status::status_ok;
    }

    if ( !std::strcmp( event, WS_EVENT_ERROR ) )
    {
        event_error_callback = reinterpret_cast< t_event_error >( callback );
        return e_ws_status::status_ok;
    }

    return e_ws_status::status_error;
}

bool
c_websocket::operate()
{
    return impl->operate();
}

e_ws_status
c_websocket::emit( int fd, c_ws_frame *frame )
{
    if ( !frame )
    {
        return e_ws_status::status_error;
    }

    auto it = impl->fd_map.find( fd );
    if ( it == impl->fd_map.end() )
    {
        return e_ws_status::status_error;
    }

    file_descriptor_context *ctx = &it->second;

    if ( ctx->state != e_file_descriptor_state::open )
    {
        return e_ws_status::status_error;
    }

    if ( frame->write( &ctx->stream.output ) != e_ws_frame_status::status_ok )
    {
        return e_ws_status::status_error;
    }

    return e_ws_status::status_ok;
}
