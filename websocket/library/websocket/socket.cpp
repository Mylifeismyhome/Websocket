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

#include <websocket/core/websocket.hpp>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#endif

#include <mbedtls/build_info.h>
#include <mbedtls/platform.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>

#ifdef MBEDTLS_SSL_CACHE_C
#include <mbedtls/ssl_cache.h>
#endif

#include <mbedtls/debug.h>

#include <map>
#include <mutex>
#include <sstream>
#include <string>

#include <websocket/core/byteStream.hpp>
#include <websocket/core/frame.hpp>
#include <websocket/core/handshake.hpp>

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
    close()
    {
        input.close();
        output.close();
    }
};

struct file_descriptor_context
{
    mbedtls_net_context net; /**< network context for the file descriptor. */
    mbedtls_ssl_context ssl; /**< ssl context for the file descriptor. */
    addr_t addr; /**< address associated with the file descriptor. */
    e_file_descriptor_type type; /**< type of the file descriptor. */
    e_file_descriptor_state state; /**< state of the file descriptor. */

    network_stream_t stream;

    std::string sec_websocket_accept;

    c_handshake::e_state handshake_state;

    c_frame frame;

    file_descriptor_context();

    ~file_descriptor_context();
};

struct c_websocket::impl_t
{
    c_websocket *instance;

    e_mode mode; /**< operation mode */

    unsigned int read_timeout; /**< read timeout in milliseconds. */
    unsigned int poll_timeout; /**< poll timeout in milliseconds. */

    size_t max_fd; /**< maximum number of file descriptors to manage. */

    mutable std::recursive_mutex mutex; /**< mutex for thread-safe operations. */

    int last_status; /**< last status code returned by an operation. */
    std::string last_error; /**< last error message. */

    ssl_t ssl;

    std::map< int, file_descriptor_context > fd_map;

    e_endpoint_type endpoint;

    std::string host;
    std::string allowed_origin;

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

    int
    setup( socket_settings_t *settings );

    e_status
    setup_ssl( mbedtls_net_context *net, mbedtls_ssl_context *ssl );

    int
    poll( file_descriptor_context *ctx );

    void
    accept( file_descriptor_context *ctx );

    void
    communicate( file_descriptor_context *ctx );

    int
    handshake( file_descriptor_context *ctx );

    int
    bind( const char *bind_ip, const char *bind_port );

    int
    open( const char *host_name, const char *host_port );

    void
    close( int fd = -1 );

    void
    transmit( int fd, unsigned char *message, size_t size );

    int
    operate();

    void
    on_open( file_descriptor_context *ctx );

    void
    on_message( file_descriptor_context *ctx );

    void
    on_close( int fd );

    void
    on_error( const char *message );

    impl_t()
    {
        instance = nullptr;

        mode = e_mode::unsecured;

        read_timeout = 0;
        poll_timeout = 0;

        max_fd = 1024;

        last_status = 0;
        last_error = "";

        ssl = {};

        endpoint = e_endpoint_type::unset;

        host = "";
        allowed_origin = "";
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

file_descriptor_context::file_descriptor_context()
{
    net = {};
    ssl = {};

    addr = {};

    type = e_file_descriptor_type::any;
    state = e_file_descriptor_state::close;

    handshake_state = c_handshake::e_state::initial;
}

file_descriptor_context::~file_descriptor_context()
{
    stream.close();
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

    on_error( last_error.c_str() );
}

int
c_websocket::impl_t::setup( socket_settings_t *settings )
{
    if ( settings == nullptr )
    {
        return -1;
    }

    endpoint = settings->endpoint;

    read_timeout = settings->read_timeout;
    poll_timeout = settings->poll_timeout;

    max_fd = settings->max_fd;

    if ( mode == e_mode::secured )
    {
        if ( MBEDTLS_STATUS( mbedtls_entropy_add_source( &ssl.entropy, mbedtls_platform_entropy_poll, nullptr, 32, MBEDTLS_ENTROPY_SOURCE_STRONG ) ) != 0 )
        {
            return -1;
        }

        if ( MBEDTLS_STATUS( mbedtls_ctr_drbg_seed( &ssl.drbg, mbedtls_entropy_func, &ssl.entropy, reinterpret_cast< const unsigned char * >( settings->ssl_seed ? settings->ssl_seed : "" ), settings->ssl_seed ? std::strlen( settings->ssl_seed ) : 0 ) ) != 0 )
        {
            return -1;
        }

        if ( MBEDTLS_STATUS( mbedtls_x509_crt_parse( &ssl.cert, reinterpret_cast< const unsigned char * >( settings->ssl_ca_cert ? settings->ssl_ca_cert : "" ), settings->ssl_ca_cert ? std::strlen( settings->ssl_ca_cert ) : 0 ) ) != 0 )
        {
            return -1;
        }

        if ( MBEDTLS_STATUS( mbedtls_x509_crt_parse( &ssl.cert, reinterpret_cast< const unsigned char * >( settings->ssl_own_cert ? settings->ssl_own_cert : "" ), settings->ssl_own_cert ? std::strlen( settings->ssl_own_cert ) : 0 ) ) != 0 )
        {
            return -1;
        }

        if ( MBEDTLS_STATUS( mbedtls_pk_parse_key( &ssl.private_key, reinterpret_cast< const unsigned char * >( settings->ssl_private_key ? settings->ssl_private_key : "" ), settings->ssl_private_key ? std::strlen( settings->ssl_private_key ) : 0, nullptr, 0, mbedtls_ctr_drbg_random, &ssl.drbg ) ) != 0 )
        {
            return -1;
        }

        if ( MBEDTLS_STATUS( mbedtls_ssl_config_defaults( &ssl.context, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
        {
            return -1;
        }

        mbedtls_ssl_conf_ca_chain( &ssl.context, &ssl.cert, nullptr );

        if ( MBEDTLS_STATUS( mbedtls_ssl_conf_own_cert( &ssl.context, ssl.cert.next, &ssl.private_key ) ) != 0 )
        {
            return -1;
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

    return 0;
}

e_status
c_websocket::impl_t::setup_ssl( mbedtls_net_context *net, mbedtls_ssl_context *ssl )
{
    if ( !net || !ssl )
    {
        return e_status::error;
    }

    if ( MBEDTLS_STATUS( mbedtls_ssl_setup( ssl, &this->ssl.context ) ) != 0 )
    {
        return e_status::error;
    }

    mbedtls_ssl_set_bio( ssl, net, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );

    return e_status::ok;
}

int
c_websocket::impl_t::handshake( file_descriptor_context *ctx )
{
    int state = poll( ctx );

    if ( !( state & MBEDTLS_NET_POLL_WRITE ) )
    {
        return 0;
    }

    int status = MBEDTLS_STATUS( mbedtls_ssl_handshake( &ctx->ssl ) );

    if ( status == MBEDTLS_ERR_SSL_WANT_READ || status == MBEDTLS_ERR_SSL_WANT_WRITE )
    {
        return 0;
    }

    if ( status != 0 )
    {
        return -1;
    }

    if ( MBEDTLS_STATUS( mbedtls_ssl_get_verify_result( &ctx->ssl ) ) != 0 )
    {
        return -1;
    }

    return 0;
}

int
c_websocket::impl_t::poll( file_descriptor_context *ctx )
{
    return mbedtls_net_poll( &ctx->net, MBEDTLS_NET_POLL_READ | MBEDTLS_NET_POLL_WRITE, poll_timeout );
}

void
c_websocket::impl_t::accept( file_descriptor_context *ctx )
{
    if ( ctx->state == e_file_descriptor_state::pending_close )
    {
        return;
    }

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

    if ( mode == e_mode::secured )
    {
        if ( setup_ssl( &net, &ssl ) == e_status::error )
        {
            mbedtls_ssl_free( &ssl );
            mbedtls_net_free( &net );
            return;
        }
    }

    file_descriptor_context new_fd;
    new_fd.net = net;
    new_fd.ssl = ssl;
    new_fd.addr = { client_addr, client_addr_len };
    new_fd.type = e_file_descriptor_type::any;
    new_fd.state = e_file_descriptor_state::close;
    fd_map.emplace( std::make_pair( net.fd, new_fd ) );
}

void
c_websocket::impl_t::communicate( file_descriptor_context *ctx )
{
    if ( ctx->state == e_file_descriptor_state::close )
    {
        if ( mode == e_mode::secured )
        {
            if ( handshake( ctx ) != 0 )
            {
                close( ctx->net.fd );
                return;
            }
        }

        ctx->state = e_file_descriptor_state::open;

        std::string addr = ctx->addr.to_string();

        on_open( ctx );
    }

    int state = poll( ctx );

    if ( state & MBEDTLS_NET_POLL_READ )
    {
        unsigned char buffer[ CHUNK_SIZE ];

        int status = -1;

        if ( mode == e_mode::secured )
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
                on_message( ctx );
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
                    ctx->stream.input.close();
                    close( ctx->net.fd );
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

            if ( mode == e_mode::secured )
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
                        ctx->stream.output.close();
                        close( ctx->net.fd );

                    case MBEDTLS_ERR_SSL_WANT_READ:
                    case MBEDTLS_ERR_SSL_WANT_WRITE:
                        // pipe is busy
                        break;
                }
            }
        }
    }
}

int
c_websocket::impl_t::bind( const char *bind_ip, const char *bind_port )
{
    mbedtls_net_context net;
    mbedtls_net_init( &net );

    if ( MBEDTLS_STATUS( mbedtls_net_bind( &net, bind_ip, bind_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return -1;
    }

    if ( MBEDTLS_STATUS( mbedtls_net_set_nonblock( &net ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return -1;
    }

    file_descriptor_context new_fd;
    new_fd.net = net;
    new_fd.addr = bind_ip ? bind_ip : "0.0.0.0";
    new_fd.type = e_file_descriptor_type::bind;
    new_fd.state = e_file_descriptor_state::open;
    fd_map.emplace( std::make_pair( net.fd, new_fd ) );

    return net.fd;
}

int
c_websocket::impl_t::open( const char *host_name, const char *host_port )
{
    mbedtls_net_context net;
    mbedtls_net_init( &net );

    if ( MBEDTLS_STATUS( mbedtls_net_connect( &net, host_name, host_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return -1;
    }

    if ( MBEDTLS_STATUS( mbedtls_net_set_nonblock( &net ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return -1;
    }

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init( &ssl );

    if ( mode == e_mode::secured )
    {
        if ( setup_ssl( &net, &ssl ) == e_status::error )
        {
            mbedtls_ssl_free( &ssl );
            mbedtls_net_free( &net );
            return -1;
        }
    }

    file_descriptor_context new_fd;
    new_fd.net = net;
    new_fd.ssl = ssl;
    new_fd.addr = host_name;
    new_fd.type = e_file_descriptor_type::any;
    new_fd.state = e_file_descriptor_state::close;
    fd_map.emplace( std::make_pair( net.fd, new_fd ) );

    return net.fd;
}

void
c_websocket::impl_t::close( int fd )
{
    wait_lock();

    auto it = fd_map.find( fd );
    if ( it == fd_map.end() )
    {
        unlock();

        return;
    }

    it->second.state = e_file_descriptor_state::pending_close;

    unlock();
}

void
c_websocket::impl_t::transmit( int fd, unsigned char *message, size_t size )
{
    if ( !message || size == 0 )
    {
        return;
    }

    auto it = fd_map.find( fd );
    if ( it == fd_map.end() )
    {
        return;
    }

    if ( it->second.state != e_file_descriptor_state::open )
    {
        return;
    }

    it->second.stream.output.push_back( message, size );
}

int
c_websocket::impl_t::operate()
{
    wait_lock();

    for ( auto it = fd_map.begin(); it != fd_map.end(); )
    {
        file_descriptor_context *ctx = &it->second;

        if ( ctx->state != e_file_descriptor_state::pending_close )
        {
            ++it;
            continue;
        }

        if ( it->second.stream.output.available() )
        {
            ++it;
            continue;
        }

        if ( it->second.type != e_file_descriptor_type::bind && it->second.state == e_file_descriptor_state::open )
        {
            int state = poll( &it->second );

            if ( !( state & MBEDTLS_NET_POLL_WRITE ) )
            {
                ++it;
                continue;
            }

            if ( mode == e_mode::secured )
            {
                int status = MBEDTLS_STATUS( mbedtls_ssl_close_notify( &it->second.ssl ) );
                if ( status == MBEDTLS_ERR_SSL_WANT_READ || status == MBEDTLS_ERR_SSL_WANT_WRITE )
                {
                    ++it;
                    continue;
                }

                MBEDTLS_STATUS( mbedtls_ssl_session_reset( &it->second.ssl ) );
            }
        }

        on_close( it->second.net.fd );

        mbedtls_net_close( &it->second.net );

        mbedtls_net_free( &it->second.net );
        mbedtls_ssl_free( &it->second.ssl );

        it->second.state = e_file_descriptor_state::close;

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
                if ( fd_map.size() > max_fd )
                {
                    break;
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
                close( ctx->net.fd );
                break;
            }
        }
    }

    unlock();

    return fd_map.size() != 0;
}

void
c_websocket::impl_t::on_open( file_descriptor_context *ctx )
{
    switch ( endpoint )
    {
        case e_endpoint_type::client:
        {
            e_status status = c_handshake::create( host.c_str(), allowed_origin.c_str(), "/", &ctx->stream.output, ctx->sec_websocket_accept );

            if ( status != e_status::ok )
            {
                close( ctx->net.fd );
                return;
            }

            break;
        }

        case e_endpoint_type::server:
            break;

        default:
            // throw exception
            close( ctx->net.fd );
            return;
    }
}

void
c_websocket::impl_t::on_message( file_descriptor_context *ctx )
{
    do
    {
        switch ( ctx->handshake_state )
        {
            case c_handshake::e_state::initial:
            {
                e_status status = e_status::ok;

                c_byte_stream output;

                switch ( endpoint )
                {
                    case e_endpoint_type::server:
                        status = c_handshake::server( host.c_str(), allowed_origin.c_str(), &ctx->stream.input, &ctx->stream.output );
                        break;

                    case e_endpoint_type::client:
                        status = c_handshake::client( ctx->sec_websocket_accept.c_str(), &ctx->stream.input, &ctx->stream.output );
                        break;

                    default:
                        break;
                }

                switch ( status )
                {
                    case e_status::busy:
                    {
                        return;
                    }

                    case e_status::ok:
                    {
                        ctx->handshake_state = c_handshake::e_state::estabilished;

                        // instance->on_open( fd, peer->addr.c_str() );

                        break;
                    }

                    case e_status::error:
                    {
                        close( ctx->net.fd );
                        return;
                    }

                    default:
                    {
                        close( ctx->net.fd );
                        return;
                    }
                }

                break;
            }

            case c_handshake::e_state::estabilished:
            {
                c_frame::e_status status = ctx->frame.read( &ctx->stream.input );

                switch ( status )
                {
                    case c_frame::e_status::wait:
                    {
                        return;
                    }

                    case c_frame::e_status::fragment:
                    {
                        break;
                    }

                    case c_frame::e_status::final:
                    {
                        e_opcode opcode = ctx->frame.get_opcode();

                        switch ( opcode )
                        {
                            case e_opcode::text:
                            case e_opcode::binary:
                            {
                                // std::thread( &c_websocket::impl_t::async_frame, this, fd, std::move( peer->frame ) ).detach();
                                break;
                            }

                            /*
                            todo:
                            Pings and Pongs: The Heartbeat of WebSockets

                            At any point after the handshake, either the client or the server can choose to send a ping to the other party.
                            When the ping is received, the recipient must send back a pong as soon as possible.
                            You can use this to make sure that the client is still connected, for example.

                            A ping or pong is just a regular frame, but it's a control frame.
                            Pings have an opcode of 0x9, and pongs have an opcode of 0xA. When you get a ping,
                            send back a pong with the exact same Payload Data as the ping (for pings and pongs,
                            the max payload length is 125). You might also get a pong without ever sending a ping;
                            ignore this if it happens.
                            */
                            case e_opcode::ping:
                            {
                                c_frame response( e_opcode::pong );
                                // instance->emit( fd, &response );
                                break;
                            }

                            case e_opcode::pong:
                            {
                                // todo: reset timer
                                printf( "PONG\n" );
                                break;
                            }

                            case e_opcode::close:
                            {
                                // if ( peer->pending_close )
                                //{
                                //     // respond received, gracefully close the socket
                                //     c_websocket::close( fd );
                                // }
                                // else
                                //{
                                //     // respond with closing frame
                                //     c_frame response( e_opcode::close );
                                //     instance->emit( fd, &response );

                                //    // gracefully close the socket
                                //    c_websocket::close( fd );
                                //}


                                return;
                            }

                            default:
                            {
                                close( ctx->net.fd );
                                return;
                            }
                        }

                        break;
                    }

                    case c_frame::e_status::error:
                    {
                        close( ctx->net.fd );
                        return;
                    }

                    default:
                    {
                        close( ctx->net.fd );
                        return;
                    }
                }

                break;
            }
        }
    }
    while ( ctx->stream.input.available() );
}

void
c_websocket::impl_t::on_close( int fd )
{
    /*peer_t *peer = get_peer( fd );

    if ( peer == nullptr )
    {
        return;
    }

    if ( peer->state == c_handshake::e_state::estabilished )
    {
        instance->on_close( fd );
    }

    erase_peer( fd );*/
}

void
c_websocket::impl_t::on_error( const char *message )
{
    //  instance->on_error( message );
}

c_websocket::c_websocket()
{
    impl = new impl_t();
    impl->instance = this;
}

c_websocket::~c_websocket()
{
    delete impl;
}

int
c_websocket::get_last_status() const
{
    return impl->last_status;
}

const char *
c_websocket::get_last_error() const
{
    return impl->last_error.c_str();
}

void
c_websocket::set_last_error( const char *message )
{
    impl->set_last_error( message );
}

int
c_websocket::setup( socket_settings_t *settings )
{
    return impl->setup( settings );
}

int
c_websocket::bind( const char *bind_ip, const char *bind_port )
{
    return impl->bind( bind_ip, bind_port );
}

int
c_websocket::bind( const char *bind_port )
{
    return impl->bind( NULL, bind_port );
}

int
c_websocket::open( const char *host_name, const char *host_port )
{
    return impl->open( host_name, host_port );
}

void
c_websocket::close( int fd )
{
    impl->close( fd );
}

void
c_websocket::transmit( int fd, unsigned char *message, size_t size )
{
    impl->transmit( fd, message, size );
}

bool
c_websocket::operate()
{
    return impl->operate();
}
