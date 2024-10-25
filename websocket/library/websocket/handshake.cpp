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
#include <websocket/core/handshake.hpp>

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <sstream>

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha1.h>

/**
 * @brief Calculates the length of a C-style string at compile-time.
 *
 * This function iterates through the string until it finds the null
 * terminator ('\0'), counting the number of characters.
 *
 * @param s A pointer to a null-terminated string.
 * @return The length of the string (not including the null terminator).
 */
constexpr size_t
constexpr_strlen( const char *s )
{
    return *s ? 1 + constexpr_strlen( s + 1 ) : 0;
}

static std::string
string_to_lower( const std::string &str )
{
    std::string result = str;

    std::transform( result.begin(), result.end(), result.begin(), []( unsigned char c )
        { return std::tolower( c ); } );

    return result;
}

static bool
string_contains_case_insensitive( const std::string &mainStr, const std::string &subStr )
{
    std::string lowerMainStr = string_to_lower( mainStr );
    std::string lowerSubStr = string_to_lower( subStr );

    return lowerMainStr.find( lowerSubStr ) != std::string::npos;
}

/**
 * @brief Represents the HTTP/1.1 header.
 *
 * This is a static constant string that represents the HTTP/1.1
 * protocol as specified in RFC 2616.
 */
static constexpr const char HTTP_HEADER[] = "HTTP/1.1";

/**
 * @brief The size of the HTTP_HEADER string.
 *
 * This constant holds the length of the HTTP_HEADER string
 * calculated at compile time.
 */
static constexpr size_t HTTP_HEADER_SIZE = constexpr_strlen( HTTP_HEADER );

/**
 * @brief Represents the WebSocket magic GUID.
 *
 * This is a static constant string that represents the WebSocket
 * magic GUID as specified in RFC 4122.
 */
static constexpr const char WS_MAGIC[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/**
 * @brief The size of the WS_MAGIC string.
 *
 * This constant holds the length of the WS_MAGIC string
 * calculated at compile time.
 */
static constexpr size_t WS_MAGIC_SIZE = constexpr_strlen( WS_MAGIC );

std::string
trim( const std::string &s )
{
    size_t start = s.find_first_not_of( " \t\r\n" );
    size_t end = s.find_last_not_of( " \t\r\n" );
    return ( start == std::string::npos || end == std::string::npos ) ? "" : s.substr( start, end - start + 1 );
}

static std::map< std::string, std::string >
parse_http_header( unsigned char *buffer, size_t len )
{
    std::map< std::string, std::string > headers;

    std::string input( reinterpret_cast< char * >( buffer ), len );

    std::istringstream stream( input );
    std::string line;

    while ( std::getline( stream, line ) )
    {
        size_t colon_pos = line.find( ':' );

        if ( colon_pos != std::string::npos )
        {
            std::string key = trim( line.substr( 0, colon_pos ) );
            std::string value = trim( line.substr( colon_pos + 1 ) );

            if ( !key.empty() )
            {
                headers[ key ] = value;
            }
        }
    }

    return headers;
}

void
c_ws_handshake::respond( int status_code, const char *message, c_byte_stream *output )
{
    if ( !output )
    {
        return;
    }

    ( *output ) << "HTTP/1.1 " << status_code << " " << message << "\r\n ";
    ( *output ) << "Content-Length: 0\r\n";
    ( *output ) << "Connection: close\r\n";
    ( *output ) << "\r\n";
}

c_ws_handshake::e_status
c_ws_handshake::random( size_t count, std::string &output )
{
    constexpr const char *pers = "websocket_handshake_random";

    unsigned char *block = reinterpret_cast< unsigned char * >( malloc( sizeof( unsigned char ) * count ) );

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    if ( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, ( const unsigned char * )pers, strlen( pers ) ) != 0 )
    {
        mbedtls_ctr_drbg_free( &ctr_drbg );
        mbedtls_entropy_free( &entropy );
        return e_status::error;
    }

    if ( mbedtls_ctr_drbg_random( &ctr_drbg, block, count ) != 0 )
    {
        mbedtls_ctr_drbg_free( &ctr_drbg );
        mbedtls_entropy_free( &entropy );
        return e_status::error;
    }

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    output.assign( std::move( reinterpret_cast< char * >( block ) ) );

    return e_status::ok;
}

c_ws_handshake::e_status
c_ws_handshake::secret( std::string input, std::string &output )
{
    // create sha1 hash
    unsigned char hash[ 20 ];

    mbedtls_sha1_context sha1_ctx;
    mbedtls_sha1_init( &sha1_ctx );

    if ( mbedtls_sha1_starts( &sha1_ctx ) != 0 )
    {
        return e_status::error;
    }

    if ( mbedtls_sha1_update( &sha1_ctx, reinterpret_cast< const unsigned char * >( input.c_str() ), input.size() ) != 0 )
    {
        return e_status::error;
    }

    if ( mbedtls_sha1_update( &sha1_ctx, reinterpret_cast< const unsigned char * >( WS_MAGIC ), WS_MAGIC_SIZE ) != 0 )
    {
        return e_status::error;
    }

    if ( mbedtls_sha1_finish( &sha1_ctx, hash ) != 0 )
    {
        return e_status::error;
    }

    mbedtls_sha1_free( &sha1_ctx );

    // base64 encode sha1 hash
    unsigned char b64[ 30 ];
    size_t olen = 0;
    if ( mbedtls_base64_encode( b64, 30, &olen, hash, 20 ) != 0 )
    {
        return e_status::error;
    }

    // assign base64 encoded to output
    output.assign( reinterpret_cast< const char * >( b64 ), 30 );

    return e_status::ok;
}

c_ws_handshake::e_status
c_ws_handshake::create( const char *host, const char *origin, const char *channel, c_byte_stream *output, std::string &out_accept_key )
{
    if ( !output )
    {
        return e_status::error;
    }

    // generate 16-byte random block
    std::string sec_websocket_key;

    if ( c_ws_handshake::random( 16, sec_websocket_key ) != e_status::ok )
    {
        return e_status::error;
    }

    // base64 encode secret-key
    unsigned char b64[ 30 ];
    size_t olen = 0;

    if ( mbedtls_base64_encode( b64, sizeof( b64 ), &olen, reinterpret_cast< const unsigned char * >( sec_websocket_key.c_str() ), sec_websocket_key.size() ) != 0 )
    {
        return e_status::error;
    }

    // create accept-key out of secret-key
    std::string accept_key;

    if ( c_ws_handshake::secret( std::string( reinterpret_cast< const char * >( b64 ), olen ), accept_key ) != e_status::ok )
    {
        return e_status::error;
    }

    // create request
    c_byte_stream request;

    request << "GET " << channel << " HTTP/1.1\r\n";
    request << "Host: " << host << "\r\n";
    request << "Upgrade: websocket\r\n";
    request << "Connection: Upgrade\r\n";
    request << "Sec-WebSocket-Key: " << b64 << "\r\n";
    request << "Sec-WebSocket-Version: 13\r\n";

    if ( origin )
    {
        request << "Origin: " << origin << "\r\n";
    }

    request << "\r\n";

    if ( request.move( output, request.size(), 0 ) != c_byte_stream::e_status::ok )
    {
        return e_status::error;
    }

    out_accept_key = accept_key;

    return e_status::ok;
}

c_ws_handshake::e_status
c_ws_handshake::client( const char *accept_key, c_byte_stream *input, c_byte_stream *output )
{
    if ( !output )
    {
        return e_status::error;
    }

    if ( !input )
    {
        respond( 500, "Internal Server Error", output );
        return e_status::error;
    }

    if ( !input->available() )
    {
        return e_status::busy;
    }

    if ( input->index_of( reinterpret_cast< unsigned char * >( ( char * )"HTTP/1.1 101 Switching Protocols" ), strlen( "HTTP/1.1 101 Switching Protocols" ) ) == c_byte_stream::npos )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    // verify http header is present
    size_t header_end = input->index_of( reinterpret_cast< unsigned char * >( ( char * )"\r\n\r\n" ), 4 );
    if ( header_end == c_byte_stream::npos )
    {
        return e_status::busy;
    }

    std::unique_ptr< unsigned char[] > header_buffer( new unsigned char[ header_end ] );

    if ( input->pull( header_buffer.get(), header_end ) != c_byte_stream::e_status::ok )
    {
        respond( 500, "Internal Server Error", output );
        return e_status::error;
    }

    // no need of body data
    input->flush();

    auto header = parse_http_header( header_buffer.get(), header_end );
    if ( header.empty() )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    // verify required attributes are present
    if ( header.find( "Upgrade" ) == header.end() ||
        header.find( "Connection" ) == header.end() ||
        header.find( "Sec-WebSocket-Accept" ) == header.end() )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    // verify |Upgrade| header field contains websocket
    std::string header_upgrade = header[ "Upgrade" ];

    if ( !string_contains_case_insensitive( header_upgrade, "websocket" ) )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    // verify |Connection| header field contains upgrade
    std::string header_connetion = header[ "Connection" ];

    if ( !string_contains_case_insensitive( header_connetion, "upgrade" ) )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    std::string sec_websocket_accept = header[ "Sec-WebSocket-Accept" ];

    // verify |Sec-WebSocket-Accept| header field matches accept-key
    if ( std::strcmp( sec_websocket_accept.c_str(), accept_key ) != 0 )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    return e_status::ok;
}

c_ws_handshake::e_status
c_ws_handshake::server( const char *host, const char *origin, c_byte_stream *input, c_byte_stream *output )
{
    if ( !output )
    {
        return e_status::error;
    }

    if ( !input )
    {
        respond( 500, "Internal Server Error", output );
        return e_status::error;
    }

    if ( !input->available() )
    {
        return e_status::busy;
    }

    // verify http header is present
    if ( input->index_of( reinterpret_cast< unsigned char * >( ( char * )HTTP_HEADER ), HTTP_HEADER_SIZE ) == c_byte_stream::npos )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    // verify http header is entirely present
    size_t header_end = input->index_of( reinterpret_cast< unsigned char * >( ( char * )"\r\n\r\n" ), 4 );
    if ( header_end == c_byte_stream::npos )
    {
        return e_status::busy;
    }

    std::unique_ptr< unsigned char[] > header_buffer( new unsigned char[ header_end ] );

    if ( input->pull( header_buffer.get(), header_end ) != c_byte_stream::e_status::ok )
    {
        respond( 500, "Internal Server Error", output );
        return e_status::error;
    }

    // no further need of holding body data after extracted header
    input->flush();

    auto header = parse_http_header( header_buffer.get(), header_end );
    if ( header.empty() )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    // verify required attributes are present
    if ( header.find( "Host" ) == header.end() ||
        header.find( "Upgrade" ) == header.end() ||
        header.find( "Connection" ) == header.end() ||
        header.find( "Sec-WebSocket-Key" ) == header.end() ||
        header.find( "Sec-WebSocket-Version" ) == header.end() )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    // verify |Host| header field containing the server's authority
    std::string header_host = header[ "Host" ];

    if ( std::strcmp( header_host.c_str(), host ) != 0 )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    // verify |Upgrade| header field contains websocket
    std::string header_upgrade = header[ "Upgrade" ];

    if ( !string_contains_case_insensitive( header_upgrade, "websocket" ) )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    // verify |Connection| header field contains upgrade
    std::string header_connetion = header[ "Connection" ];

    if ( !string_contains_case_insensitive( header_connetion, "upgrade" ) )
    {
        respond( 400, "Bad Request", output );
        return e_status::error;
    }

    // verify |Sec-WebSocket-Version| header field is set to supported websocket version
    std::string version = header[ "Sec-WebSocket-Version" ];

    if ( std::strcmp( version.c_str(), "13" ) != 0 )
    {
        respond( 426, "Upgrade Required", output );
        return e_status::error;
    }

    // [optional] verify |Origin| header field matches
    if ( std::strcmp( origin, "" ) != 0 && std::strcmp( origin, "null" ) != 0 )
    {
        if ( header.find( "Origin" ) == header.end() )
        {
            respond( 400, "Bad Request", output );
            return e_status::error;
        }

        std::string header_origin = header[ "Origin" ];

        if ( !string_contains_case_insensitive( header_origin, host ) )
        {
            respond( 403, "Forbidden", output );
            return e_status::error;
        }
    }

    // todo: [optional] verify |Sec-WebSocket-Protocol| header field
    /*
        Optionally, a |Sec-WebSocket-Protocol| header field, with a list
        of values indicating which protocols the client would like to
        speak, ordered by preference.
    */

    // todo: [optional] verify |Sec-WebSocket-Extensions| header field
    /*
        Optionally, a |Sec-WebSocket-Extensions| header field, with a
        list of values indicating which extensions the client would like
        to speak.  The interpretation of this header field is discussed
        in Section 9.1.
    */

    // generate |Sec-WebSocket-Accept| out of |Sec-WebSocket-Key|
    std::string secret = header[ "Sec-WebSocket-Key" ];
    std::string accept;

    if ( c_ws_handshake::secret( secret, accept ) != e_status::ok )
    {
        respond( 500, "Internal Server Error", output );
        return e_status::error;
    }

    ( *output ) << "HTTP/1.1 101 Switching Protocols\r\n";
    ( *output ) << "Upgrade: websocket\r\n";
    ( *output ) << "Connection: Upgrade\r\n";
    ( *output ) << "Sec-WebSocket-Accept: " << accept.c_str() << "\r\n";
    ( *output ) << "\r\n";

    return e_status::ok;
}
