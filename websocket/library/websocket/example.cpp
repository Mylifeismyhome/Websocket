#if defined( _WIN32 ) && !defined( EFIX64 ) && !defined( EFI32 )
#include <Windows.h>
#endif

#include <csignal>
#include <cstring>
#include <memory>
#include <stdio.h>

#ifdef WEBSOCKET_EXAMPLE_C_API
#ifndef WEBSOCKET_C_API
#define WEBSOCKET_C_API
#endif
#include <websocket/api/websocket_c_api.h>
#else
#ifndef WEBSOCKET_CPP_API
#define WEBSOCKET_CPP_API
#endif
#include <websocket/api/websocket_cpp_api.h>
#endif

static ws_settings_t settings;

#ifdef WEBSOCKET_EXAMPLE_C_API
static void *ctx = NULL;
#else
static c_websocket ws;
#endif

static void
handle_exit()
{
#ifdef WEBSOCKET_EXAMPLE_C_API
    websocket_close( ctx );

    while ( websocket_operate( ctx ) )
    {
        // keep operating till all fd's has been terminated
    }

    websocket_destroy( ctx );
#else
    ws.close();

    while ( ws.operate() )
    {
        // keep operating till all fd's has been terminated
    }
#endif

    ws_settings_destroy( &settings );
}

#if defined( _WIN32 ) && !defined( EFIX64 ) && !defined( EFI32 )
BOOL WINAPI
win_console_handler( DWORD eventType )
{
    switch ( eventType )
    {
        case CTRL_C_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            handle_exit();
            return TRUE;

        default:
            return FALSE;
    }
}
#endif

void
exit_handler( int signal_num )
{
    handle_exit();
    std::exit( signal_num );
}

#ifdef WEBSOCKET_EXAMPLE_C_API
void
websocket_on_open( void *ctx, int fd, const char *addr )
{
    printf( "new connection `%i;%s`\n", fd, addr );

    void *frame = websocket_frame_create( e_ws_frame_opcode::opcode_text );
    websocket_frame_mask( frame, 123 );
    websocket_frame_push_string( frame, "hello world!" );
    websocket_frame_emit( ctx, fd, frame );
    websocket_frame_destroy( frame );
}

void
websocket_on_close( void *ctx, int fd, e_ws_closure_status status )
{
    printf( "connection dropped `%i` with status `%i`\n", fd, status );
}

void
websocket_on_frame( void *ctx, int fd, e_ws_frame_opcode opcode, unsigned char *payload, size_t size )
{
    printf( "income frame `%i` :: opcode -> %d\n\t%s\n", fd, opcode, payload );
}

void
websocket_on_error( void *ctx, const char *message )
{
    printf( "%s\n", message );
}
#else
void
websocket_on_open( void *ctx, int fd, const char *addr )
{
    printf( "new connection `%i;%s`\n", fd, addr );

    c_websocket *ws = reinterpret_cast< c_websocket * >( ctx );

    c_ws_frame frame( e_ws_frame_opcode::opcode_text );
    frame.mask( 123 );
    frame.push( "hello world!" );
    ws->emit( fd, &frame );
}

void
websocket_on_close( void *ctx, int fd, e_ws_closure_status status )
{
    printf( "connection dropped `%i` with status `%i`\n", fd, status );
}

void
websocket_on_frame( void *ctx, int fd, e_ws_frame_opcode opcode, unsigned char *payload, size_t size )
{
    printf( "income frame `%i` :: opcode -> %d\n\t%s\n", fd, opcode, payload );
}

void
websocket_on_error( void *ctx, const char *message )
{
    printf( "error: %s\n", message );
}
#endif

#include <string>
#include <websocket/core/huffman.hpp>
#include <websocket/core/lzss.hpp>
#include <websocket/core/flate.hpp>

int
main()
{
    printf( "lzss test\n" );
    {
        std::string message = "AAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAA";

        std::vector< unsigned char > input( message.begin(), message.end() );

        printf( "original message: %s\n", input.data() );
        printf( "original length: %llu\n", input.size() );

        std::vector< unsigned char > output;
        std::map< unsigned char, size_t > frequency_table;

        c_lzss::compress( input, output );

        printf( "compressed length: %llu\n", output.size() );

        std::vector< unsigned char > dec;

        c_lzss::decompress( output, dec, input.size() );

        printf( "decompressed message: %s\n", dec.data() );
        printf( "decompressed length: %llu\n", dec.size() );
    }

    printf( "huffman test\n" );
    {
        std::string message = "AAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAA";

        std::vector< unsigned char > input( message.begin(), message.end() );

        printf( "original message: %s\n", input.data() );
        printf( "original length: %llu\n", input.size() );

        std::vector< unsigned char > output;

        size_t bit_count = 0;

        std::map< unsigned char, size_t > frequency_table;

        c_huffman::encode( input, output, bit_count, frequency_table );

        printf( "encoded length: %llu\n", output.size() );

        std::vector< unsigned char > dec;

        c_huffman::decode( output, dec, bit_count, frequency_table );

        printf( "decoded message: %s\n", dec.data() );
        printf( "decoded length: %llu\n", dec.size() );
    }

    printf( "flate test\n" );
    {
        std::string message = "AAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAAAAAAABBBCCDAAA";

        std::vector< unsigned char > input( message.begin(), message.end() );

        printf( "original message: %s\n", input.data() );
        printf( "original length: %llu\n", input.size() );

        std::vector< unsigned char > output;

        c_flate::inflate( input, output );

        printf( "compressed length: %llu\n", output.size() );

        std::vector< unsigned char > dec;

        c_flate::deflate( output, dec );

        printf( "decoded message: %s\n", dec.data() );
        printf( "decoded length: %llu\n", dec.size() );
    }

    //{
    //    std::unordered_map< unsigned char, std::string > huffmanCodes;


    //    const char *test_input = "Hello, this is a test input for compression!";
    //    size_t input_length = std::strlen( test_input );

    //    unsigned char *compressed_output = nullptr;
    //    int compressed_size = c_deflate::compress( reinterpret_cast< unsigned char * >( const_cast< char * >( test_input ) ), input_length, compressed_output, huffmanCodes );

    //    std::cout << "Compressed size: " << compressed_size << " bytes" << std::endl;

    //    // Output the compressed data as hex for verification
    //    std::cout << "Compressed data (hex): ";
    //    for ( int i = 0; i < compressed_size; ++i )
    //    {
    //        std::cout << std::hex << static_cast< int >( compressed_output[ i ] ) << " ";
    //    }
    //    std::cout << std::dec << std::endl; // Switch back to decimal

    //    // Decompression
    //    unsigned char *decompressed_output = nullptr;
    //    int decompressed_size = c_deflate::decompress( compressed_output, compressed_size, decompressed_output, huffmanCodes );

    //    std::cout << "Decompressed size: " << decompressed_size << " bytes" << std::endl;
    //    std::cout << "Decompressed data: " << std::string( reinterpret_cast< char * >( decompressed_output ), decompressed_size ) << std::endl;

    //    delete[] compressed_output; // Clean up the compressed output buffer
    //    delete[] decompressed_output; // Clean up the decompressed output buffer
    //}

#if defined( _WIN32 ) && !defined( EFIX64 ) && !defined( EFI32 )
    if ( !SetConsoleCtrlHandler( win_console_handler, TRUE ) )
    {
        return 1;
    }
#endif

    std::signal( SIGINT, exit_handler );

    ws_settings_init( &settings );

#ifdef WEBSOCKET_EXAMPLE_ENDPOINT_SERVER
    settings.endpoint = e_ws_endpoint_type::endpoint_server;
#elif WEBSOCKET_EXAMPLE_ENDPOINT_CLIENT
    settings.endpoint = e_ws_endpoint_type::endpoint_client;
#endif

    settings.host = strdup( "localhost:4433" );

#ifdef WEBSOCKET_EXAMPLE_C_API
    ctx = websocket_create();

    if ( ctx == NULL )
    {
        return 1;
    }

    if ( websocket_on( ctx, WS_EVENT_OPEN, reinterpret_cast< void * >( websocket_on_open ) ) == e_ws_status::status_error )
    {
        websocket_destroy( ctx );
        ws_settings_destroy( &settings );
        return 1;
    }

    if ( websocket_on( ctx, WS_EVENT_CLOSE, reinterpret_cast< void * >( websocket_on_close ) ) == e_ws_status::status_error )
    {
        websocket_destroy( ctx );
        ws_settings_destroy( &settings );
        return 1;
    }

    if ( websocket_on( ctx, WS_EVENT_FRAME, reinterpret_cast< void * >( websocket_on_frame ) ) == e_ws_status::status_error )
    {
        websocket_destroy( ctx );
        ws_settings_destroy( &settings );
        return 1;
    }

    if ( websocket_on( ctx, WS_EVENT_ERROR, reinterpret_cast< void * >( websocket_on_error ) ) == e_ws_status::status_error )
    {
        websocket_destroy( ctx );
        ws_settings_destroy( &settings );
        return 1;
    }

    if ( websocket_setup( ctx, &settings ) == e_ws_status::status_error )
    {
        websocket_destroy( ctx );
        ws_settings_destroy( &settings );
        return 1;
    }

#ifdef WEBSOCKET_EXAMPLE_ENDPOINT_SERVER
    if ( websocket_bind( ctx, "localhost", "4433", NULL ) == e_ws_status::status_error )
    {
        websocket_destroy( ctx );
        ws_settings_destroy( &settings );
        return 1;
    }
#elif WEBSOCKET_EXAMPLE_ENDPOINT_CLIENT
    if ( websocket_open( ctx, "localhost", "4433", NULL ) == e_ws_status::status_error )
    {
        websocket_destroy( ctx );
        ws_settings_destroy( &settings );
        return 1;
    }
#endif

    printf( "websocket launched\n" );

    while ( websocket_operate( ctx ) )
    {
        // main loop
    }

    websocket_destroy( ctx );
#else
    if ( ws.on( WS_EVENT_OPEN, reinterpret_cast< void * >( websocket_on_open ) ) == e_ws_status::status_error )
    {
        ws_settings_destroy( &settings );
        return 1;
    }

    if ( ws.on( WS_EVENT_CLOSE, reinterpret_cast< void * >( websocket_on_close ) ) == e_ws_status::status_error )
    {
        ws_settings_destroy( &settings );
        return 1;
    }

    if ( ws.on( WS_EVENT_FRAME, reinterpret_cast< void * >( websocket_on_frame ) ) == e_ws_status::status_error )
    {
        ws_settings_destroy( &settings );
        return 1;
    }

    if ( ws.on( WS_EVENT_ERROR, reinterpret_cast< void * >( websocket_on_error ) ) == e_ws_status::status_error )
    {
        ws_settings_destroy( &settings );
        return 1;
    }

    if ( ws.setup( &settings ) != 0 )
    {
        ws_settings_destroy( &settings );
        return 1;
    }

#ifdef WEBSOCKET_EXAMPLE_ENDPOINT_SERVER
    if ( ws.bind( "localhost", "4433", nullptr ) == e_ws_status::status_error )
    {
        ws_settings_destroy( &settings );
        return 1;
    }
#elif WEBSOCKET_EXAMPLE_ENDPOINT_CLIENT
    if ( ws.open( "localhost", "4433", nullptr ) == e_ws_status::status_error )
    {
        ws_settings_destroy( &settings );
        return 1;
    }
#endif

    printf( "websocket launched\n" );

    while ( ws.operate() )
    {
        // main loop
    }
#endif

    ws_settings_destroy( &settings );

    return 0;
}
