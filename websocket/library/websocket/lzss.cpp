#include <websocket/core/lzss.hpp>

static constexpr size_t LZSS_MIN_MATCH_LENGTH = 3; // Minimum match length to encode
static constexpr size_t LZSS_MAX_MATCH_LENGTH = 18; // Maximum match length
static constexpr size_t LZSS_FLAG_BYTE = 0x80; // Flag byte to indicate literal/match

c_lzss::e_status
c_lzss::compress( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, size_t window_size )
{
    const size_t input_size = input.size();
    if ( input_size == 0 )
    {
        return e_status::status_error;
    }

    std::vector< unsigned char > window;
    window.reserve( window_size );

    size_t pos = 0;

    while ( pos < input_size )
    {
        size_t match_length = 0;
        size_t match_position = 0;

        // search for the longest match within the sliding window
        for ( size_t j = 0; j < window.size(); ++j )
        {
            size_t k = 0;
            while ( k < LZSS_MAX_MATCH_LENGTH && j + k < window.size() && pos + k < input_size && window[ j + k ] == input[ pos + k ] )
            {
                ++k;
            }

            if ( k >= LZSS_MIN_MATCH_LENGTH && k > match_length )
            {
                match_length = k;
                match_position = j;
            }
        }

        if ( match_length >= LZSS_MIN_MATCH_LENGTH )
        {
            // add match flag
            output.push_back( LZSS_FLAG_BYTE | ( match_position >> 4 ) );
            output.push_back( ( ( match_position & 0x0F ) << 4 ) | ( match_length - LZSS_MIN_MATCH_LENGTH ) );

            pos += match_length;
        }
        else
        {
            // add literal byte without match
            output.push_back( input[ pos++ ] );
        }

        // slide the window
        while ( window.size() < window_size && window.size() < pos )
        {
            window.push_back( input[ window.size() ] );
        }

        while ( window.size() >= window_size )
        {
            window.erase( window.begin() );
        }
    }
    return e_status::status_ok;
}

c_lzss::e_status
c_lzss::decompress( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, size_t maxout )
{
    size_t pos = 0;
    while ( pos < input.size() )
    {
        const unsigned char byte = input[ pos++ ];

        if ( byte & LZSS_FLAG_BYTE )
        {
            // extract match position and length from two bytes
            if ( pos >= input.size() )
            {
                return e_status::status_error;
            }

            const unsigned char next_byte = input[ pos++ ];
            const size_t match_position = ( ( byte & 0x7F ) << 4 ) | ( next_byte >> 4 );
            const size_t match_length = ( next_byte & 0x0F ) + LZSS_MIN_MATCH_LENGTH;

            // copy match from output buffer
            for ( size_t j = 0; j < match_length; ++j )
            {
                if ( match_position + j >= output.size() )
                {
                    return e_status::status_error;
                }

                output.push_back( output[ match_position + j ] );
            }
        }
        else
        {
            // Literal byte (no match)
            output.push_back( byte );
        }

        if ( output.size() > maxout )
        {
            return e_status::status_error;
        }
    }

    return e_status::status_ok;
}
