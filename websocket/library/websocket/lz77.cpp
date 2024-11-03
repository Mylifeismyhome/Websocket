#include <websocket/core/lz77.h>

c_lz77::e_status
c_lz77::compress( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, const size_t window_size )
{
    output.resize( input.size() );

    size_t output_length = 0;

    for ( size_t i = 0, j = 0; i < input.size(); i += j )
    {
        // search for the longest match
        size_t best_distance = 0;
        size_t best_length = 0;

        const size_t start = i >= window_size ? i - window_size : 0;

        for ( size_t z = start; z < i; ++z )
        {
            size_t length = 0;

            // compare in the search window
            while ( i + length < input.size() && input[ z + length ] == input[ i + length ] )
            {
                ++length;
            }

            if ( length > best_length )
            {
                best_distance = i - z;
                best_length = length;
            }
        }

        // write (distance, length, literal) to output
        if ( best_length > 0 )
        {
            output[ output_length++ ] = best_distance;
            output[ output_length++ ] = best_length;
            output[ output_length++ ] = input[ i + best_length ];

            j = best_length + 1;
        }
        else
        {
            output[ output_length++ ] = 0;
            output[ output_length++ ] = 0;
            output[ output_length++ ] = input[ i ];

            j = 1;
        }
    }

    output.resize( output_length );

    return e_status::status_ok;
}

c_lz77::e_status
c_lz77::decompress( const std::vector< unsigned char > &input, std::vector< unsigned char > &output )
{
    size_t output_length = 0;

    for ( size_t i = 0, j = 0; i < input.size(); i += j )
    {
        if ( i + 3 > input.size() )
        {
            return e_status::status_error;
        }

        const unsigned char distance = input[ i ];
        const unsigned char length = input[ i + 1 ];

        if ( distance > 0 && length > 0 )
        {
            output_length += length;
        }

        output_length++;

        j = 3;
    }

    output.resize( output_length );

    for ( size_t i = 0, j = 0, k = 0; i < input.size(); i += j )
    {
        if ( i + 3 > input.size() )
        {
            return e_status::status_error;
        }

        const unsigned char distance = input[ i ];
        const unsigned char length = input[ i + 1 ];
        const unsigned char literal = input[ i + 2 ];

        if ( distance > 0 && length > 0 )
        {
            const size_t start = k - distance;

            for ( size_t z = 0; z < length; ++z )
            {
                output[ k++ ] = output[ start + z ];
            }
        }

        output[ k++ ] = literal;

        j = 3;
    }

    return e_status::status_ok;
}
