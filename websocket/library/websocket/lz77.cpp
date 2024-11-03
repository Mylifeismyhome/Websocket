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
    size_t i = 0;

    while ( i < input.size() )
    {
        if ( i + 2 >= input.size() )
        {
            // Incomplete triple, so we can't proceed
            return e_status::status_error;
        }

        // Read (distance, length, next_char) triple
        unsigned char distance = input[ i ];
        unsigned char length = input[ i + 1 ];
        unsigned char next_char = input[ i + 2 ];
        i += 3;

        if ( distance > 0 && length > 0 )
        {
            // Copy `length` bytes from `distance` back in the output
            size_t copy_start = output.size() - distance;
            for ( size_t j = 0; j < length; ++j )
            {
                if ( copy_start + j >= output.size() )
                {
                    // Ensure within bounds
                    return e_status::status_error;
                }
                output.push_back( output[ copy_start + j ] );
            }
        }

        // Add `next_char` to the output, whether or not a match was found
        output.push_back( next_char );
    }

    return e_status::status_ok;
}
