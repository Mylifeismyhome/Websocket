#include <websocket/core/lz77.h>

struct Match
{
    short distance;
    unsigned char length;
};

static Match
find_longest_match( const std::vector< unsigned char > &input, size_t pos, size_t window_size )
{
    short best_distance = 0;
    unsigned char best_length = 0;

    size_t start = ( pos >= window_size ) ? ( pos - window_size ) : 0;

    for ( size_t j = start; j < pos; ++j )
    {
        size_t length = 0;

        // Compare characters in the search window with the current position
        while ( pos + length < input.size() && input[ j + length ] == input[ pos + length ] )
        {
            ++length;
            if ( length >= 255 )
                break; // Limit the length to 255 for byte storage
        }

        if ( length > best_length )
        {
            best_distance = pos - j;
            best_length = length;
        }
    }

    return { best_distance, best_length };
}

c_lz77::e_status
c_lz77::compress( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, const size_t window_size )
{
    output.resize( input.size() );

    size_t output_length = 0;

    for ( size_t i = 0, j = 0; i < input.size(); i += j )
    {
        // Step 1: Find the longest match in the window
        const Match match = find_longest_match( input, i, window_size );

        // Step 2: Store the (distance, length, next_char) in the output
        if ( match.length > 0 )
        {
            // Encode as (distance, length, next_char) triple
            output[ output_length++ ] = match.distance;
            output[ output_length++ ] = match.length;
            output[ output_length++ ] = input[ i + match.length ]; // next unmatched character

            j = match.length + 1;
        }
        else
        {
            // No match found, encode as (0, 0, current_char)
            output[ output_length++ ] = 0; // distance
            output[ output_length++ ] = 0; // length
            output[ output_length++ ] = input[ i ]; // current character

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
