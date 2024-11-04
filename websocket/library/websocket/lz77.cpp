#include <websocket/core/lz77.h>

#include <unordered_map>

c_lz77::e_status
c_lz77::compress( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, const size_t window_size )
{
    try
    {
        output.resize( input.size() );
    }
    catch ( ... )
    {
        return e_status::status_error;
    }

    size_t output_length = 0;

    // hash table for speeding up window search
    std::unordered_map< size_t, std::vector< size_t > > hash_table;
    constexpr size_t hash_length = 3;

    // rolling hash function
    auto hash_function = [ & ]( const size_t pos ) -> size_t
    {
        if ( pos + hash_length > input.size() )
        {
            return 0;
        }

        return input[ pos ] << 16 | input[ pos + 1 ] << 8 | input[ pos + 2 ];
    };

    for ( size_t i = 0, j = 0; i < input.size(); i += j )
    {
        size_t best_distance = 0;
        size_t best_length = 0;

        size_t current_hash = hash_function( i );

        if ( i >= hash_length )
        {
            // lookup positions with the same hash in the sliding window
            const size_t start = i >= window_size ? i - window_size : 0;
            auto it = hash_table.find( current_hash );

            if ( it != hash_table.end() )
            {
                for ( const size_t pos : it->second )
                {
                    if ( pos < start )
                        continue;

                    size_t length = 0;
                    while ( i + length < input.size() && input[ pos + length ] == input[ i + length ] )
                    {
                        ++length;
                    }

                    if ( length > best_length )
                    {
                        best_distance = i - pos;
                        best_length = length;
                    }
                }
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

        // update hash table
        if ( i + hash_length <= input.size() )
        {
            size_t new_hash = hash_function( i );
            hash_table[ new_hash ].push_back( i );

            // keep hash table within the sliding window
            if ( hash_table[ new_hash ].size() > window_size )
            {
                hash_table[ new_hash ].erase( hash_table[ new_hash ].begin() );
            }
        }
    }

    try
    {
        output.resize( output_length );
    }
    catch ( ... )
    {
        return e_status::status_error;
    }

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
