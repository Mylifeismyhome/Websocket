/**
 * WIP deflate/inflate RFC1951
 *
 *      DEFLATE Compressed Data Format Specification version 1.3
 */

#include <websocket/core/flate.h>

#include <websocket/core/endian.h>
#include <websocket/core/huffman.h>
#include <websocket/core/lz77.h>

#include <cstring>
#include <map>

enum e_block_type
{
    block_type_uncompressed = 0b00,
    block_type_fixed_huffman = 0b01,
    block_type_dynamic_huffman = 0b10,
};

union header_t
{
    unsigned char value;

    struct
    {
        unsigned char final : 1; // BFINAL bit (1 = last block, 0 = more blocks)
        unsigned char type : 2; // BTYPE (00 = uncompressed, 01 = fixed Huffman, 10 = dynamic Huffman)
        unsigned char reserved : 5;
    } bits;
};

int
c_flate::deflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, const size_t block_size )
{
    size_t offset = 0;

    while ( offset < input.size() )
    {
        std::vector< unsigned char > block;

        const size_t available_size = input.size() - offset;
        const size_t next_size = std::min( block_size, available_size );

        header_t header{};
        header.bits.final = available_size == next_size;
        header.bits.type = block_type_dynamic_huffman;

        block.insert( block.begin(), header.value );

        switch ( header.bits.type )
        {
            case block_type_uncompressed:
            {
                const unsigned short len = c_endian::little_endian_16( next_size );
                const unsigned short nlen = ~len;

                block.insert( block.end(), reinterpret_cast< const unsigned char * >( &len ), reinterpret_cast< const unsigned char * >( &len ) + sizeof( len ) );
                block.insert( block.end(), reinterpret_cast< const unsigned char * >( &nlen ), reinterpret_cast< const unsigned char * >( &nlen ) + sizeof( nlen ) );

                block.insert( block.end(), input.begin() + static_cast< ptrdiff_t >( offset ), input.begin() + static_cast< ptrdiff_t >( offset ) + static_cast< ptrdiff_t >( next_size ) );

                break;
            }

            case block_type_dynamic_huffman:
            {
                std::vector< unsigned char > nn;
                nn.insert( nn.end(), input.begin() + static_cast< ptrdiff_t >( offset ), input.begin() + static_cast< ptrdiff_t >( offset ) + static_cast< ptrdiff_t >( next_size ) );

                std::vector< unsigned char > encoded;
                std::map< unsigned char, size_t > frequency_table;
                c_huffman::encode( nn, encoded, frequency_table );



                break;
            }
        }

        output.insert( output.end(), block.begin(), block.end() );

        offset += next_size;
    }

    return 0;
}

c_flate::e_status
c_flate::inflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output )
{
    if ( input.size() < sizeof( header_t ) )
    {
        return e_status::status_not_enough_data;
    }

    size_t offset = 0;

    bool complete = false;

    while ( offset < input.size() )
    {
        header_t header{};
        header.value = input[ offset ];

        offset += sizeof( header_t );

        switch ( header.bits.type )
        {
            case block_type_uncompressed:
            {
                if ( input.size() < offset + sizeof( unsigned short ) )
                {
                    return e_status::status_not_enough_data;
                }

                unsigned short len = 0;
                std::memcpy( &len, &input[ offset ], sizeof( unsigned short ) );

                if ( c_endian::is_big() )
                {
                    len = c_endian::big_endian_16( len );
                }

                offset += sizeof( unsigned short );

                if ( input.size() < offset + sizeof( unsigned short ) )
                {
                    return e_status::status_not_enough_data;
                }

                unsigned short nlen = 0;
                std::memcpy( &nlen, &input[ offset ], sizeof( unsigned short ) );

                if ( c_endian::is_big() )
                {
                    nlen = c_endian::big_endian_16( nlen );
                }

                nlen = ~nlen;

                offset += sizeof( unsigned short );

                if ( nlen != len )
                {
                    return e_status::status_length_mismatch;
                }

                if ( input.size() < offset + len )
                {
                    return e_status::status_not_enough_data;
                }

                output.insert( output.end(), input.begin() + static_cast< ptrdiff_t >( offset ), input.begin() + static_cast< ptrdiff_t >( offset ) + len );

                offset += len;

                break;
            }
        }

        complete = header.bits.final;
    }

    return complete ? e_status::status_ok : e_status::status_not_enough_data;
}
