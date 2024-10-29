/**
 * WIP deflate/inflate RFC1951
 *
 *      DEFLATE Compressed Data Format Specification version 1.3
 */

#include <websocket/core/flate.h>

#include <websocket/core/endian.h>
#include <websocket/core/huffman.h>
#include <websocket/core/lzss.h>

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
    size_t available_size = input.size();
    size_t offset = 0;

    while ( available_size > 0 )
    {
        std::vector< unsigned char > block;

        const size_t next_size = std::min( block_size, available_size );

        header_t header{};
        header.bits.final = available_size == next_size;
        header.bits.type = block_type_uncompressed;

        block.insert( block.begin(), header.value );

        switch ( header.bits.type )
        {
            case block_type_uncompressed:
            {
                const unsigned short len = c_endian::little_endian_16( next_size );
                const unsigned short nlen = ~len;

                block.insert( block.end(), reinterpret_cast< const unsigned char * >( &len ), reinterpret_cast< const unsigned char * >( &len ) + sizeof( len ) );
                block.insert( block.end(), reinterpret_cast< const unsigned char * >( &nlen ), reinterpret_cast< const unsigned char * >( &nlen ) + sizeof( nlen ) );

                break;
            }
        }

        block.insert( block.end(), input.begin() + offset, input.begin() + offset + next_size );

        output.insert( output.end(), block.begin(), block.end() );

        available_size -= block_size;
        offset += block_size;
    }

    return 0;
}


int
c_flate::inflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, const size_t block_size )
{

    return 0;
}
