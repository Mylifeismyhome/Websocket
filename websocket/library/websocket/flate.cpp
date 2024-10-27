#include <map>
#include <websocket/core/flate.hpp>
#include <websocket/core/huffman.hpp>
#include <websocket/core/lzss.hpp>

union header_t
{
    unsigned char value;

    struct
    {
        unsigned char final : 1; // BFINAL bit (1 = last block, 0 = more blocks)
        unsigned char type : 2; // BTYPE (0 = uncompressed, 1 = fixed Huffman, 2 = dynamic Huffman)
    } bits;
};

int
c_flate::inflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output )
{
    return 0;
}

int
c_flate::deflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output )
{
    return 0;
}
