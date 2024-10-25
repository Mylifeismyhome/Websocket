#pragma once

#include <cstddef>
#include <vector>

class c_huffman_code
{
public:
    static int
    encode( unsigned char *input, size_t length, std::vector< bool > &output );

    static int
    decode( std::vector< bool > input, unsigned char *output, size_t &length );
};
