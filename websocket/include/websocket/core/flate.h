#pragma once

#include <vector>


/***
 * RFC1951
 */
class c_flate
{
public:
    static int
    deflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, size_t block_size = 32768 );

    static int
    inflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, size_t block_size = 32768 );
};
