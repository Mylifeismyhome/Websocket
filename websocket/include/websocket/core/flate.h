#pragma once

#include <cstddef>
#include <vector>

/***
 * RFC1951
 */
class c_flate
{
public:
    enum class e_status : unsigned char
    {
        status_ok = 0x0,
        status_not_enough_data = 0x1,
        status_length_mismatch = 0x2,
    };

    static int
    deflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, size_t block_size = 32768 );

    static e_status
    inflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output );
};
