#pragma once

#include <cstddef>
#include <map>
#include <vector>

class c_huffman
{
public:
    enum class e_status
    {
        status_ok = 0,
        status_error = -1
    };

    static e_status
    encode( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, size_t &bit_count, std::map< unsigned char, size_t > &frequency_table );

    static e_status
    decode( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, size_t bit_count, std::map< unsigned char, size_t > frequency_table );

    c_huffman();

    ~c_huffman();

    c_huffman( const c_huffman &rhs ) = delete;

    c_huffman &
    operator=( const c_huffman &rhs ) = delete;

private:
    struct impl_t;
    impl_t *impl;
};
