#pragma once

#include <cstddef>
#include <map>

class c_huffman
{
public:
    enum class e_status
    {
        status_ok = 0,
        status_error = -1
    };

    static e_status
    encode( unsigned char *input, size_t input_length, unsigned char *&output, size_t &output_length, size_t &output_bits, std::map< unsigned char, size_t >& frequency_table );

    static e_status
    decode( unsigned char *input, size_t input_length, size_t input_bits, unsigned char *&output, size_t &output_length, std::map< unsigned char, size_t > frequency_table );

    c_huffman();

    ~c_huffman();

    c_huffman( const c_huffman &rhs ) = delete;

    c_huffman &
    operator=( const c_huffman &rhs ) = delete;

private:
    struct impl_t;
    impl_t *impl;
};
