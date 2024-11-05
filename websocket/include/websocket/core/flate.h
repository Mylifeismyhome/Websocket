#pragma once

#include <cstddef>

#include <websocket/core/byte_stream.h>

class c_flate
{
public:
    enum class e_status : unsigned char
    {
        status_ok = 0x0,
        status_not_enough_data = 0x1,
        status_length_mismatch = 0x2,
        status_error = 0x3,
    };

    static e_status
    deflate( const c_byte_stream *input, const c_byte_stream *output, size_t window_size );

    static e_status
    inflate( const c_byte_stream *input, const c_byte_stream *output, size_t window_size );
};
