#pragma once

class c_deflate
{
public:
    static int
    compress( unsigned char *input, size_t length, unsigned char *output, size_t &max_out );

    static int
    decompress( unsigned char *input, size_t length, unsigned char *output, size_t &max_out );
};
