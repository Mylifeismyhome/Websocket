#pragma once

#include <vector>

class c_flate
{
public:
    static int
    inflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output );
    
    static int
    deflate( const std::vector< unsigned char > &input, std::vector< unsigned char > &output );
};
