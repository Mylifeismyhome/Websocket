#pragma once

#include <cstddef>
#include <string>
#include <map>
#include <vector>

class c_huffman_code
{
    struct Node
    {
        unsigned char character;
        size_t frequency;
        Node *left, *right;
        Node( unsigned char d, size_t f ) :
            character( d ), frequency( f ), left( nullptr ), right( nullptr ) {}
    };

    struct Compare
    {
        bool
        operator()( Node *a, Node *b )
        {
            if ( a->frequency == b->frequency )
                return a->character > b->character; // Secondary sort by character value
            return a->frequency > b->frequency; // Primary sort by frequency
        }
    };

    static void
    huffman_build_frequency_table( unsigned char *input, size_t length, std::map< unsigned char, size_t > &frequency_table );

    static Node *
    huffman_build_tree( const std::map< unsigned char, size_t > &freqTable );

    static void
    huffman_build_code_table( Node *root, std::map< unsigned char, std::vector< bool > > &huffman_codes_table );

    static void
    huffman_release_tree( Node *root );

public:
    enum class e_status
    {
        status_ok = 0,
        status_error = -1
    };

    static e_status
    encode( unsigned char *input, size_t input_length, unsigned char *&output, size_t& output_length, size_t &output_bits, std::map< unsigned char, size_t > &frequency_table );

    static e_status
    decode( unsigned char *input, size_t input_length, size_t input_bits, unsigned char *&output, size_t &output_length, std::map< unsigned char, size_t > frequency_table );
};
