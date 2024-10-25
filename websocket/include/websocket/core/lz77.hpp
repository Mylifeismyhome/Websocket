#pragma once

#include <cstddef>
#include <memory>

/**
 * @class c_lz277
 * @brief Provides methods for compression and decompression using LZ77 algorithm.
 */
class c_lz277
{
public:
    /**
     * @brief Compresses data using LZ77 algorithm with default compression level.
     *
     * @param input Pointer to the input data.
     * @param length Length of the input data.
     * @param output Pointer to the output buffer.
     * @return The number of bytes written to the output buffer.
     */
    static int
    compress( const void *input, int length, void *output, size_t window_size = 8192 );

    /**
     * @brief Decompresses data compressed using LZ77 algorithm.
     *
     * @param input Pointer to the compressed data.
     * @param length Length of the compressed data.
     * @param output Pointer to the output buffer.
     * @param maxout Maximum number of bytes to write to the output buffer.
     * @return The number of bytes written to the output buffer.
     */
    static int
    decompress( const void *input, int length, void *output, int maxout );
};
