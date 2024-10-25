#pragma once

#include <cstddef>
#include <memory>

/**
 * @class c_lz277
 * @brief Implements the LZ77 compression algorithm.
 *
 * This class provides static methods to compress and decompress data using the LZ77 algorithm.
 * The LZ77 algorithm is a lossless data compression algorithm that replaces duplicate strings with
 * references to previous occurrences within a sliding window.
 */
class c_lz277
{
public:
    /**
     * @brief Compresses data using the LZ77 algorithm.
     *
     * Compresses the input data and writes the compressed data to the output buffer.
     * The compression process is based on the LZ77 algorithm, which utilizes a sliding window
     * to search for repeating patterns.
     *
     * @param input Pointer to the input data buffer that needs to be compressed.
     * @param length The length of the input data in bytes.
     * @param output Pointer to the output buffer where compressed data will be stored.
     * @param window_size The size of the sliding window for the LZ77 algorithm. Default is 8192 bytes.
     * @return The number of bytes written to the output buffer.
     *
     * @note Ensure that the output buffer has sufficient space to store the compressed data.
     *       The required buffer size will depend on the data being compressed.
     */
    static int
    compress( unsigned char *input, size_t length, unsigned char *output, size_t window_size = 8192 );

    /**
     * @brief Decompresses data compressed with the LZ77 algorithm.
     *
     * Decompresses the input data, which was previously compressed with the LZ77 algorithm,
     * and writes the decompressed data to the output buffer.
     *
     * @param input Pointer to the compressed input data buffer.
     * @param length The length of the compressed data in bytes.
     * @param output Pointer to the output buffer where decompressed data will be stored.
     * @param maxout The maximum number of bytes that can be written to the output buffer.
     * @return The number of bytes written to the output buffer.
     *
     * @note Ensure that the output buffer has sufficient space to store the decompressed data
     *       up to maxout bytes. If the buffer is too small, data might be truncated.
     */
    static int
    decompress( unsigned char *input, size_t length, unsigned char *output, size_t maxout );
};
