#pragma once

#include <cstddef>
#include <vector>

/**
 * @class c_lzss
 * @brief Implements the LZSS compression algorithm.
 *
 * This class provides static methods to compress and decompress data using the LZSS algorithm.
 * The LZSS algorithm is a lossless data compression algorithm that replaces duplicate strings with
 * references to previous occurrences within a sliding window.
 */
class c_lzss
{
public:
    enum class e_status
    {
        status_ok = 0,
        status_error = -1
    };

    /**
     * @brief Compresses data using the LZSS algorithm.
     *
     * Compresses the input data and writes the compressed data to the output buffer.
     * The compression process is based on the LZSS algorithm, which utilizes a sliding window
     * to search for repeating patterns.
     *
     * @param input Pointer to the input data buffer that needs to be compressed.
     * @param length The length of the input data in bytes.
     * @param output Pointer to the output buffer where compressed data will be stored.
     * @param window_size The size of the sliding window for the LZSS algorithm. Default is 32kb in bytes.
     * @return The number of bytes written to the output buffer.
     *
     * @note Ensure that the output buffer has sufficient space to store the compressed data.
     *       The required buffer size will depend on the data being compressed.
     */
    static e_status
    compress( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, size_t window_size = 32768 );

    /**
     * @brief Decompresses data compressed with the LZSS algorithm.
     *
     * Decompresses the input data, which was previously compressed with the LZSS algorithm,
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
    static e_status
    decompress( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, size_t maxout );
};
