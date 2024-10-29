#pragma once

#include <cstddef>
#include <vector>

/**
 * @class c_lzss
 * @brief Implements the LZSS (Lempel-Ziv-Storer-Szymanski) compression algorithm.
 *
 * This class provides static methods to compress and decompress data using the LZSS algorithm.
 * The LZSS algorithm is a lossless data compression method that replaces duplicate strings with
 * references to previous occurrences within a sliding window. It is particularly efficient for
 * compressing data with repeated patterns.
 */
class c_lzss
{
public:
    /**
     * @enum e_status
     * @brief Enum to represent the status of the compression or decompression operation.
     */
    enum class e_status
    {
        status_ok = 0,   ///< Operation completed successfully.
        status_error = -1 ///< Operation encountered an error.
    };

    /**
     * @brief Compresses data using the LZSS algorithm.
     *
     * Compresses the provided input data buffer and stores the compressed data in the output buffer.
     * The compression utilizes a sliding window to find and replace repeating patterns, reducing the
     * overall data size.
     *
     * @param input The input data buffer containing the data to compress.
     * @param output The output buffer where compressed data will be stored.
     * @param window_size The size of the sliding window for the LZSS algorithm, in bytes.
     *            The default size is 32 KB.
     * @return `e_status::status_ok` if compression was successful; otherwise, `e_status::status_error`.
     *
     * @note Ensure that the output buffer has sufficient space to store the compressed data.
     *       The exact space requirement depends on the input data and compression efficiency.
     */
    static e_status
    compress(const std::vector<unsigned char> &input, std::vector<unsigned char> &output, size_t window_size = 32768);

    /**
     * @brief Decompresses data that was compressed with the LZSS algorithm.
     *
     * Decompresses the data in the input buffer, which must have been previously compressed
     * with the LZSS algorithm, and writes the decompressed data to the output buffer.
     *
     * @param input The input buffer containing compressed data.
     * @param output The output buffer where decompressed data will be stored.
     * @param maxout The maximum number of bytes that can be written to the output buffer.
     * @return `e_status::status_ok` if decompression was successful; otherwise, `e_status::status_error`.
     *
     * @note Ensure that the output buffer has enough capacity to store up to `maxout` bytes
     *       of decompressed data. If the buffer is too small, decompressed data may be truncated.
     */
    static e_status
    decompress(const std::vector<unsigned char> &input, std::vector<unsigned char> &output, size_t maxout);
};
