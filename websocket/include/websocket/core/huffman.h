#pragma once

#include <cstddef>
#include <map>
#include <vector>

/**
 * @class c_huffman
 * @brief Implements the Huffman coding algorithm for data compression.
 *
 * The `c_huffman` class provides methods for encoding and decoding data using Huffman coding, a popular
 * lossless data compression algorithm that assigns variable-length codes to input characters, with shorter
 * codes for more frequent characters. This class is non-copyable to avoid unintended duplication of resources.
 */
class c_huffman
{
public:
    /**
     * @enum e_status
     * @brief Represents the status of the encoding or decoding operation.
     */
    enum class e_status
    {
        status_ok = 0,   ///< Operation completed successfully.
        status_error = -1 ///< Operation encountered an error.
    };

    /**
     * @brief Encodes data using the Huffman algorithm.
     *
     * Encodes the input data using Huffman coding and stores the encoded data in the output buffer.
     * Also generates a frequency table that represents the frequency of each symbol in the input data.
     *
     * @param input The input data buffer containing the data to encode.
     * @param output The output buffer where the encoded (compressed) data will be stored.
     * @param frequency_table A frequency table mapping each symbol to its frequency in the input data.
     * @return `e_status::status_ok` if encoding was successful; otherwise, `e_status::status_error`.
     *
     * @note Ensure that the output buffer has sufficient space for the encoded data.
     */
    static e_status
    encode(const std::vector<unsigned char> &input, std::vector<unsigned char> &output, std::map<unsigned char, size_t> &frequency_table);

    /**
     * @brief Decodes data encoded with the Huffman algorithm.
     *
     * Decodes the input data, which was previously encoded using Huffman coding, and writes the decompressed data to the output buffer.
     *
     * @param input The input buffer containing encoded data.
     * @param output The output buffer where the decoded (decompressed) data will be stored.
     * @param frequency_table The frequency table used for decoding, mapping symbols to their frequency.
     * @return `e_status::status_ok` if decoding was successful; otherwise, `e_status::status_error`.
     *
     * @note Ensure that the output buffer has sufficient space to store the decompressed data.
     */
    static e_status
    decode(const std::vector<unsigned char> &input, std::vector<unsigned char> &output, const std::map<unsigned char, size_t> &frequency_table);

    /**
     * @brief Constructs a new c_huffman object.
     *
     * Initializes the internal implementation details for Huffman coding.
     */
    c_huffman();

    /**
     * @brief Destroys the c_huffman object.
     *
     * Cleans up the internal resources allocated for Huffman coding.
     */
    ~c_huffman();

    /**
     * @brief Deleted copy constructor.
     *
     * The copy constructor is deleted to prevent copying of `c_huffman` instances.
     */
    c_huffman(const c_huffman &rhs) = delete;

    /**
     * @brief Deleted copy assignment operator.
     *
     * The copy assignment operator is deleted to prevent assignment of `c_huffman` instances.
     * @return A reference to the current instance.
     */
    c_huffman &operator=(const c_huffman &rhs) = delete;

private:
    /**
     * @struct impl_t
     * @brief Holds the private implementation details of the Huffman coding algorithm.
     *
     * The `impl_t` structure is defined in the source file, implementing the actual logic
     * for encoding and decoding to separate the interface from the implementation.
     */
    struct impl_t;

    impl_t *impl; ///< Pointer to the private implementation of the Huffman coding algorithm.
};
