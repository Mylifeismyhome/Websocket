/*
MIT License

Copyright (c) 2024 Tobias Staack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once

#include <websocket/api/websocket_api.h>

#include <websocket/defs/frameDefs.h>

#include <websocket/core/byte_stream.hpp>

/**
 * @class c_ws_frame
 * @brief Websocket frame
 *
 * This class is used to create a WebSocket frame with a specific opcode and to append payload data to it.
 * It provides methods for applying a masking key to mask the payload and to push a payload.
 */
class WEBSOCKET_API c_ws_frame final
{
    /**
     * @brief Writes the frame to an output buffer (internal use only).
     *
     * This method writes the WebSocket frame data to the specified output buffer.
     * This method is intended for internal use and is not accessible externally.
     *
     * @param[out] output Pointer to the output stream `c_byte_stream` where the frame data will be written.
     * @return Status of the write operation as an `e_ws_frame_status`.
     *
     * @internal
     */
    e_ws_frame_status
    write( c_byte_stream *output );

    /**
     * @brief Reads the frame from an input buffer (internal use only).
     *
     * This method reads WebSocket frame data from the specified input buffer.
     * This method is intended for internal use and is not accessible externally.
     *
     * @param[in] input Pointer to the input stream `c_byte_stream` containing frame data.
     * @return Status of the read operation as an `e_ws_frame_status`.
     *
     * @internal
     */
    e_ws_frame_status
    read( c_byte_stream *input );

public:
    c_ws_frame();

    c_ws_frame( e_ws_frame_opcode opcode );

    ~c_ws_frame();

    c_ws_frame( const c_ws_frame &other );

    c_ws_frame( c_ws_frame &&other ) noexcept;

    c_ws_frame &
    operator=( const c_ws_frame &other );

    c_ws_frame &
    operator=( c_ws_frame &&other ) noexcept;

    /**
     * @brief Masks the WebSocket frame payload.
     *
     * Applies a masking key to the WebSocket frame, as required for client frames in WebSocket communication.
     *
     * @param[in] key The masking key to apply.
     */
    void
    mask( unsigned int key );

    /**
     * @brief Appends data to the WebSocket frame payload.
     *
     * Adds the specified data to the frame's payload.
     *
     * @param[in] data Pointer to the data to be added.
     * @param[in] size The size of the data to add in bytes.
     * @return `true` if the data is successfully added, `false` otherwise.
     */
    bool
    push( unsigned char *data, size_t size );

    /**
     * @brief Appends a null-terminated string to the WebSocket frame payload.
     *
     * Adds the specified string data to the frame's payload.
     *
     * @param[in] data Pointer to the null-terminated string to be added.
     * @return `true` if the string is successfully added, `false` otherwise.
     */
    bool
    push( const char *data );

    /**
     * @brief Clears the WebSocket frame payload.
     *
     * Resets the payload, removing all data currently held in the frame.
     */
    void
    flush();

    /**
     * @brief Retrieves the WebSocket frame opcode.
     *
     * Returns the opcode that indicates the frame type, such as text, binary, or control frames.
     *
     * @return The frame opcode as an `e_ws_frame_opcode`.
     */
    e_ws_frame_opcode
    get_opcode() const;

    /**
     * @brief Retrieves the WebSocket frame payload.
     *
     * Returns a pointer to the payload data currently stored in the frame.
     *
     * @return Pointer to the payload data.
     */
    unsigned char *
    get_payload() const;

    /**
     * @brief Retrieves the size of the WebSocket frame payload.
     *
     * Returns the size of the payload data in bytes.
     *
     * @return Size of the payload in bytes.
     */
    size_t
    get_payload_size() const;

private:
    struct impl_t;
    impl_t *impl;

    friend class c_websocket;
};