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

#include <websocket/core/byte_stream.h>

#include <string>

#include <websocket/defs/socketDefs.h>

/** \cond */
class c_ws_handshake final
{
public:
    enum e_status : unsigned char
    {
        ok = 0x0, /**< operation was successful. */
        error = 0x1, /**< an error occurred during the operation. */
        busy = 0x2 /**< the socket is currently busy. */
    };

    static e_status
    random( size_t count, std::string &output );

    static e_status
    secret( const std::string &input, std::string &output );

    static e_status
    create( const char *host, const char *origin, const char *channel, c_byte_stream *output, std::string &out_accept_key, const ws_extensions_t *extensions );

    static e_status
    client( const char *accept_key, const c_byte_stream *input, c_byte_stream *output, ws_extensions_t *extensions );

    static e_status
    server( const char *host, const char *origin, const c_byte_stream *input, c_byte_stream *output, const ws_extensions_t *server_extensions, ws_extensions_t *client_extensions );
};
/** \endcond */
