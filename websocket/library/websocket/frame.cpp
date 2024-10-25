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

#define CHUNK_SIZE 8192

#include <websocket/core/frame.hpp>

#include <websocket/core/byte_stream.hpp>
#include <websocket/core/endian.hpp>

#include <cstring>
#include <memory>

union ws_frame_byte1_t
{
    unsigned char value;

    struct
    {
        e_ws_frame_opcode opcode : 4;
        bool rsv3 : 1;
        bool rsv2 : 1;
        bool rsv1 : 1;
        bool fin : 1;
    } bits;
};

static_assert( sizeof( ws_frame_byte1_t ) == sizeof( unsigned char ), "ws_frame_byte1_t size mismatch!" );

union ws_frame_byte2_t
{
    unsigned char value;

    struct
    {
        unsigned char payload_length : 7;
        bool mask : 1;
    } bits;
};

static_assert( sizeof( ws_frame_byte2_t ) == sizeof( unsigned char ), "ws_frame_byte2_t size mismatch!" );

struct c_ws_frame::impl_t
{
    e_ws_frame_opcode opcode;
    unsigned char key[ 4 ];
    c_byte_stream payload;

    bool
    is_masked() const;

    static e_ws_frame_status
    encode( e_ws_frame_opcode opcode, bool mask, unsigned char *mask_key, c_byte_stream *input, c_byte_stream *output );

    static e_ws_frame_status
    decode( c_byte_stream *input, c_byte_stream *output, e_ws_frame_opcode &opcode, size_t limit );

    impl_t()
    {
        opcode = e_ws_frame_opcode::opcode_binary;
        std::memset( key, 0, 4 );
    }

    ~impl_t()
    {
        payload.close();
    }
};

c_ws_frame::c_ws_frame()
{
    impl = new impl_t();
}

c_ws_frame::c_ws_frame( e_ws_frame_opcode opcode )
{
    impl = new impl_t();
    impl->opcode = opcode;
}

c_ws_frame::~c_ws_frame()
{
    if ( impl )
    {
        delete impl;
        impl = nullptr;
    }
}

c_ws_frame::c_ws_frame( const c_ws_frame &other )
{
    impl = new impl_t();
    impl->opcode = other.impl->opcode;
    std::memcpy( impl->key, other.impl->key, sizeof( impl->key ) );
    impl->payload = other.impl->payload;
}

c_ws_frame::c_ws_frame( c_ws_frame &&other ) noexcept
{
    impl = other.impl;
    other.impl = nullptr;
}

c_ws_frame &
c_ws_frame::operator=( const c_ws_frame &other )
{
    if ( this == &other )
    {
        return *this;
    }

    impl->opcode = other.impl->opcode;
    std::memcpy( impl->key, other.impl->key, sizeof( impl->key ) );
    impl->payload = other.impl->payload;

    return *this;
}

c_ws_frame &
c_ws_frame::operator=( c_ws_frame &&other ) noexcept
{
    if ( this == &other )
    {
        return *this;
    }

    impl = other.impl;
    other.impl = nullptr;

    return *this;
}

bool
c_ws_frame::impl_t::is_masked() const
{
    unsigned int value = ( static_cast< uint32_t >( key[ 0 ] ) << 24 ) |
        ( static_cast< uint32_t >( key[ 1 ] ) << 16 ) |
        ( static_cast< uint32_t >( key[ 2 ] ) << 8 ) |
        ( static_cast< uint32_t >( key[ 3 ] ) );

    return value != 0;
}

void
c_ws_frame::mask( unsigned int value )
{
    impl->key[ 0 ] = ( value >> 24 ) & 0xFF;
    impl->key[ 1 ] = ( value >> 16 ) & 0xFF;
    impl->key[ 2 ] = ( value >> 8 ) & 0xFF;
    impl->key[ 3 ] = value & 0xFF;
}

bool
c_ws_frame::push( unsigned char *data, size_t size )
{
    return ( impl->payload.push( data, size ) == c_byte_stream::e_status::ok );
}

bool
c_ws_frame::push( const char *data )
{
    size_t size = std::strlen( data );
    return ( impl->payload.push( reinterpret_cast< unsigned char * >( const_cast< char * >( data ) ), size ) == c_byte_stream::e_status::ok );
}

void
c_ws_frame::flush()
{
    impl->payload.flush();
}

e_ws_frame_opcode
c_ws_frame::get_opcode() const
{
    return impl->opcode;
}

unsigned char *
c_ws_frame::get_payload() const
{
    return impl->payload.pointer();
}

size_t
c_ws_frame::get_payload_size() const
{
    return impl->payload.size();
}

bool
c_ws_frame::is_payload_utf8() const
{
    return impl->payload.is_utf8();
}

e_ws_frame_status
c_ws_frame::write( c_byte_stream *output )
{
    switch ( impl->opcode )
    {
        case e_ws_frame_opcode::opcode_text:
        case e_ws_frame_opcode::opcode_binary:
        case e_ws_frame_opcode::opcode_close:
        case e_ws_frame_opcode::opcode_ping:
        case e_ws_frame_opcode::opcode_pong:
            break;

        default:
            return e_ws_frame_status::status_error;
    }

    return c_ws_frame::impl_t::encode( impl->opcode, impl->is_masked(), reinterpret_cast< unsigned char * >( &impl->key ), &impl->payload, output );
}

e_ws_frame_status
c_ws_frame::read( c_byte_stream *input, size_t limit )
{
    e_ws_frame_opcode out_opcode = e_ws_frame_opcode::opcode_binary;

    e_ws_frame_status status = c_ws_frame::impl_t::decode( input, &impl->payload, out_opcode, limit );

    impl->opcode = out_opcode;

    return status;
}

e_ws_frame_status
c_ws_frame::impl_t::encode( e_ws_frame_opcode opcode, bool mask, unsigned char *mask_key, c_byte_stream *input, c_byte_stream *output )
{
    if ( !output )
    {
        return e_ws_frame_status::status_error;
    }

    size_t offset = 0, size = input ? input->size() : 0;

    do
    {
        c_byte_stream fragment;

        ws_frame_byte1_t byte1;

        byte1.bits.fin = ( size <= CHUNK_SIZE );
        byte1.bits.rsv1 = 0x0; // < extension, used to indicate compression
        byte1.bits.rsv2 = 0x0; // < not in use yet.
        byte1.bits.rsv3 = 0x0; // < not in use yet.
        byte1.bits.opcode = ( offset == 0 ? opcode : e_ws_frame_opcode::opcode_continuation );

        if ( fragment.push_back( byte1.value ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }

        ws_frame_byte2_t byte2;

        byte2.bits.mask = mask;

        size_t payload_length = std::min< size_t >( CHUNK_SIZE, size );

        if ( payload_length > 65535 )
        {
            // indicate 64-bit payload length
            byte2.bits.payload_length = 127;

            if ( fragment.push_back( byte2.value ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }

            // 64-bit host to network endian conversion
            unsigned long long network_payload_length = c_endian::host_to_network_64( static_cast< unsigned long long >( payload_length ) );

            // write 64-bit value
            if ( fragment.push_back( reinterpret_cast< unsigned char * >( &network_payload_length ), 8 ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }
        else if ( payload_length > 125 )
        {
            // indicate 16-bit payload length
            byte2.bits.payload_length = 126;

            if ( fragment.push_back( byte2.value ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }

            // 16-bit host to network endian conversion
            unsigned short network_payload_length = c_endian::host_to_network_16( static_cast< unsigned short >( payload_length ) );

            // write 16-bit value
            if ( fragment.push_back( reinterpret_cast< unsigned char * >( &network_payload_length ), 2 ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }
        else
        {
            byte2.bits.payload_length = payload_length;

            if ( fragment.push_back( byte2.value ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }

        if ( mask )
        {
            if ( input && input->available() )
            {
                unsigned char *payload = input->pointer( offset );
                if ( !payload )
                {
                    return e_ws_frame_status::status_error;
                }

                // mask payload
                for ( size_t i = 0; i < payload_length; ++i )
                {
                    payload[ i ] ^= mask_key[ i % 4 ];
                }
            }

            // write 32-bit value
            if ( fragment.push_back( mask_key, 4 ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }

        if ( input && input->available() )
        {
            // move payload to fragment
            if ( input->move( &fragment, payload_length, offset ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }

        // move fragment to output
        if ( fragment.move( output, fragment.size(), 0 ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }

        // move to next fragment
        offset += payload_length;
        size -= payload_length;
    }
    while ( size > 0 );

    return e_ws_frame_status::status_ok;
}

e_ws_frame_status
c_ws_frame::impl_t::decode( c_byte_stream *input, c_byte_stream *output, e_ws_frame_opcode &opcode, size_t limit )
{
    if ( !input || !output )
    {
        return e_ws_frame_status::status_error;
    }

    if ( !input->available() )
    {
        return e_ws_frame_status::status_incomplete;
    }

    ws_frame_byte1_t byte1 = { *input->pointer() };

    // RFC 7692
    // todo: support rsv1 permessage-deflate compression

    // reserved bits for extending features
    if ( byte1.bits.rsv1 != 0 || byte1.bits.rsv2 != 0 || byte1.bits.rsv3 != 0 )
    {
        return e_ws_frame_status::status_error;
    }

    switch ( byte1.bits.opcode )
    {
        case e_ws_frame_opcode::opcode_continuation:
            if ( byte1.bits.fin )
            {
                return e_ws_frame_status::status_error;
            }
            break;

        case e_ws_frame_opcode::opcode_text:
        case e_ws_frame_opcode::opcode_binary:
        case e_ws_frame_opcode::opcode_close:
        case e_ws_frame_opcode::opcode_ping:
        case e_ws_frame_opcode::opcode_pong:
            opcode = byte1.bits.opcode;
            break;

        // further planned non controll
        case e_ws_frame_opcode::opcode_rsv1_further_non_controll:
        case e_ws_frame_opcode::opcode_rsv2_further_non_controll:
        case e_ws_frame_opcode::opcode_rsv3_further_non_controll:
        case e_ws_frame_opcode::opcode_rsv4_further_non_controll:
        case e_ws_frame_opcode::opcode_rsv5_further_non_controll:
            // those opcodes are reserved and are not being used yet.
            return e_ws_frame_status::status_error;

        // further planned controll
        case e_ws_frame_opcode::opcode_rsv1_further_controll:
        case e_ws_frame_opcode::opcode_rsv2_further_controll:
        case e_ws_frame_opcode::opcode_rsv3_further_controll:
        case e_ws_frame_opcode::opcode_rsv4_further_controll:
        case e_ws_frame_opcode::opcode_rsv5_further_controll:
            // those opcodes are reserved and are not being used yet.
            return e_ws_frame_status::status_error;
    }

    if ( input->size() < 2 )
    {
        return e_ws_frame_status::status_incomplete;
    }

    ws_frame_byte2_t byte2 = { *input->pointer( 1 ) };

    size_t payload_length = byte2.bits.payload_length;
    size_t offset = 2;

    if ( input->size() < ( payload_length == 127 ? 8 : 2 ) )
    {
        return e_ws_frame_status::status_incomplete;
    }

    if ( payload_length == 126 )
    {
        // read 16-bit value
        if ( input->copy( reinterpret_cast< unsigned char * >( &payload_length ), 2, nullptr, offset ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }

        // 16-bit network to host endian conversion
        payload_length = static_cast< unsigned long long >( c_endian::network_to_host_16( static_cast< unsigned short >( payload_length ) ) );

        // move by 2-bytes
        offset += 2;
    }
    else if ( payload_length == 127 )
    {
        // read 64-bit value
        if ( input->copy( reinterpret_cast< unsigned char * >( &payload_length ), 8, nullptr, offset ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }

        // 64-bit network to host endian conversion
        payload_length = c_endian::network_to_host_64( static_cast< unsigned long long >( payload_length ) );

        // move by 8-bytes
        offset += 8;
    }

    if ( ( output->size() + payload_length ) > limit )
    {
        return e_ws_frame_status::status_message_too_big;
    }

    if ( input->size() < offset )
    {
        return e_ws_frame_status::status_incomplete;
    }

    unsigned char mask_key[ 4 ] = { 0 };

    if ( byte2.bits.mask )
    {
        // payload is masked, read 32-bit mask-key
        input->copy( reinterpret_cast< unsigned char * >( &mask_key ), 4, nullptr, offset );

        // move by 4-bytes
        offset += 4;
    }

    if ( input->size() < offset + payload_length )
    {
        return e_ws_frame_status::status_incomplete;
    }

    if ( payload_length > 0 )
    {
        unsigned char *payload = input->pointer( offset );

        if ( !payload )
        {
            return e_ws_frame_status::status_error;
        }

        if ( byte2.bits.mask )
        {
            // unmask payload
            for ( size_t i = 0; i < payload_length; ++i )
            {
                payload[ i ] ^= mask_key[ i % 4 ];
            }
        }

        // move payload
        if ( input->move( output, payload_length, offset ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }
    }

    // frame processed
    if ( input->pop( offset ) != c_byte_stream::e_status::ok )
    {
        return e_ws_frame_status::status_error;
    }

    opcode = static_cast< e_ws_frame_opcode >( byte1.bits.opcode );

    if ( byte1.bits.fin )
    {
        // push null-terminator to indicate end of sequence
        if ( byte1.bits.opcode == e_ws_frame_opcode::opcode_text )
        {
            output->push_back( '\0' );
        }

        return e_ws_frame_status::status_final;
    }

    return e_ws_frame_status::status_fragment;
}
