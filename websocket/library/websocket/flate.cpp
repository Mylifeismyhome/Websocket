/**
 * WIP deflate/inflate RFC1951
 *
 *      DEFLATE Compressed Data Format Specification version 1.3
 */

#undef CUSTOM_IMPL

#include <websocket/core/flate.h>

#ifdef CUSTOM_IMPL
#include <websocket/core/endian.h>
#include <websocket/core/huffman.h>
#include <websocket/core/lz77.h>

#include <cstring>
#include <map>

enum e_block_type
{
    block_type_uncompressed = 0b00,
    block_type_fixed_huffman = 0b01,
    block_type_dynamic_huffman = 0b10,
};

union header_t
{
    unsigned char value;

    struct
    {
        unsigned char final : 1; // BFINAL bit (1 = last block, 0 = more blocks)
        unsigned char type : 2; // BTYPE (00 = uncompressed, 01 = fixed Huffman, 10 = dynamic Huffman)
        unsigned char reserved : 5;
    } bits;
};

#else
#include <websocket/core/deflate.h>

#include <websocket/core/inftrees.h>

#include <websocket/core/inflate.h>
#endif

c_flate::e_status
c_flate::deflate( const c_byte_stream *input, const c_byte_stream *output, const size_t window_size )
{
#ifdef CUSTOM_IMPL
    size_t offset = 0;

    while ( offset < input.size() )
    {
        std::vector< unsigned char > block;

        const size_t available_size = input.size() - offset;
        const size_t next_size = std::min( block_size, available_size );

        header_t header{};
        header.bits.final = available_size == next_size;
        header.bits.type = block_type_dynamic_huffman;

        block.insert( block.begin(), header.value );

        switch ( header.bits.type )
        {
            case block_type_uncompressed:
            {
                const unsigned short len = c_endian::little_endian_16( next_size );
                const unsigned short nlen = ~len;

                block.insert( block.end(), reinterpret_cast< const unsigned char * >( &len ), reinterpret_cast< const unsigned char * >( &len ) + sizeof( len ) );
                block.insert( block.end(), reinterpret_cast< const unsigned char * >( &nlen ), reinterpret_cast< const unsigned char * >( &nlen ) + sizeof( nlen ) );

                block.insert( block.end(), input.begin() + static_cast< ptrdiff_t >( offset ), input.begin() + static_cast< ptrdiff_t >( offset ) + static_cast< ptrdiff_t >( next_size ) );

                break;
            }

            case block_type_dynamic_huffman:
            {
                std::vector< unsigned char > nn;
                nn.insert( nn.end(), input.begin() + static_cast< ptrdiff_t >( offset ), input.begin() + static_cast< ptrdiff_t >( offset ) + static_cast< ptrdiff_t >( next_size ) );

                std::vector< unsigned char > encoded;
                std::map< unsigned char, size_t > frequency_table;
                c_huffman::encode( nn, encoded, frequency_table );


                break;
            }
        }

        output.insert( output.end(), block.begin(), block.end() );

        offset += next_size;
    }

    return e_status::status_ok;
#else
    z_stream strm = {};

    int ret = deflateInit2( &strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -1 * window_size, 8, Z_DEFAULT_STRATEGY );
    if ( ret != Z_OK )
    {
        return e_status::status_error;
    }

    strm.avail_in = input->size();
    strm.next_in = input->pointer();

    std::vector< unsigned char > buffer( 32768 );

    do
    {
        strm.avail_out = buffer.size();
        strm.next_out = buffer.data();

        ret = ::deflate( &strm, Z_FINISH );
        if ( ret == Z_STREAM_ERROR )
        {
            deflateEnd( &strm );
            return e_status::status_error;
        }

        if ( output->push_back( buffer.data(), buffer.size() - strm.avail_out ) != c_byte_stream::e_status::ok )
        {
            deflateEnd( &strm );
            return e_status::status_error;
        }
    }
    while ( strm.avail_out == 0 );

    deflateEnd( &strm );

    return ( ret == Z_STREAM_END ) ? e_status::status_ok : e_status::status_error;
#endif
}

c_flate::e_status
c_flate::inflate( const c_byte_stream *input, const c_byte_stream *output, const size_t window_size )
{
#ifdef CUSTOM_IMPL
    if ( input.size() < sizeof( header_t ) )
    {
        return e_status::status_not_enough_data;
    }

    size_t offset = 0;

    bool complete = false;

    while ( offset < input.size() )
    {
        header_t header{};
        header.value = input[ offset ];

        offset += sizeof( header_t );

        switch ( header.bits.type )
        {
            case block_type_uncompressed:
            {
                if ( input.size() < offset + sizeof( unsigned short ) )
                {
                    return e_status::status_not_enough_data;
                }

                unsigned short len = 0;
                std::memcpy( &len, &input[ offset ], sizeof( unsigned short ) );

                if ( c_endian::is_big() )
                {
                    len = c_endian::big_endian_16( len );
                }

                offset += sizeof( unsigned short );

                if ( input.size() < offset + sizeof( unsigned short ) )
                {
                    return e_status::status_not_enough_data;
                }

                unsigned short nlen = 0;
                std::memcpy( &nlen, &input[ offset ], sizeof( unsigned short ) );

                if ( c_endian::is_big() )
                {
                    nlen = c_endian::big_endian_16( nlen );
                }

                nlen = ~nlen;

                offset += sizeof( unsigned short );

                if ( nlen != len )
                {
                    return e_status::status_length_mismatch;
                }

                if ( input.size() < offset + len )
                {
                    return e_status::status_not_enough_data;
                }

                output.insert( output.end(), input.begin() + static_cast< ptrdiff_t >( offset ), input.begin() + static_cast< ptrdiff_t >( offset ) + len );

                offset += len;

                break;
            }
        }

        complete = header.bits.final;
    }

    return complete ? e_status::status_ok : e_status::status_not_enough_data;
#else
    z_stream strm = {};

    int ret = inflateInit2( &strm, -1 * window_size );
    if ( ret != Z_OK )
    {
        return e_status::status_error;
    }

    strm.avail_in = input->size();
    strm.next_in = input->pointer();

    std::vector< unsigned char > buffer( 32768 );

    do
    {
        strm.avail_out = buffer.size();
        strm.next_out = buffer.data();

        ret = ::inflate( &strm, Z_SYNC_FLUSH );
        if ( ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR )
        {
            inflateEnd( &strm );
            return e_status::status_error;
        }

        if ( output->push_back( buffer.data(), buffer.size() - strm.avail_out ) != c_byte_stream::e_status::ok )
        {
            inflateEnd( &strm );
            return e_status::status_error;
        }
    }
    while ( strm.avail_in > 0 );

    inflateEnd( &strm );

    return ( ret == Z_OK || ret == Z_STREAM_END ) ? e_status::status_ok : e_status::status_error;
#endif
}
