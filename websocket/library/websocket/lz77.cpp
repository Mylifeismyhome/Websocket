#include <websocket/core/lz77.hpp>

#if defined( __clang__ ) || ( defined( __GNUC__ ) && ( __GNUC__ > 2 ) )
#define LIKELY( c ) ( __builtin_expect( !!( c ), 1 ) )
#define UNLIKELY( c ) ( __builtin_expect( !!( c ), 0 ) )
#else
#define LIKELY( c ) ( c )
#define UNLIKELY( c ) ( c )
#endif

#if defined( __x86_64__ ) || defined( _M_X64 ) || defined( __aarch64__ )
#define ARCH64
#endif

#define MAX_COPY 32
#define MAX_LEN 264

#define HASH_LOG 13
#define HASH_SIZE ( 1 << HASH_LOG )
#define HASH_MASK ( HASH_SIZE - 1 )

#define BOUND_CHECK( cond )      \
    if ( UNLIKELY( !( cond ) ) ) \
        return 0;

/**
 * @brief Reads a 32-bit unsigned integer from a pointer.
 *
 * @param[in] ptr Pointer to the location of the 32-bit value.
 *
 * @return The 32-bit unsigned integer value at the pointer location.
 */
static unsigned int
readu32( const void *ptr )
{
#ifdef ARCH64
    return *( const unsigned int * )ptr;
#else
    const unsigned char *p = ( const unsigned char * )ptr;
    return ( p[ 3 ] << 24 ) | ( p[ 2 ] << 16 ) | ( p[ 1 ] << 8 ) | p[ 0 ];
#endif
}

/**
 * @brief Compares two byte sequences and returns the length of the matching prefix.
 *
 * @param[in] p Pointer to the first byte sequence.
 * @param[in] q Pointer to the second byte sequence.
 * @param[in] r Pointer to the end of the second byte sequence.
 *
 * @return The length of the matching prefix.
 */
static unsigned int
cmp( const unsigned char *p, const unsigned char *q, const unsigned char *r )
{
#ifdef ARCH64
    const unsigned char *start = p;

    if ( readu32( p ) == readu32( q ) )
    {
        p += 4;
        q += 4;
    }
    while ( q < r )
        if ( *p++ != *q++ )
            break;
    return p - start;
#else
    const unsigned char *start = p;
    while ( q < r )
        if ( *p++ != *q++ )
            break;
    return p - start;
#endif
}

/**
 * @brief Computes a hash value for a 32-bit input.
 *
 * @param[in] v The 32-bit input value.
 *
 * @return The hash value computed from the input.
 */
static unsigned short
make_hash( unsigned int v )
{
    unsigned int h = ( v * 2654435769LL ) >> ( 32 - HASH_LOG );
    return h & HASH_MASK;
}

/**
 * @brief Encodes a sequence of literal bytes.
 *
 * @param[in] runs The number of bytes to encode.
 * @param[in] src Pointer to the source buffer.
 * @param[out] dest Pointer to the destination buffer.
 *
 * @return Pointer to the end of the destination buffer after encoding.
 */
static unsigned char *
literals( unsigned int runs, const unsigned char *src, unsigned char *dest )
{
    while ( runs >= MAX_COPY )
    {
        *dest++ = MAX_COPY - 1;
        std::memcpy( dest, src, MAX_COPY );
        src += MAX_COPY;
        dest += MAX_COPY;
        runs -= MAX_COPY;
    }
    if ( runs > 0 )
    {
        *dest++ = runs - 1;
        std::memcpy( dest, src, runs );
        dest += runs;
    }
    return dest;
}

/**
 * @brief Encodes a match of a sequence.
 *
 * @param[in] len Length of the match.
 * @param[in] distance Distance of the match.
 * @param[out] op Pointer to the destination buffer for the encoded match.
 *
 * @return Pointer to the end of the destination buffer after encoding.
 */
static unsigned char *
match1( unsigned int len, unsigned int distance, unsigned char *op )
{
    --distance;
    if ( UNLIKELY( len > MAX_LEN - 2 ) )
    {
        while ( len > MAX_LEN - 2 )
        {
            *op++ = ( 7 << 5 ) + ( distance >> 8 );
            *op++ = MAX_LEN - 2 - 7 - 2;
            *op++ = ( distance & 255 );
            len -= MAX_LEN - 2;
        }
    }
    if ( len < 7 )
    {
        *op++ = ( len << 5 ) + ( distance >> 8 );
        *op++ = ( distance & 255 );
    }
    else
    {
        *op++ = ( 7 << 5 ) + ( distance >> 8 );
        *op++ = len - 7;
        *op++ = ( distance & 255 );
    }
    return op;
}

int
c_lz277::compress( unsigned char *input, size_t length, unsigned char *output, size_t window_size )
{
    const unsigned char *ip = input;
    const unsigned char *ip_start = ip;
    const unsigned char *ip_bound = ip + length - 4;
    const unsigned char *ip_limit = ip + length - 12 - 1;
    unsigned char *op = output;

    unsigned int htab[ HASH_SIZE ];
    unsigned int seq, hash;

    for ( hash = 0; hash < HASH_SIZE; ++hash )
    {
        htab[ hash ] = 0;
    }

    const unsigned char *anchor = ip;

    ip += 2;

    while ( LIKELY( ip < ip_limit ) )
    {
        const unsigned char *ref;

        unsigned int distance, cmp_val;

        do
        {
            seq = readu32( ip ) & 0xffffff;
            hash = make_hash( seq );
            ref = ip_start + htab[ hash ];
            htab[ hash ] = ip - ip_start;
            distance = ip - ref;
            cmp_val = LIKELY( distance < window_size ) ? readu32( ref ) & 0xffffff : 0x1000000;

            if ( UNLIKELY( ip >= ip_limit ) )
            {
                break;
            }

            ++ip;
        }
        while ( seq != cmp_val );

        if ( UNLIKELY( ip >= ip_limit ) )
        {
            break;
        }

        --ip;

        if ( LIKELY( ip > anchor ) )
        {
            op = literals( ip - anchor, anchor, op );
        }

        unsigned int len = cmp( ref + 3, ip + 3, ip_bound );

        op = match1( len, distance, op );

        ip += len;
        seq = readu32( ip );
        hash = make_hash( seq & 0xffffff );
        htab[ hash ] = ip++ - ip_start;
        seq >>= 8;
        hash = make_hash( seq );
        htab[ hash ] = ip++ - ip_start;

        anchor = ip;
    }

    unsigned int copy = ( unsigned char * )input + length - anchor;

    op = literals( copy, anchor, op );

    return op - ( unsigned char * )output;
}

int
c_lz277::decompress( unsigned char *input, size_t length, unsigned char *output, size_t maxout )
{
    const unsigned char *ip = ( const unsigned char * )input;
    const unsigned char *ip_limit = ip + length;
    unsigned char *op = ( unsigned char * )output;
    unsigned char *op_limit = op + maxout;
    unsigned char *op_end = op;

    while ( LIKELY( ip < ip_limit ) )
    {
        unsigned int ctrl = *ip++;

        if ( UNLIKELY( ctrl < ( 1 << 5 ) ) )
        {
            ctrl++;
            BOUND_CHECK( op_end + ctrl <= op_limit );
            std::memcpy( op_end, ip, ctrl );
            ip += ctrl;
            op_end += ctrl;
        }
        else
        {
            unsigned int len = ctrl >> 5;
            unsigned int distance = ( ctrl & 31 ) << 8;

            if ( len == 7 )
            {
                BOUND_CHECK( ip < ip_limit );
                len += *ip++;
            }

            BOUND_CHECK( ip < ip_limit );

            distance += *ip++;
            distance++;

            BOUND_CHECK( op_end - distance >= op && op_end + len + 2 <= op_limit );

            unsigned char *ref = op_end - distance;
            len += 2;
            std::memcpy( op_end, ref, MAX_COPY );
            op_end += len;
        }
    }

    return op_end - ( unsigned char * )output;
}
