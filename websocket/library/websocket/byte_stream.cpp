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

#include <websocket/core/byte_stream.hpp>

#include <cstring>
#include <mutex>
#include <vector>

struct c_byte_stream::impl_t
{
    mutable std::recursive_mutex mutex;
    std::vector< unsigned char > container;

    bool
    try_lock() const;

    void
    wait_lock() const;

    void
    unlock() const;

    c_byte_stream::e_status
    push( unsigned char *source, size_t size );

    c_byte_stream::e_status
    push_back( unsigned char *source, size_t size );

    c_byte_stream::e_status
    pull( unsigned char *destination, size_t &size, size_t offset );

    c_byte_stream::e_status
    pull_back( unsigned char *destination, size_t &size, size_t offset );

    c_byte_stream::e_status
    move( c_byte_stream *destination, size_t size, size_t offset );

    c_byte_stream::e_status
    copy( unsigned char *destination, size_t size, size_t *available, size_t offset );

    c_byte_stream::e_status
    pop( size_t size );

    c_byte_stream::e_status
    pop_back( size_t size );

    c_byte_stream::e_status
    erase( size_t start, size_t size );

    void
    flush();

    int
    compare( unsigned char *pattern, size_t size, size_t offset );

    size_t
    index_of( int val, size_t offset );

    size_t
    index_of( unsigned char *pattern, size_t size, size_t offset );

    size_t
    index_of_back( int val, size_t offset );

    size_t
    index_of_back( unsigned char *pattern, size_t size, size_t offset );

    unsigned char *
    pointer( size_t offset ) const;

    bool
    is_utf8() const;
};

bool
c_byte_stream::impl_t::try_lock() const
{
    return mutex.try_lock();
}

void
c_byte_stream::impl_t::wait_lock() const
{
    mutex.lock();
}

void
c_byte_stream::impl_t::unlock() const
{
    mutex.unlock();
}

c_byte_stream::c_byte_stream()
{
    impl = new impl_t();
}

c_byte_stream::c_byte_stream( const c_byte_stream &other )
{
    impl = new impl_t();

    std::lock( impl->mutex, other.impl->mutex );
    std::lock_guard< std::recursive_mutex > lhs_lock( impl->mutex, std::adopt_lock );
    std::lock_guard< std::recursive_mutex > rhs_lock( other.impl->mutex, std::adopt_lock );

    impl->container = other.impl->container;
}

c_byte_stream &
c_byte_stream::operator=( const c_byte_stream &other )
{
    if ( this == &other )
    {
        return *this;
    }

    std::lock( impl->mutex, other.impl->mutex );
    std::lock_guard< std::recursive_mutex > lhs_lock( impl->mutex, std::adopt_lock );
    std::lock_guard< std::recursive_mutex > rhs_lock( other.impl->mutex, std::adopt_lock );

    impl->container = other.impl->container;

    return *this;
}

c_byte_stream::c_byte_stream( c_byte_stream &&other ) noexcept
{
    impl = other.impl;
    other.impl = nullptr;
}

c_byte_stream &
c_byte_stream::operator=( c_byte_stream &&other ) noexcept
{
    if ( this == &other )
    {
        return *this;
    }

    impl = other.impl;
    other.impl = nullptr;

    return *this;
}

c_byte_stream::~c_byte_stream()
{
    if ( impl )
    {
        delete impl;
        impl = nullptr;
    }
}

c_byte_stream &
c_byte_stream::operator<<( unsigned char value )
{
    push_back( value );
    return *this;
}

c_byte_stream &
c_byte_stream::operator<<( const char *value )
{
    size_t size = std::strlen( value );
    push_back( reinterpret_cast< unsigned char * >( const_cast< char * >( value ) ), size );
    return *this;
}

c_byte_stream &
c_byte_stream::operator<<( unsigned char *value )
{
    size_t size = std::strlen( reinterpret_cast< const char * >( value ) );
    push_back( value, size );
    return *this;
}

void
c_byte_stream::close()
{
    impl->wait_lock();

    impl->flush();

    impl->unlock();
}

void
c_byte_stream::resize( size_t size )
{
    impl->wait_lock();

    impl->container.resize( size );

    impl->unlock();
}

c_byte_stream::e_status
c_byte_stream::impl_t::push( unsigned char *source, size_t size )
{
    try
    {
        container.insert( container.begin(), source, source + size );
    }
    catch ( const std::bad_alloc & )
    {
        return c_byte_stream::e_status::out_of_memory;
    }
    catch ( ... )
    {
        return c_byte_stream::e_status::error;
    }

    return c_byte_stream::e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::push_back( unsigned char *source, size_t size )
{
    try
    {
        container.insert( container.end(), source, source + size );
    }
    catch ( const std::bad_alloc & )
    {
        return c_byte_stream::e_status::out_of_memory;
    }
    catch ( ... )
    {
        return c_byte_stream::e_status::error;
    }

    return c_byte_stream::e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::pull( unsigned char *destination, size_t &size, size_t offset )
{
    if ( offset >= container.size() )
    {
        return c_byte_stream::e_status::out_of_bound;
    }

    size = std::min( size, container.size() - offset );

    try
    {
        std::memcpy( destination, container.data() + offset, size );
    }
    catch ( ... )
    {
        return c_byte_stream::e_status::error;
    }

    return pop( size );
}


c_byte_stream::e_status
c_byte_stream::impl_t::pull_back( unsigned char *destination, size_t &size, size_t offset )
{
    if ( offset >= container.size() )
    {
        return c_byte_stream::e_status::out_of_bound;
    }

    size = std::min( size, container.size() - offset );

    try
    {
        std::memcpy( destination, container.data() + offset, size );
    }
    catch ( ... )
    {
        return c_byte_stream::e_status::error;
    }

    return pop_back( size );
}

c_byte_stream::e_status
c_byte_stream::impl_t::move( c_byte_stream *destination, size_t size, size_t offset )
{
    if ( offset >= container.size() )
    {
        return c_byte_stream::e_status::out_of_bound;
    }

    if ( offset + size > container.size() )
    {
        return c_byte_stream::e_status::out_of_bound;
    }

    try
    {
        auto begin = container.begin() + offset;
        auto end = begin + size;

        destination->impl->container.insert( destination->impl->container.end(),
            std::make_move_iterator( begin ),
            std::make_move_iterator( end ) );

        container.erase( begin, end );
    }
    catch ( const std::bad_alloc & )
    {
        return c_byte_stream::e_status::out_of_memory;
    }
    catch ( ... )
    {
        return c_byte_stream::e_status::error;
    }

    return c_byte_stream::e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::copy( unsigned char *destination, size_t size, size_t *available, size_t offset )
{
    if ( offset >= container.size() )
    {
        return c_byte_stream::e_status::out_of_bound;
    }

    size = std::min( size, container.size() - offset );

    if ( available )
    {
        ( *available ) = size;
    }

    try
    {
        std::memcpy( destination, container.data() + offset, size );
    }
    catch ( ... )
    {
        return c_byte_stream::e_status::error;
    }

    return c_byte_stream::e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::pop( size_t size )
{
    if ( size > container.size() )
    {
        return c_byte_stream::e_status::out_of_bound;
    }

    try
    {
        container.erase( container.begin(), container.begin() + size );
    }
    catch ( ... )
    {
        return c_byte_stream::e_status::error;
    }

    return c_byte_stream::e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::pop_back( size_t size )
{
    if ( size > container.size() )
    {
        return c_byte_stream::e_status::out_of_bound;
    }

    try
    {
        container.erase( container.end() - size, container.end() );
    }
    catch ( ... )
    {
        return c_byte_stream::e_status::error;
    }

    return c_byte_stream::e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::erase( size_t start, size_t size )
{
    if ( start >= container.size() || start + size > container.size() )
    {
        return c_byte_stream::e_status::out_of_bound;
    }

    try
    {
        container.erase( container.begin() + start, container.begin() + start + size );
    }
    catch ( ... )
    {
        return c_byte_stream::e_status::error;
    }

    return c_byte_stream::e_status::ok;
}

void
c_byte_stream::impl_t::flush()
{
    container.clear();
}

int
c_byte_stream::impl_t::compare( unsigned char *pattern, size_t size, size_t offset )
{
    if ( container.empty() || size == 0 || offset >= container.size() )
    {
        return -1;
    }

    size = std::min( size, container.size() - offset );

    return std::memcmp( container.data() + offset, pattern, size );
}

size_t
c_byte_stream::impl_t::index_of( int val, size_t offset )
{
    if ( container.empty() || offset >= container.size() )
    {
        return npos;
    }

    unsigned char *ptr = static_cast< unsigned char * >( std::memchr( container.data() + offset, static_cast< unsigned char >( val ), container.size() - offset ) );

    if ( ptr == nullptr )
    {
        return npos;
    }

    return ptr - container.data();
}

size_t
c_byte_stream::impl_t::index_of( unsigned char *pattern, size_t size, size_t offset )
{
    if ( container.empty() || size == 0 || size > container.size() || offset >= container.size() )
    {
        return npos;
    }

    size_t end = container.size() - size;

    for ( size_t i = offset; i <= end; ++i )
    {
        if ( compare( pattern, size, i ) == 0 )
        {
            return i;
        }
    }

    return npos;
}

size_t
c_byte_stream::impl_t::index_of_back( int val, size_t offset )
{
    if ( container.empty() || offset >= container.size() )
    {
        return npos;
    }

    size_t start = container.size() - offset;

    for ( size_t i = start; i != npos; --i )
    {
        if ( container[ i ] == static_cast< unsigned char >( val ) )
        {
            return i;
        }
    }

    return npos;
}

size_t
c_byte_stream::impl_t::index_of_back( unsigned char *pattern, size_t size, size_t offset )
{
    if ( container.empty() || size == 0 || size > container.size() || offset >= container.size() )
    {
        return npos;
    }

    size_t start = std::min( offset, container.size() - size );

    for ( size_t i = start; i != npos; --i )
    {
        if ( compare( pattern, size, i ) == 0 )
        {
            return i;
        }

        if ( i == 0 )
        {
            break;
        }
    }

    return npos;
}

unsigned char *
c_byte_stream::impl_t::pointer( size_t offset ) const
{
    if ( container.empty() || offset >= container.size() )
    {
        return nullptr;
    }

    return const_cast< unsigned char * >( container.data() + offset );
}

bool
c_byte_stream::impl_t::is_utf8() const
{
    if ( container.empty() )
    {
        return false;
    }

    size_t i = 0;
    const size_t len = container.size();

    while ( i < len )
    {
        unsigned char c = container[ i ];
        int n = 0;

        if ( c <= 0x7F )
        {
            // 1-byte ascii (0xxxxxxx)
            n = 0;
        }
        else if ( ( c & 0xE0 ) == 0xC0 )
        {
            // 2-byte sequence (110xxxxx)
            n = 1;
        }
        else if ( ( c & 0xF0 ) == 0xE0 )
        {
            // 3-byte sequence (1110xxxx)
            n = 2;
        }
        else if ( ( c & 0xF8 ) == 0xF0 )
        {
            // 4-byte sequence (11110xxx)
            n = 3;
        }
        else if ( c == 0xED && i + 1 < len && ( container[ i + 1 ] & 0xA0 ) == 0xA0 )
        {
            // invalid surrogate half
            return false;
        }
        else
        {
            // invalid utf-8 start byte
            return false;
        }

        // verify that the `n` continuation bytes start with 10xxxxxx
        for ( int j = 0; j < n; ++j )
        {
            if ( ++i >= len || ( container[ i ] & 0xC0 ) != 0x80 )
            {
                return false;
            }
        }

        ++i;
    }

    return true;
}

c_byte_stream::e_status
c_byte_stream::push( unsigned char value )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->push( &value, 1 );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_async( unsigned char value )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->push( &value, 1 );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push( unsigned char *source, size_t size )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->push( source, size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_async( unsigned char *source, size_t size )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->push( source, size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_back( unsigned char value )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->push_back( &value, 1 );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_back_async( unsigned char value )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->push_back( &value, 1 );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_back( unsigned char *source, size_t size )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->push_back( source, size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_back_async( unsigned char *source, size_t size )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->push_back( source, size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pull( unsigned char *destination, size_t &size, size_t offset )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->pull( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pull_async( unsigned char *destination, size_t &size, size_t offset )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->pull( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pull_back( unsigned char *destination, size_t &size, size_t offset )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->pull_back( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pull_back_async( unsigned char *destination, size_t &size, size_t offset )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->pull_back( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::move( c_byte_stream *destination, size_t size, size_t offset )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->move( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::move_async( c_byte_stream *destination, size_t size, size_t offset )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->move( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::copy( unsigned char *destination, size_t size, size_t *available, size_t offset )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->copy( destination, size, available, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::copy_async( unsigned char *destination, size_t size, size_t *available, size_t offset )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->copy( destination, size, available, offset );

    impl->unlock();

    return status;
}

unsigned char *
c_byte_stream::pointer( size_t offset ) const
{
    return impl->pointer( offset );
}

c_byte_stream::e_status
c_byte_stream::pop( size_t size )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->pop( size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pop_async( size_t size )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->pop( size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pop_back( size_t size )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->pop_back( size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pop_back_async( size_t size )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->pop_back( size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::erase( size_t start, size_t size )
{
    impl->wait_lock();

    c_byte_stream::e_status status = impl->erase( start, size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::erase_async( size_t start, size_t size )
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    c_byte_stream::e_status status = impl->erase( start, size );

    impl->unlock();

    return status;
}

void
c_byte_stream::flush()
{
    impl->wait_lock();

    impl->flush();

    impl->unlock();
}

c_byte_stream::e_status
c_byte_stream::flush_async()
{
    if ( !impl->try_lock() )
    {
        return c_byte_stream::e_status::busy;
    }

    impl->flush();

    impl->unlock();

    return c_byte_stream::e_status::ok;
}

int
c_byte_stream::compare( unsigned char *pattern, size_t size, size_t offset )
{
    impl->wait_lock();

    int ret = impl->compare( pattern, size, offset );

    impl->unlock();

    return ret;
}

int
c_byte_stream::compare_async( unsigned char *pattern, size_t size, size_t offset )
{
    if ( !impl->try_lock() )
    {
        return -1;
    }

    int ret = impl->compare( pattern, size, offset );

    impl->unlock();

    return ret;
}

size_t
c_byte_stream::index_of( int val, size_t offset )
{
    impl->wait_lock();

    size_t pos = impl->index_of( val, offset );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_async( int val, size_t offset )
{
    if ( !impl->try_lock() )
    {
        return npos;
    }

    size_t pos = impl->index_of( val, offset );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of( unsigned char *pattern, size_t size, size_t offset )
{
    impl->wait_lock();

    size_t pos = impl->index_of( pattern, size, offset );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_async( unsigned char *pattern, size_t size, size_t offset )
{
    if ( !impl->try_lock() )
    {
        return npos;
    }

    size_t pos = impl->index_of( pattern, size, offset );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_back( int val, size_t offset )
{
    impl->wait_lock();

    size_t pos = impl->index_of_back( val, offset );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_back( unsigned char *pattern, size_t size, size_t offset )
{
    impl->wait_lock();

    size_t pos = impl->index_of_back( pattern, size, offset );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_back_async( int val, size_t offset )
{
    if ( !impl->try_lock() )
    {
        return npos;
    }

    size_t pos = impl->index_of_back( val, offset );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_back_async( unsigned char *pattern, size_t size, size_t offset )
{
    if ( !impl->try_lock() )
    {
        return npos;
    }

    size_t pos = impl->index_of_back( pattern, size, offset );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::size() const
{
    return impl->container.size();
}

bool
c_byte_stream::available() const
{
    return size() > 0;
}

bool
c_byte_stream::is_utf8() const
{
    return impl->is_utf8();
}
