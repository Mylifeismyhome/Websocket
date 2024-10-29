#include <websocket/core/huffman.h>

#include <queue>
#include <stack>

struct c_huffman::impl_t
{
    struct Node
    {
        unsigned char character;
        size_t frequency;
        Node *left, *right;
        Node( const unsigned char d, const size_t f ) :
            character( d ), frequency( f ), left( nullptr ), right( nullptr ) {}
    };

    struct Compare
    {
        bool
        operator()( const Node *a, const Node *b ) const
        {
            return a->frequency > b->frequency;
        }
    };

    static void
    huffman_build_frequency_table( const std::vector< unsigned char > &input, std::map< unsigned char, size_t > &frequency );

    static Node *
    huffman_build_tree( const std::map< unsigned char, size_t > &frequency );

    static e_status
    huffman_build_bits_table( Node *root, std::map< unsigned char, std::vector< bool > > &huffman_bits );

    static void
    huffman_release_tree( const Node *node );
};

void
c_huffman::impl_t::huffman_build_frequency_table( const std::vector< unsigned char > &input, std::map< unsigned char, size_t > &frequency )
{
    for ( unsigned char character : input )
    {
        auto it = frequency.find( character );
        if ( it == frequency.end() )
        {
            frequency.emplace( character, 1 );
            continue;
        }

        it->second++;
    }
}

c_huffman::impl_t::Node *
c_huffman::impl_t::huffman_build_tree( const std::map< unsigned char, size_t > &frequency )
{
    std::priority_queue< Node *, std::vector< Node * >, Compare > min_heap;

    for ( const auto it : frequency )
    {
        min_heap.emplace( new Node( it.first, it.second ) );
    }

    while ( min_heap.size() > 1 )
    {
        Node *left = min_heap.top();
        min_heap.pop();

        Node *right = min_heap.top();
        min_heap.pop();

        auto parent = new Node( 0, left->frequency + right->frequency );
        parent->left = left;
        parent->right = right;

        min_heap.push( parent );
    }

    return min_heap.empty() ? nullptr : min_heap.top();
}

c_huffman::e_status
c_huffman::impl_t::huffman_build_bits_table( Node *root, std::map< unsigned char, std::vector< bool > > &huffman_bits )
{
    if ( !root )
    {
        return e_status::status_error;
    }

    std::stack< std::pair< Node *, std::vector< bool > > > stack;
    stack.emplace( root, std::vector< bool >() );

    while ( !stack.empty() )
    {
        Node *node = stack.top().first;
        const std::vector< bool > bits = stack.top().second;
        stack.pop();

        if ( !node->left && !node->right )
        {
            huffman_bits[ node->character ] = bits;
        }

        if ( node->right )
        {
            std::vector< bool > right_bits = bits;
            right_bits.push_back( true );
            stack.emplace( node->right, right_bits );
        }

        if ( node->left )
        {
            std::vector< bool > left_bits = bits;
            left_bits.push_back( false );
            stack.emplace( node->left, left_bits );
        }
    }

    return e_status::status_ok;
}

void
c_huffman::impl_t::huffman_release_tree( const Node *node )
{
    if ( node == nullptr )
    {
        return;
    }

    huffman_release_tree( node->left );
    huffman_release_tree( node->right );

    delete node;
}

c_huffman::e_status
c_huffman::encode( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, std::map< unsigned char, size_t > &frequency_table )
{
    impl_t::huffman_build_frequency_table( input, frequency_table );

    impl_t::Node *root = impl_t::huffman_build_tree( frequency_table );
    if ( !root )
    {
        return e_status::status_error;
    }

    std::map< unsigned char, std::vector< bool > > bits_table;
    if ( impl_t::huffman_build_bits_table( root, bits_table ) != e_status::status_ok )
    {
        return e_status::status_error;
    }

    size_t output_length = 0;

    for ( unsigned char character : input )
    {
        auto it = bits_table.find( character );
        if ( it == bits_table.end() )
        {
            impl_t::huffman_release_tree( root );
            return e_status::status_error;
        }

        std::vector< bool > bits = bits_table[ character ];

        output_length += bits.size();
    }

    output.resize( ( output_length + 7 ) / 8 );

    for ( size_t i = 0, bit_index = 0; i < input.size(); ++i )
    {
        unsigned char character = input[ i ];

        auto it = bits_table.find( character );
        if ( it == bits_table.end() )
        {
            impl_t::huffman_release_tree( root );
            return e_status::status_error;
        }

        std::vector< bool > bits = bits_table[ character ];

        for ( const bool bit : bits )
        {
            const size_t byte_index = bit_index / 8;
            const size_t bit_position = 7 - bit_index % 8;

            if ( bit )
            {
                output[ byte_index ] |= 1 << bit_position;
            }

            bit_index++;
        }
    }

    // eob
    output.push_back( 0x1000 );

    impl_t::huffman_release_tree( root );

    return e_status::status_ok;
}

c_huffman::e_status
c_huffman::decode( const std::vector< unsigned char > &input, std::vector< unsigned char > &output, const std::map< unsigned char, size_t > &frequency_table )
{
    const impl_t::Node *root = impl_t::huffman_build_tree( frequency_table );
    if ( !root )
    {
        return e_status::status_error;
    }

    const impl_t::Node *node = root;

    size_t output_length = 0;

    for ( size_t bits = 0; bits < input.size() * 8; ++bits )
    {
        const size_t byte_index = bits / 8;
        const size_t bit_position = 7 - bits % 8;
        const unsigned char value = input[ byte_index ];

        // eob
        if ( value == 0x1000 )
        {
            break;
        }

        const bool bit = value >> bit_position & 1;

        node = bit ? node->right : node->left;

        if ( !node )
        {
            impl_t::huffman_release_tree( root );
            return e_status::status_error;
        }

        if ( !node->left && !node->right )
        {
            output_length++;
            node = root;
        }
    }

    output.resize( output_length );

    for ( size_t bits = 0, i = 0; bits < input.size() * 8; ++bits )
    {
        const size_t byte_index = bits / 8;
        const size_t bit_position = 7 - bits % 8;
        const unsigned char value = input[ byte_index ];

        // eob
        if ( value == 0x1000 )
        {
            break;
        }

        const bool bit = value >> bit_position & 1;

        node = bit ? node->right : node->left;

        if ( !node )
        {
            impl_t::huffman_release_tree( root );
            return e_status::status_error;
        }

        if ( !node->left && !node->right )
        {
            output[ i++ ] = node->character;
            node = root;
        }
    }

    impl_t::huffman_release_tree( root );

    return e_status::status_ok;
}
