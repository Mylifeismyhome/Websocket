#include <websocket/core/huffman.h>

#include <queue>
#include <stack>

struct c_huffman::impl_t
{
    static constexpr short EOB = 0x100;

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
    huffman_build_code_table( Node *root, std::map< unsigned char, std::vector< bool > > &huffman_bits );

    static void
    huffman_release_tree( const Node *node );
};

constexpr short c_huffman::impl_t::EOB;

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

    frequency.emplace( EOB, 1 );
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
c_huffman::impl_t::huffman_build_code_table( Node *root, std::map< unsigned char, std::vector< bool > > &huffman_bits )
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

    std::stack< const Node * > node_stack;
    std::vector< const Node * > node_order;

    node_stack.push( node );

    while ( !node_stack.empty() )
    {
        const Node *current = node_stack.top();
        node_stack.pop();

        node_order.push_back( current );

        if ( current->left )
        {
            node_stack.push( current->left );
        }
        if ( current->right )
        {
            node_stack.push( current->right );
        }
    }

    for ( auto it = node_order.rbegin(); it != node_order.rend(); ++it )
    {
        delete *it;
    }
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

    std::map< unsigned char, std::vector< bool > > code_table;

    if ( impl_t::huffman_build_code_table( root, code_table ) != e_status::status_ok )
    {
        impl_t::huffman_release_tree( root );

        return e_status::status_error;
    }

    size_t output_length = 0;

    for ( unsigned char character : input )
    {
        auto it = code_table.find( character );

        if ( it == code_table.end() )
        {
            impl_t::huffman_release_tree( root );

            return e_status::status_error;
        }

        std::vector< bool > bits = code_table[ character ];

        output_length += bits.size();
    }

    output.resize( ( output_length + 7 ) / 8 );

    std::fill( output.begin(), output.end(), 0 );

    size_t bit_index = 0;

    for ( unsigned char character : input )
    {
        auto it = code_table.find( character );

        if ( it == code_table.end() )
        {
            impl_t::huffman_release_tree( root );

            return e_status::status_error;
        }

        std::vector< bool > code = code_table[ character ];

        for ( const bool bit : code )
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

    const size_t bits = input.size() * 8;

    const impl_t::Node *node = root;

    size_t output_length = 0;

    for ( size_t i = 0; i < bits; ++i )
    {
        const size_t byte_index = i / 8;

        const size_t bit_position = 7 - i % 8;

        const unsigned char value = input[ byte_index ];

        const bool bit = value >> bit_position & 1;

        node = bit ? node->right : node->left;

        if ( node )
        {
            if ( !node->left && !node->right )
            {
                if ( node->character == impl_t::EOB )
                {
                    break;
                }

                output_length++;

                node = root;
            }
        }
        else
        {
            impl_t::huffman_release_tree( root );

            return e_status::status_error;
        }
    }

    output.resize( output_length );

    std::fill( output.begin(), output.end(), 0 );

    node = root;

    size_t output_index = 0;
    for ( size_t i = 0; i < bits; ++i )
    {
        const size_t byte_index = i / 8;

        const size_t bit_position = 7 - i % 8;

        const unsigned char value = input[ byte_index ];

        const bool bit = value >> bit_position & 1;

        node = bit ? node->right : node->left;

        if ( node )
        {
            if ( !node->left && !node->right )
            {
                if ( node->character == impl_t::EOB )
                {
                    break;
                }

                output[ output_index++ ] = node->character;

                node = root;
            }
        }
        else
        {
            impl_t::huffman_release_tree( root );

            return e_status::status_error;
        }
    }

    impl_t::huffman_release_tree( root );

    return e_status::status_ok;
}
