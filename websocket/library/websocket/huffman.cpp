#include <websocket/core/huffman.hpp>

#include <queue>
#include <stack>

struct c_huffman::impl_t
{
    struct Node
    {
        unsigned char character;
        size_t frequency;
        Node *left, *right;
        Node( unsigned char d, size_t f ) :
            character( d ), frequency( f ), left( nullptr ), right( nullptr ) {}
    };

    struct Compare
    {
        bool
        operator()( Node *a, Node *b )
        {
            return a->frequency > b->frequency;
        }
    };

    static void
    huffman_build_frequency_table( unsigned char *input, size_t length, std::map< unsigned char, size_t > &frequency_table );

    static Node *
    huffman_build_tree( const std::map< unsigned char, size_t > &freqTable );

    static void
    huffman_build_code_table( Node *root, std::map< unsigned char, std::vector< bool > > &huffman_bits );

    static void
    huffman_release_tree( Node *node );
};

void
c_huffman::impl_t::huffman_build_frequency_table( unsigned char *input, size_t length, std::map< unsigned char, size_t > &frequency_table )
{
    for ( size_t i = 0; i < length; ++i )
    {
        unsigned char c = input[ i ];

        auto it = frequency_table.find( c );
        if ( it == frequency_table.end() )
        {
            frequency_table.emplace( std::make_pair( c, 1 ) );
            continue;
        }

        it->second++;
    }
}

c_huffman::impl_t::Node *
c_huffman::impl_t::huffman_build_tree( const std::map< unsigned char, size_t > &freqTable )
{
    // Step 1: Create a priority queue to store nodes based on frequency
    std::priority_queue< Node *, std::vector< Node * >, Compare > minHeap;

    // Step 2: Create leaf nodes for each character and add them to the priority queue
    for ( const auto &entry : freqTable )
    {
        minHeap.push( new Node( entry.first, entry.second ) );
    }

    // Step 3: Build the Huffman Tree
    while ( minHeap.size() > 1 )
    {
        // Remove the two nodes with the lowest frequency
        Node *left = minHeap.top();
        minHeap.pop();

        Node *right = minHeap.top();
        minHeap.pop();

        // Create a new internal node with frequency equal to the sum of the two nodes' frequencies
        Node *parent = new Node( '\0', left->frequency + right->frequency ); // '\0' as placeholder for internal nodes
        parent->left = left;
        parent->right = right;

        // Add the new node to the priority queue
        minHeap.push( parent );
    }

    // Step 4: The remaining node is the root of the Huffman Tree
    return minHeap.empty() ? nullptr : minHeap.top();
}

void
c_huffman::impl_t::huffman_build_code_table( Node *root, std::map< unsigned char, std::vector< bool > > &huffman_bits )
{
    if ( !root )
    {
        return;
    }

    std::stack< std::pair< Node *, std::vector< bool > > > stack;
    stack.push( { root, {} } );

    while ( !stack.empty() )
    {
        Node *node = stack.top().first;
        std::vector< bool > codes = stack.top().second;
        stack.pop();

        // If the node is a leaf, store the accumulated code
        if ( !node->left && !node->right )
        {
            huffman_bits[ node->character ] = codes;
        }

        // Push right and left children to the stack with a separate copy of the codes vector
        if ( node->right )
        {
            auto right_codes = codes; // Copy of codes for right child
            right_codes.push_back( true );
            stack.push( { node->right, right_codes } );
        }
        if ( node->left )
        {
            auto left_codes = codes; // Copy of codes for left child
            left_codes.push_back( false );
            stack.push( { node->left, left_codes } );
        }
    }
}

void
c_huffman::impl_t::huffman_release_tree( Node *node )
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
c_huffman::encode( unsigned char *input, size_t input_length, unsigned char *&output, size_t &output_length, size_t &output_bits, std::map< unsigned char, size_t > &frequency_table )
{
    c_huffman::impl_t::huffman_build_frequency_table( input, input_length, frequency_table );

    c_huffman::impl_t::Node *root = c_huffman::impl_t::huffman_build_tree( frequency_table );
    if ( !root )
    {
        return e_status::status_error;
    }

    std::map< unsigned char, std::vector< bool > > huffman_bits;
    c_huffman::impl_t::huffman_build_code_table( root, huffman_bits );

    for ( size_t i = 0; i < input_length; ++i )
    {
        unsigned char byte = input[ i ];

        auto it = huffman_bits.find( byte );
        if ( it == huffman_bits.end() )
        {
            c_huffman::impl_t::huffman_release_tree( root );
            return e_status::status_error;
        }

        std::vector< bool > bits = huffman_bits.at( byte );

        output_bits += bits.size();
    }

    output_length = ( output_bits + 7 ) / 8;

    output = new unsigned char[ output_length + 1 ];
    std::memset( output, 0, output_length );
    output[ output_length ] = 0;

    for ( size_t i = 0, bit_index = 0; i < input_length; ++i )
    {
        unsigned char byte = input[ i ];

        auto it = huffman_bits.find( byte );
        if ( it == huffman_bits.end() )
        {
            c_huffman::impl_t::huffman_release_tree( root );
            return e_status::status_error;
        }

        std::vector< bool > bits = huffman_bits.at( byte );

        for ( bool bit : bits )
        {
            size_t byte_index = bit_index / 8;
            size_t bit_position = 7 - ( bit_index % 8 );

            if ( bit )
            {
                output[ byte_index ] |= ( 1 << bit_position );
            }

            bit_index++;
        }
    }

    c_huffman::impl_t::huffman_release_tree( root );

    return e_status::status_ok;
}

c_huffman::e_status
c_huffman::decode( unsigned char *input, size_t input_length, size_t input_bits, unsigned char *&output, size_t &output_length, std::map< unsigned char, size_t > frequency_table )
{
    c_huffman::impl_t::Node *root = c_huffman::impl_t::huffman_build_tree( frequency_table );
    if ( !root )
    {
        return e_status::status_error;
    }

    c_huffman::impl_t::Node *node = root;

    for ( size_t bits = 0; bits < input_bits; ++bits )
    {
        size_t byte_index = bits / 8;
        size_t bit_position = 7 - ( bits % 8 );

        bool bit = ( input[ byte_index ] >> bit_position ) & 1;

        node = bit ? node->right : node->left;

        if ( !node )
        {
            c_huffman::impl_t::huffman_release_tree( root );
            return e_status::status_error;
        }

        if ( !node->left && !node->right )
        {
            output_length++;
            node = root;
        }
    }

    output = new unsigned char[ output_length + 1 ];
    std::memset( output, 0, output_length );
    output[ output_length ] = 0;

    for ( size_t bits = 0, i = 0; bits < input_bits; ++bits )
    {
        size_t byte_index = bits / 8;
        size_t bit_position = 7 - ( bits % 8 );

        bool bit = ( input[ byte_index ] >> bit_position ) & 1;

        node = bit ? node->right : node->left;

        if ( !node )
        {
            c_huffman::impl_t::huffman_release_tree( root );
            return e_status::status_error;
        }

        if ( !node->left && !node->right )
        {
            output[ i++ ] = node->character;
            node = root;
        }
    }

    c_huffman::impl_t::huffman_release_tree( root );

    return e_status::status_ok;
}
