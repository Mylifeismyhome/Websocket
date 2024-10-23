#pragma once

#include <cstdint>

/** \cond */
class c_endian final
{
public:
    static unsigned short
    host_to_network_16( unsigned short value );

    static unsigned int
    host_to_network_32( unsigned int value );

    static unsigned long long
    host_to_network_64( unsigned long long value );

    static unsigned short
    network_to_host_16( unsigned short value );

    static unsigned int
    network_to_host_32( unsigned int value );

    static unsigned long long
    network_to_host_64( unsigned long long value );

private:
    static unsigned short
    swap_16( unsigned short value );

    static unsigned int
    swap_32( unsigned int value );

    static unsigned long long
    swap_64( unsigned long long value );
};
/** \endcond */
