/*

Copyright (c) 2022 TAU
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/aux_/generate_port.hpp"

namespace libTAU::aux {

std::uint16_t generate_port(const std::array<char, 32>& key)
{
    std::uint16_t port = 6881; //TODO: settings_pack
    if(key.size() < 32)
        return port;

    std::array<char, 32> key_c = key;

    unsigned char key_ex[8];
    for(int i = 0; i < 8; i++)
        key_ex[i] = *(reinterpret_cast<unsigned char *>(&key_c[i*4]));

    std::uint64_t *number = reinterpret_cast<std::uint64_t*> (key_ex);

    //TODO: settings_pack
    port = (*number)%64535 + 1024;  //1024 -> 65535 

    return port;
}

}
