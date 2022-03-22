/*

Copyright (c) 2012
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_GENERATE_PORT_HPP_INCLUDED
#define TORRENT_GENERATE_PORT_HPP_INCLUDED

#include <array>
#include <cstdint>

#include "libTAU/aux_/export.hpp"

namespace libTAU { namespace aux {

TORRENT_EXPORT std::uint16_t generate_port(const std::array<char, 32>& key);

}}

#endif

