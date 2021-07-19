/*

Copyright (c) 2004, 2006, 2010, 2015, 2017-2021, Arvid Norberg
Copyright (c) 2016, Jan Berkel
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_VERSION_HPP_INCLUDED
#define TORRENT_VERSION_HPP_INCLUDED

#include "libTAU/aux_/export.hpp"
#include <cstdint>

#define LIBTAU_VERSION_MAJOR 0
#define LIBTAU_VERSION_MINOR 0
#define LIBTAU_VERSION_TINY 0

// the format of this version is: MMmmtt
// M = Major version, m = minor version, t = tiny version
#define LIBTAU_VERSION_NUM ((LIBTAU_VERSION_MAJOR * 10000) + (LIBTAU_VERSION_MINOR * 100) + LIBTAU_VERSION_TINY)

#define LIBTAU_VERSION "0.0.0"

namespace libTAU {

	// the major, minor and tiny versions of libTAU
	constexpr int version_major = 0;
	constexpr int version_minor = 0;
	constexpr int version_tiny = 0;

	// the libTAU version in string form
	constexpr char const* version_str = "0.0.0";

	// returns the libTAU version as string form in this format:
	// "<major>.<minor>.<tiny>.<tag>"
	TORRENT_EXPORT char const* version();

}

namespace lt = libTAU;

#endif
