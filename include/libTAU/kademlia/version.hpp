/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_DHT_VERSION_HPP
#define LIBTAU_DHT_VERSION_HPP

#include <cstring>
#include <string>

namespace libTAU {
namespace dht {

    constexpr int major = 0;
    constexpr int minor = 0;
    constexpr int tiny = 0;

	constexpr int version_length = 4;

	static char const ver[] = { 'T', major, minor, tiny };
	static std::string version(ver, ver + version_length);

	inline bool version_match(const std::string& ver)
	{
		return strncmp(version.c_str(), ver.c_str(), 2) == 0 ? true : false;
	}

} // namespace dht
} // namespace libTAU

#endif // LIBTAU_DHT_VERSION_HPP
