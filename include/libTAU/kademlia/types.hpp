/*

Copyright (c) 2016-2017, 2019-2020, Arvid Norberg
Copyright (c) 2016, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTORRENT_TYPES_HPP
#define LIBTORRENT_TYPES_HPP

#include <cstdint>
#include <algorithm>
#include <array>

namespace libTAU {
namespace dht {

	struct public_key
	{
		public_key() = default;
		explicit public_key(char const* b)
		{ std::copy(b, b + len, bytes.begin()); }
		bool operator==(public_key const& rhs) const
		{ return bytes == rhs.bytes; }

		bool operator!=(const public_key &rhs) const {
			return !(rhs == *this);
		}

		bool operator<(const public_key &rhs) const {
            return bytes < rhs.bytes;
        }

        bool operator>(const public_key &rhs) const {
            return rhs < *this;
        }

        bool operator<=(const public_key &rhs) const {
            return !(rhs < *this);
        }

        bool operator>=(const public_key &rhs) const {
            return !(*this < rhs);
        }

		bool is_all_zeros() const {
			return std::all_of(bytes.begin(), bytes.end()
				, [](char v) { return v == 0; });
		}

        static constexpr int len = 32;
		std::array<char, len> bytes{};
	};

	struct secret_key
	{
		secret_key() = default;
		explicit secret_key(char const* b)
		{ std::copy(b, b + len, bytes.begin()); }
		bool operator==(secret_key const& rhs) const
		{ return bytes == rhs.bytes; }
		static constexpr int len = 64;
		std::array<char, len> bytes;
	};

	struct signature
	{
		signature() = default;
		explicit signature(char const* b)
		{ std::copy(b, b + len, bytes.begin()); }
		bool operator==(signature const& rhs) const
		{ return bytes == rhs.bytes; }
		static constexpr int len = 64;
		std::array<char, len> bytes;
	};

	struct timestamp
	{
		timestamp() : value(0) {}
		explicit timestamp(std::int64_t v) : value(v) {}
		timestamp(timestamp const& sqn) = default;
		bool operator<(timestamp rhs) const
		{ return value < rhs.value; }
		bool operator>(timestamp rhs) const
		{ return value > rhs.value; }
		timestamp& operator=(timestamp rhs) &
		{ value = rhs.value; return *this; }
		bool operator<=(timestamp rhs) const
		{ return value <= rhs.value; }
		bool operator==(timestamp const& rhs) const
		{ return value == rhs.value; }

		std::int64_t value;
	};

} // namespace dht
} // namespace libTAU

#endif // LIBTORRENT_TYPES_HPP
