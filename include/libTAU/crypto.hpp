/*

Copyright (c) 2021, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_CRYPTO_HPP_INCLUDED
#define TORRENT_CRYPTO_HPP_INCLUDED

#include "libTAU/config.hpp"
#include "libTAU/span.hpp"

#include <string>

namespace libTAU {

namespace aux {

	// AES encrypiton.
	// Here use std::string type compatible with OPENSSL AES suit.
	TORRENT_EXPORT bool aes_encrypt(const std::string& in
		, std::string& out
		, const std::string& key
		, std::string& err_str);

	// AES decrypiton.
	// Here use std::string type compatible with OPENSSL AES suit.
	TORRENT_EXPORT bool aes_decrypt(const std::string& in
		, std::string& out
		, const std::string& key
		, std::string& err_str);

	} // namespace aux
} // namespace libTAU

#endif // TORRENT_CRYPTO_HPP_INCLUDED
