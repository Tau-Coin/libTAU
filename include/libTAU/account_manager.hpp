/*

Copyright (c) 2021, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_ACCOUNT_MANAGER_HPP_INCLUDED
#define TORRENT_ACCOUNT_MANAGER_HPP_INCLUDED

#include "libTAU/config.hpp"
#include "libTAU/span.hpp"
#include "libTAU/kademlia/types.hpp"

#include <array>
#include <memory>

namespace libTAU {
namespace aux {

	// account_manager stores libTAU private key and public key.
	struct TORRENT_EXPORT account_manager final
		: std::enable_shared_from_this<account_manager>
	{
		explicit account_manager(span<const char> account_seed);

		// ensure account_manager is a singleton.
		account_manager(account_manager const&) = delete;
		account_manager& operator=(account_manager const&) = delete;

		~account_manager();

		// update key seed.
		void update_key(span<const char> account_seed);

		// get libTAU public key
		dht::public_key pub_key() const { return m_pub_key; };

		// exchange key with libTAU private key.
		std::array<char, 32> key_exchange(dht::public_key const& pk);

	private:

		// account seed
		std::array<char, 32> m_seed;

		// public key
		dht::public_key m_pub_key;

		// private key
		dht::secret_key m_priv_key;
	};
}
}

#endif
