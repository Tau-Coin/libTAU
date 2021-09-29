/*

Copyright (c) 2021, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/config.hpp"
#include "libTAU/account_manager.hpp"
#include "libTAU/kademlia/ed25519.hpp"
#include "libTAU/hex.hpp" // for hex
#include <libTAU/span.hpp>

namespace libTAU {
namespace aux {

	account_manager::account_manager(span<char const> account_seed)
	{
		update_key(account_seed);
	}

	account_manager::~account_manager() = default;

	// update account seed
	// Here account_manager is refered in one thread environment,
	// so mutex lock isn't used.
	void account_manager::update_key(span<char const> account_seed)
	{
		libTAU::aux::from_hex(account_seed, m_seed.data());
		std::tie(m_pub_key, m_priv_key) = dht::ed25519_create_keypair(m_seed);
	}

	std::array<char, 32> account_manager::key_exchange(dht::public_key const& pk)
	{
		return dht::ed25519_key_exchange(pk, this->m_priv_key);
	}
}
}
