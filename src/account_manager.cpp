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

#include <algorithm>

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

		m_keys_cache.clear();
		m_ek2pk_cache.clear();
	}

	std::array<char, 32> account_manager::key_exchange(dht::public_key const& pk)
	{
		std::array<char, 32> ret;
		sha256_hash pub_key(pk.bytes.data());
		sha256_hash ek;

		bool exist = get_exchange_key(pub_key, ek);
		if (exist)
		{
			std::copy(ek.data(), ek.data() + 32, ret.begin());
		}
		else
		{
			ret = dht::ed25519_key_exchange(pk, this->m_priv_key);
			ek.assign(ret.data());
			put_exchange_key(pub_key, ek);
		}

		return ret;
	}

	bool account_manager::get_exchange_key(sha256_hash const& pk, sha256_hash& ek)
	{
		auto i = m_keys_cache.find(pk);
		if (i == m_keys_cache.end()) return false;

		auto j = m_ek2pk_cache.find(i->second);
		TORRENT_ASSERT(j != m_ek2pk_cache.end());
		m_ek2pk_cache.erase(j);

		i->second.last_seen = aux::time_now();
		ek = i->second.key;

		m_ek2pk_cache.insert(std::make_pair(i->second, pk));

		return true;
	}

	void account_manager::put_exchange_key(sha256_hash const& pk, sha256_hash const& ek)
	{
		auto i = m_keys_cache.find(pk);
		if (i != m_keys_cache.end())
		{
			auto j = m_ek2pk_cache.find(i->second);
			TORRENT_ASSERT(j != m_ek2pk_cache.end());
			m_ek2pk_cache.erase(j);

			i->second.last_seen = aux::time_now();
			m_ek2pk_cache.insert(std::make_pair(i->second, pk));

			return;
		}

		if (m_keys_cache.size() >= key_cache_max_size)
		{
				// remove the oldest one
				auto min_it = m_ek2pk_cache.begin();
				auto min = m_keys_cache.find(min_it->second);

				TORRENT_ASSERT(min != m_keys_cache.end());
				m_keys_cache.erase(min);
				m_ek2pk_cache.erase(min_it);
		}

		exchange_key to_add;
		to_add.key = ek;
		to_add.last_seen = aux::time_now();
		m_ek2pk_cache.insert(std::make_pair(to_add, pk));
		m_keys_cache.insert(std::make_pair(pk, std::move(to_add)));
	}
}
}
