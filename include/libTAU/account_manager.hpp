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
#include <libTAU/sha1_hash.hpp>
#include <libTAU/aux_/time.hpp>

#include <array>
#include <memory>
#include <map>

namespace libTAU {
namespace aux {

	static constexpr int key_cache_max_size = 10000;

	struct exchange_key {

		sha256_hash key;

		time_point last_seen;

		bool operator<(exchange_key const& ek) const
		{
			return last_seen < ek.last_seen;
		}
    };

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

		// get libTAU private key
		dht::secret_key priv_key() const { return m_priv_key; };

		// exchange key with libTAU private key.
		std::array<char, 32> key_exchange(dht::public_key const& pk);

	private:

		// get exchange key from cache
		bool get_exchange_key(sha256_hash const& pk, sha256_hash& ek);

		// put exchange key into cache
		void put_exchange_key(sha256_hash const& pk, sha256_hash const& ek);

		// account seed
		std::array<char, 32> m_seed;

		// public key
		dht::public_key m_pub_key;

		// private key
		dht::secret_key m_priv_key;

		// exchange keys cache
		std::map<sha256_hash, exchange_key> m_keys_cache;

		// exchange key to public key
		std::map<exchange_key, sha256_hash> m_ek2pk_cache;
	};
}
}

#endif
