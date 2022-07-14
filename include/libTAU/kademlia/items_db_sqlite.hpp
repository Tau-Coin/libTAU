/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_ITEMS_DATABASE_SQLITE_HPP
#define LIBTAU_ITEMS_DATABASE_SQLITE_HPP

#include <libTAU/kademlia/dht_observer.hpp>
#include <libTAU/kademlia/dht_storage.hpp>

namespace libTAU {
namespace dht {

	struct TORRENT_EXPORT items_db_sqlite : public dht_storage_interface
	{
		explicit items_db_sqlite(settings_interface const& settings
			, dht_observer* observer);

		~items_db_sqlite() override = default;

		items_db_sqlite(items_db_sqlite const&) = delete;
		items_db_sqlite& operator=(items_db_sqlite const&) = delete;

		void update_node_ids(std::vector<node_id> const& ids) override {}

		void set_backend(std::shared_ptr<dht_storage_interface> backend) override {}

		bool get_immutable_item(sha256_hash const& target
			, entry& item) const override {}

		void put_immutable_item(sha256_hash const& target
			, span<char const> buf
			, address const& addr) override {};

		virtual bool get_mutable_item_timestamp(sha256_hash const& target
			, timestamp& ts) const override;

		virtual bool get_mutable_item(sha256_hash const& target
			, timestamp ts, bool force_fill
			, entry& item) const override;

		// get item target by the prefix
		virtual bool get_mutable_item_target(sha256_hash const& prefix
			, sha256_hash& target) const override;

		virtual void put_mutable_item(sha256_hash const& target
			, span<char const> buf
			, signature const& sig
			, timestamp ts
			, public_key const& pk
			, span<char const> salt
			, address const& addr) override;

		virtual void remove_mutable_item(sha256_hash const& target) override;

		void relay_referred(node_id const& peer
			, node_entry const& ne) override {};

		void find_relays(node_id const& peer
			, std::vector<node_entry>& l
			, int count, udp protocol) override {};

		void put_relay_entry(sha256_hash const& sender
			, sha256_hash const& receiver
			, span<char const> payload
			, span<char const> aux_nodes
			, udp protocol
			, relay_hmac const& hmac) override {};

		bool get_relay_entry(sha256_hash const& key
			, entry& re) const override { return false; };

		bool get_random_relay_entry(sha256_hash const& receiver
			, sha256_hash& key) const override { return false; };

		void remove_relay_entry(sha256_hash const& key) override {};

		virtual void tick() override;

		dht_storage_counters counters() const override { return dht_storage_counters{}; };

	private:

		void init();

		settings_interface const& m_settings;
		dht_observer* m_observer;

	};
} // namespace dht
} // namespace libTAU

#endif // LIBTAU_ITEMS_DATABASE_SQLITE_HPP
