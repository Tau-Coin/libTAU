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

#include "libTAU/time.hpp"
#include "libTAU/aux_/time.hpp" // for time_now

namespace libTAU {
namespace dht {

	static const std::string create_items_table =
		"CREATE TABLE IF NOT EXISTS mutable_items ("
			 "target VARCHAR(32) NOT NULL PRIMARY KEY,"
			 "ts INT,"
			 "item VARCHAR(2000) NOT NULL);";

	static const std::string create_ts_index =
		"CREATE INDEX IF NOT EXISTS index_ts ON mutable_items (ts);";

	static const std::string select_ts_by_target =
		"SELECT ts FROM mutable_items WHERE target=?";

	static const std::string select_item_by_target =
		"SELECT * FROM mutable_items WHERE target=?";

	static const std::string insert_or_replace_items =
		"INSERT OR REPLACE INTO mutable_items (target, ts, item) VALUES (?, ?, ?);";

	static const std::string items_count =
		"SELECT COUNT(*) FROM mutable_items;";

	static const std::string delete_items =
		/*
		"DELETE FROM mutable_items "
			 "WHERE target IN "
			 "(SELECT target FROM mutable_items ORDER BY ts ASC LIMIT 0, ?);";
		 */
		/*
		"DELETE FROM mutable_items "
			 "WHERE ts <= (SELECT ts FROM mutable_items LIMIT ?, 1);";
		 */

		"DELETE FROM mutable_items WHERE ts <= ?;";

	static const std::string select_ts_threshold =
		"SELECT ts FROM mutable_items ORDER BY ts ASC LIMIT ?, 1;";

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

		virtual void close() override;

	private:

		void init();
		void prepare_statements();

		void sql_error(int err_code, const char* err_str) const;
		void sql_log(int code, const char* msg) const;
		void sql_time_cost(int const milliseconds, const char* msg) const;

		settings_interface const& m_settings;
		dht_observer* m_observer;

		// sql statements
		sqlite3_stmt* m_select_ts_by_target_stmt = NULL;
		sqlite3_stmt* m_select_item_by_target_stmt = NULL;
		sqlite3_stmt* m_insert_or_replace_items_stmt = NULL;
		sqlite3_stmt* m_items_count_stmt = NULL;
		sqlite3_stmt* m_delete_items_stmt = NULL;
		sqlite3_stmt* m_select_ts_threshold_stmt = NULL;

		// put item cache
		std::string m_mutable_item;

		time_point m_last_refresh;
	};
} // namespace dht
} // namespace libTAU

#endif // LIBTAU_ITEMS_DATABASE_SQLITE_HPP
