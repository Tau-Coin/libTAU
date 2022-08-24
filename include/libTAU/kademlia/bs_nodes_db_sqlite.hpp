/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BOOTSTRAP_NODES_DATABASE_SQLITE_HPP
#define LIBTAU_BOOTSTRAP_NODES_DATABASE_SQLITE_HPP

#include <libTAU/kademlia/dht_observer.hpp>
#include <libTAU/kademlia/bs_nodes_storage.hpp>

#include "libTAU/time.hpp"
#include "libTAU/aux_/time.hpp" // for time_now

namespace libTAU {
namespace dht {

	static const std::string create_bs_nodes_table =
		"CREATE TABLE IF NOT EXISTS bs_nodes ("
			 "nid VARCHAR(32) NOT NULL PRIMARY KEY,"
			 "ts INT,"
			 "endpoint VARCHAR(18) NOT NULL,"
			 "v4 INT);";

	static const std::string create_bs_nodes_ts_index =
		"CREATE INDEX IF NOT EXISTS index_ts ON bs_nodes (ts);";

	static const std::string insert_or_replace_nodes =
		"INSERT OR REPLACE INTO bs_nodes(nid, ts, endpoint, v4) VALUES (?, ?, ?, ?);";

	static const std::string select_nodes =
		"SELECT * FROM bs_nodes ORDER BY ts DESC LIMIT ?, ?;";

	static const std::string nodes_count =
		"SELECT COUNT(*) FROM bs_nodes;";

	/*
	static const std::string delete_nodes =
		"DELETE FROM bs_nodes "
			 "WHERE nid IN "
			 "(SELECT nid FROM bs_nodes ORDER BY ts ASC LIMIT 0, ?);";
	 */

	static const std::string delete_nodes =
		"DELETE FROM bs_nodes WHERE ts <= ?;";

	static const std::string select_bs_nodes_ts_threshold =
		"SELECT ts FROM bs_nodes ORDER BY ts ASC LIMIT ?, 1;";

	struct TORRENT_EXPORT bs_nodes_db_sqlite : public bs_nodes_storage_interface
	{
		explicit bs_nodes_db_sqlite(settings_interface const& settings
			, dht_observer* observer);

		~bs_nodes_db_sqlite() override = default;

		bs_nodes_db_sqlite(bs_nodes_db_sqlite const&) = delete;
		bs_nodes_db_sqlite& operator=(bs_nodes_db_sqlite const&) = delete;

		virtual bool put(std::vector<bs_node_entry> const& nodes) override;

		virtual bool get(std::vector<bs_node_entry>& nodes
			 , int offset, int count) const override;

		virtual std::size_t size() override;

		virtual std::size_t tick() override;

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
		sqlite3_stmt* m_insert_or_replace_nodes_stmt = NULL;
		sqlite3_stmt* m_select_nodes_stmt = NULL;
		sqlite3_stmt* m_nodes_count_stmt = NULL;
		sqlite3_stmt* m_delete_nodes_stmt = NULL;
		sqlite3_stmt* m_select_ts_threshold_stmt = NULL;

		time_point m_last_refresh;

		// the total count of sqlite db records
		std::size_t m_size = 0;
	};
} // namespace dht
} // namespace libTAU

#endif // LIBTAU_BOOTSTRAP_NODES_DATABASE_SQLITE_HPP
