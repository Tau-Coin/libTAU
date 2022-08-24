/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <libTAU/kademlia/bs_nodes_db_sqlite.hpp>

#include <libTAU/aux_/socket_io.hpp>
#include <libTAU/aux_/time.hpp>
#include <libTAU/config.hpp>
#include <libTAU/aux_/numeric_cast.hpp>
#include <libTAU/aux_/ip_helpers.hpp> // for is_v4
#include <libTAU/bdecode.hpp>
#include "libTAU/hex.hpp" // to_hex

namespace libTAU { namespace dht {

bs_nodes_db_sqlite::bs_nodes_db_sqlite(settings_interface const& settings
	, dht_observer* observer)
	: m_settings(settings)
	, m_observer(observer)
{
	init();
	prepare_statements();
}

void bs_nodes_db_sqlite::init()
{
	// init data members
	m_last_refresh = min_time();

	sqlite3* db = m_observer->get_items_database();
	if (db != NULL)
	{
		char *zErrMsg = nullptr;

		// first of all, create table if not exist.
		int ok = sqlite3_exec(db, create_bs_nodes_table.c_str(), nullptr, nullptr, &zErrMsg);
		if (ok != SQLITE_OK)
		{
			sqlite3_free(zErrMsg);
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
			{
				m_observer->log(dht_logger::bs_nodes_db, "create table error: %d, %s"
					, ok, create_bs_nodes_table.c_str());
			}
#endif
			return;
		}

		// create index
		ok = sqlite3_exec(db, create_bs_nodes_ts_index.c_str(), nullptr, nullptr, &zErrMsg);
		if (ok != SQLITE_OK)
		{
			sqlite3_free(zErrMsg);
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
			{
				m_observer->log(dht_logger::bs_nodes_db, "create index error: %d, %s"
					, ok, create_bs_nodes_ts_index.c_str());
			}
#endif

			return;
		}

#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_INFO))
		{
			m_observer->log(dht_logger::bs_nodes_db, "create table and index successfully");
		}
#endif
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::bs_nodes_db, "init: sqlite databse is invalid");
		}
#endif
	}
}

void bs_nodes_db_sqlite::prepare_statements()
{
	sqlite3* db = m_observer->get_items_database();

	if (db != NULL)
	{
		std::string error = "prepare statements ";

		int ok = sqlite3_prepare_v2(db, insert_or_replace_nodes.c_str(), -1
			, &m_insert_or_replace_nodes_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(insert_or_replace_nodes);
			sql_error(ok, error.c_str());

			return;
		}

		ok = sqlite3_prepare_v2(db, select_nodes.c_str(), -1
			, &m_select_nodes_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(select_nodes);
			sql_error(ok, error.c_str());

			return;
		}

		ok = sqlite3_prepare_v2(db, nodes_count.c_str(), -1
			, &m_nodes_count_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(nodes_count);
			sql_error(ok, error.c_str());

			return;
		}

		ok = sqlite3_prepare_v2(db, delete_nodes.c_str(), -1
			, &m_delete_nodes_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(delete_nodes);
			sql_error(ok, error.c_str());

			return;
		}

		ok = sqlite3_prepare_v2(db, select_bs_nodes_ts_threshold.c_str(), -1
			, &m_select_ts_threshold_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(select_bs_nodes_ts_threshold);
			sql_error(ok, error.c_str());

			return;
		}
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::bs_nodes_db
				, "prepare statements: sqlite databse is invalid");
		}
#endif
	}
}

bool bs_nodes_db_sqlite::put(std::vector<bs_node_entry> const& nodes)
{
	if (nodes.empty()) return true;

	sqlite3* db = m_observer->get_items_database();

	if (db != NULL && m_insert_or_replace_nodes_stmt != NULL)
	{
		char *zErrMsg = nullptr;

		time_point const start = aux::time_now();

		int ok = sqlite3_exec(db, "BEGIN TRANSACTION", nullptr, nullptr, &zErrMsg);
		if (ok != SQLITE_OK)
		{
			sqlite3_free(zErrMsg);
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
			{
				m_observer->log(dht_logger::bs_nodes_db, "BEGIN TRANSACTION error: %d", ok);
			}
#endif
			return false;
		}

		for (auto& n : nodes)
		{
			std::string ep_str;
			std::back_insert_iterator<std::string> out(ep_str);
			aux::write_endpoint(n.m_ep, out);

			sqlite3_reset(m_insert_or_replace_nodes_stmt);

			sqlite3_bind_text(m_insert_or_replace_nodes_stmt, 1
				, n.m_nid.data(), 32, nullptr);
			sqlite3_bind_int(m_insert_or_replace_nodes_stmt, 2
				, aux::numeric_cast<int>(n.m_ts.value));
			sqlite3_bind_text(m_insert_or_replace_nodes_stmt, 3
				, ep_str.c_str(), ep_str.size(), nullptr);
			sqlite3_bind_int(m_insert_or_replace_nodes_stmt, 4
				, aux::is_v4(n.m_ep) ? 1 : 0);

			ok = sqlite3_step(m_insert_or_replace_nodes_stmt);
			if (ok != SQLITE_DONE)
			{
				sql_error(ok, "put bs nodes");
				return false;
			}
        }

		ok = sqlite3_exec(db, "COMMIT TRANSACTION", nullptr, nullptr, &zErrMsg);
		if (ok != SQLITE_OK)
		{
			sqlite3_free(zErrMsg);
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
			{
				m_observer->log(dht_logger::bs_nodes_db, "COMMIT TRANSACTION error: %d", ok);
			}
#endif
			return false;
		}

		int const cost = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start));
		sql_time_cost(cost, "put bs nodes:");

		return true;
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::bs_nodes_db, "put bs nodes: sqlite databse is invalid");
		}
#endif

		return false;
	}
}

bool bs_nodes_db_sqlite::get(std::vector<bs_node_entry>& nodes
	, int offset, int count) const
{
	sqlite3* db = m_observer->get_items_database();

	if (db != NULL && m_select_nodes_stmt != NULL)
	{
		sqlite3_reset(m_select_nodes_stmt);

		sqlite3_bind_int(m_select_nodes_stmt, 1, offset);
		sqlite3_bind_int(m_select_nodes_stmt, 2, count);

		time_point const start = aux::time_now();

		while (sqlite3_step(m_select_nodes_stmt) == SQLITE_ROW)
		{
			const unsigned char* nid_ptr = static_cast<const unsigned char*>(
				sqlite3_column_text(m_select_nodes_stmt, 0));
			auto nid_len = static_cast<std::size_t>(
				sqlite3_column_bytes(m_select_nodes_stmt, 0));
			std::string nid_str(nid_ptr, nid_ptr + nid_len);
			node_id nid(nid_str);

			std::int64_t ts_value = aux::numeric_cast<std::int64_t>(
				sqlite3_column_int(m_select_nodes_stmt, 1));

            const unsigned char* ep_ptr = static_cast<const unsigned char*>(
                sqlite3_column_text(m_select_nodes_stmt, 2));
            auto ep_len = static_cast<std::size_t>(
                sqlite3_column_bytes(m_select_nodes_stmt, 2));
            std::string ep_str(ep_ptr, ep_ptr + ep_len);
            udp::endpoint ep;

			if (ep_len == 6)
			{
				ep = aux::read_v4_endpoint<udp::endpoint>(ep_str.c_str());
			} else if (ep_len == 18)
			{
				ep = aux::read_v6_endpoint<udp::endpoint>(ep_str.c_str());
			}

			nodes.push_back(bs_node_entry(nid, ep, timestamp(ts_value)));
		}

		int const cost = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start));
		sql_time_cost(cost, "get bs nodes");

		return true;
    }
    else
    {
#ifndef TORRENT_DISABLE_LOGGING
        if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
        {
            m_observer->log(dht_logger::bs_nodes_db, "get bs nodes: sqlite databse is invalid");
        }
#endif

        return false;
    }
}

std::size_t bs_nodes_db_sqlite::size()
{
	sqlite3* db = m_observer->get_items_database();

	if (db != NULL && m_nodes_count_stmt != NULL)
	{
		int count = 0;

		sqlite3_reset(m_nodes_count_stmt);

		time_point const start = aux::time_now();
		int ok = sqlite3_step(m_nodes_count_stmt);
		int const cost = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start));
		if (ok == SQLITE_ROW)
		{
			sql_time_cost(cost, "count:");

			count = sqlite3_column_int(m_nodes_count_stmt, 0);
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_INFO))
			{
				m_observer->log(dht_logger::bs_nodes_db, "nodes count:%d", count);
			}
#endif

			// move to the end
			sqlite3_step(m_nodes_count_stmt);

			m_size = std::size_t(count);

			return m_size;
		}
		else
		{
			sql_error(ok, nodes_count.c_str());
			return m_size;
		}
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::bs_nodes_db, "size: sqlite databse is invalid");
		}
#endif

		return m_size;
	}
}

std::size_t bs_nodes_db_sqlite::tick()
{
	time_point const now = aux::time_now();
	int refresh_period = m_settings.get_int(settings_pack::dht_bs_nodes_db_refresh_time);
	if (m_last_refresh + seconds(refresh_period) > now) return m_size;
	m_last_refresh = now;

	int max = m_settings.get_int(settings_pack::dht_bs_nodes_db_max_count);
	int count = 0;

	sqlite3* db = m_observer->get_items_database();

	if (db != NULL && m_nodes_count_stmt != NULL
		&& m_delete_nodes_stmt != NULL && m_select_ts_threshold_stmt != NULL)
	{
		sqlite3_reset(m_nodes_count_stmt);

		time_point const start = aux::time_now();
		int ok = sqlite3_step(m_nodes_count_stmt);
		int const cost = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start));
		if (ok == SQLITE_ROW)
		{
			sql_time_cost(cost, "count:");

            count = sqlite3_column_int(m_nodes_count_stmt, 0);
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_INFO))
			{
				m_observer->log(dht_logger::bs_nodes_db, "nodes count:%d, max:%d"
					, count, max);
			}
#endif

			// move to the end
			sqlite3_step(m_nodes_count_stmt);

			m_size = static_cast<std::size_t>(count);
        }
		else
		{
			sql_error(ok, nodes_count.c_str());
			return m_size;
		}

		if (count > max)
		{
			int timestamp = 0;

			sqlite3_reset(m_select_ts_threshold_stmt);
			sqlite3_bind_int(m_select_ts_threshold_stmt, 1, count - max - 1);

			time_point const start1 = aux::time_now();
			ok = sqlite3_step(m_select_ts_threshold_stmt);
			int const cost1 = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start1));
			if (ok == SQLITE_ROW)
			{
				sql_time_cost(cost1, "timestamp threshold:");
				timestamp = sqlite3_column_int(m_select_ts_threshold_stmt, 0);

#ifndef TORRENT_DISABLE_LOGGING
				if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_DEBUG))
				{
					m_observer->log(dht_logger::bs_nodes_db, "timestamp threshold:%d"
						, timestamp);
				}
#endif

				// move to the end
				sqlite3_step(m_select_ts_threshold_stmt);
			}
			else
			{
				sql_error(ok, select_bs_nodes_ts_threshold.c_str());
				return m_size;
			}

			sqlite3_reset(m_delete_nodes_stmt);
			sqlite3_bind_int(m_delete_nodes_stmt, 1, timestamp);

			time_point const start2 = aux::time_now();
			ok = sqlite3_step(m_delete_nodes_stmt);
			int const cost2 = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start2));
			if (ok == SQLITE_DONE)
			{
				this->sql_time_cost(cost2, "delete:");

#ifndef TORRENT_DISABLE_LOGGING
				if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_INFO))
				{
					m_observer->log(dht_logger::bs_nodes_db, "delete %d items successfully"
						, count - max);
				}
#endif

				m_size = static_cast<std::size_t>(max);
				return m_size;
			}
			else
			{
				sql_error(ok, delete_nodes.c_str());
				return m_size;
			}
		}

		return m_size;
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::bs_nodes_db, "tick: sqlite databse is invalid");
		}
#endif

		return m_size;
	}
}

void bs_nodes_db_sqlite::close()
{
	if (m_insert_or_replace_nodes_stmt != NULL) sqlite3_finalize(m_insert_or_replace_nodes_stmt);
	if (m_select_nodes_stmt != NULL) sqlite3_finalize(m_select_nodes_stmt);
	if (m_nodes_count_stmt != NULL) sqlite3_finalize(m_nodes_count_stmt);
	if (m_delete_nodes_stmt != NULL) sqlite3_finalize(m_delete_nodes_stmt);
	if (m_select_ts_threshold_stmt != NULL) sqlite3_finalize(m_select_ts_threshold_stmt);
}

void bs_nodes_db_sqlite::sql_error(int err_code, const char* err_str) const
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
	{
		m_observer->log(dht_logger::bs_nodes_db, "sql error: %d: %s", err_code, err_str);
	}
#endif
}

void bs_nodes_db_sqlite::sql_log(int code, const char* msg) const
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_DEBUG))
	{
		m_observer->log(dht_logger::bs_nodes_db, "sql log: %d: %s", code, msg);
	}
#endif
}

void bs_nodes_db_sqlite::sql_time_cost(int const microseconds, const char* msg) const
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer->should_log(dht_logger::bs_nodes_db, aux::LOG_DEBUG))
	{
		m_observer->log(dht_logger::bs_nodes_db, "sql %s time cost %dus", msg, microseconds);
	}
#endif
}

} } // namespace libTAU::dht
