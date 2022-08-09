/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <libTAU/kademlia/items_db_sqlite.hpp>

#include <libTAU/aux_/socket_io.hpp>
#include <libTAU/aux_/time.hpp>
#include <libTAU/config.hpp>
#include <libTAU/aux_/numeric_cast.hpp>
#include <libTAU/aux_/ip_helpers.hpp> // for is_v4
#include <libTAU/bdecode.hpp>
#include "libTAU/hex.hpp" // to_hex

namespace libTAU { namespace dht {

items_db_sqlite::items_db_sqlite(settings_interface const& settings
	, dht_observer* observer)
	: m_settings(settings)
	, m_observer(observer)
{
	init();
	prepare_statements();
}

void items_db_sqlite::init()
{
	// init data members
	m_mutable_item.reserve(2000);
	m_last_refresh = min_time();

	sqlite3* db = m_observer->get_items_database();
	if (db != NULL)
	{
		char *zErrMsg = nullptr;

		// first of all, create table if not exist.
		int ok = sqlite3_exec(db, create_items_table.c_str(), nullptr, nullptr, &zErrMsg);
		if (ok != SQLITE_OK)
		{
			sqlite3_free(zErrMsg);
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer->should_log(dht_logger::items_db, aux::LOG_ERR))
			{
				m_observer->log(dht_logger::items_db, "create table error: %d, %s"
					, ok, create_items_table.c_str());
			}
#endif
			return;
		}

		// create index
		ok = sqlite3_exec(db, create_ts_index.c_str(), nullptr, nullptr, &zErrMsg);
		if (ok != SQLITE_OK)
		{
			sqlite3_free(zErrMsg);
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer->should_log(dht_logger::items_db, aux::LOG_ERR))
			{
				m_observer->log(dht_logger::items_db, "create index error: %d, %s"
					, ok, create_ts_index.c_str());
			}
#endif

			return;
		}

#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::items_db, aux::LOG_INFO))
		{
			m_observer->log(dht_logger::items_db, "create table and index successfully");
		}
#endif
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::items_db, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::items_db, "init: sqlite databse is invalid");
		}
#endif
	}
}

void items_db_sqlite::prepare_statements()
{
	sqlite3* db = m_observer->get_items_database();

	if (db != NULL)
	{
		std::string error = "prepare statements ";

		int ok = sqlite3_prepare_v2(db, select_ts_by_target.c_str(), -1
			, &m_select_ts_by_target_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(select_ts_by_target);
			sql_error(ok, error.c_str());

			return;
		}

		ok = sqlite3_prepare_v2(db, select_item_by_target.c_str(), -1
			, &m_select_item_by_target_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(select_item_by_target);
			sql_error(ok, error.c_str());

			return;
		}

		ok = sqlite3_prepare_v2(db, insert_or_replace_items.c_str(), -1
			, &m_insert_or_replace_items_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(insert_or_replace_items);
			sql_error(ok, error.c_str());

			return;
		}

		ok = sqlite3_prepare_v2(db, items_count.c_str(), -1
			, &m_items_count_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(items_count);
			sql_error(ok, error.c_str());

			return;
		}

		ok = sqlite3_prepare_v2(db, delete_items.c_str(), -1
			, &m_delete_items_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(delete_items);
			sql_error(ok, error.c_str());

			return;
		}

		ok = sqlite3_prepare_v2(db, select_ts_threshold.c_str(), -1
			, &m_select_ts_threshold_stmt, nullptr);
		if (ok != SQLITE_OK)
		{
			error.append(select_ts_threshold);
			sql_error(ok, error.c_str());

			return;
		}
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::items_db, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::items_db, "prepare statements: sqlite databse is invalid");
		}
#endif
	}
}

bool items_db_sqlite::get_mutable_item_timestamp(sha256_hash const& target
	, timestamp& ts) const
{
	sqlite3* db = m_observer->get_items_database();

	if (db != NULL && m_select_ts_by_target_stmt != NULL)
	{
		sqlite3_reset(m_select_ts_by_target_stmt);

		sqlite3_bind_text(m_select_ts_by_target_stmt, 1
			, target.data(), 32, nullptr);

		time_point const start = aux::time_now();
		int ok = sqlite3_step(m_select_ts_by_target_stmt);
		int const cost = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start));
		if (ok == SQLITE_ROW)
		{
			sql_time_cost(cost, "select ts by target");

			std::int64_t ts_value = aux::numeric_cast<std::int64_t>(
				sqlite3_column_int(m_select_ts_by_target_stmt, 0));
			ts.value = ts_value;

			// move to the end
			sqlite3_step(m_select_ts_by_target_stmt);
			return true;
		}
		else
		{
			std::string log_msg("can't get timestamp by target:");
			log_msg.append(aux::to_hex(target));
			sql_log(ok, log_msg.c_str());

			return false;
        }
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::items_db, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::items_db, "get ts by target: sqlite databse is invalid");
		}
#endif

		return false;
	}
}

bool items_db_sqlite::get_mutable_item(sha256_hash const& target
	, timestamp ts, bool force_fill
	, entry& item) const
{
	sqlite3* db = m_observer->get_items_database();

	if (db != NULL && m_select_item_by_target_stmt != NULL)
	{
		sqlite3_reset(m_select_item_by_target_stmt);

		sqlite3_bind_text(m_select_item_by_target_stmt, 1
			, target.data(), 32, nullptr);

		time_point const start = aux::time_now();
		int ok = sqlite3_step(m_select_item_by_target_stmt);
		int const cost = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start));
		if (ok == SQLITE_ROW)
		{
			sql_time_cost(cost, "select item by target");

			std::int64_t ts_value = aux::numeric_cast<std::int64_t>(
				sqlite3_column_int(m_select_item_by_target_stmt, 1));
            item["ts"] = ts_value;

			const unsigned char* item_ptr = static_cast<const unsigned char*>(
				sqlite3_column_text(m_select_item_by_target_stmt, 2));
			auto length = static_cast<std::size_t>(
				sqlite3_column_bytes(m_select_item_by_target_stmt, 2));
			std::string item_str(item_ptr, item_ptr + length);

#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer->should_log(dht_logger::items_db, aux::LOG_DEBUG))
			{
				m_observer->log(dht_logger::items_db, "debug put size:%d, get size:%d, put==get? %s"
					, m_mutable_item.size(), length
					, item_str == m_mutable_item ? "true" : "false");

			}
#endif

			if (force_fill || (timestamp(0) <= ts && ts < timestamp(ts_value)))
			{
				error_code ec;
				item = bdecode(item_str, ec);
				// TODO: how to handle decoding error
				if (ec.value() != 0)
				{
					std::string err_msg("get bdecoding error:");
					err_msg.append(item_str);
					err_msg.append(" entry:");
					err_msg.append(item.to_string(true));
					sql_error(ec.value(), err_msg.c_str());

					// move to the end
					sqlite3_step(m_select_item_by_target_stmt);
					return false;
				}

				std::string get_log_msg("get item:");
				get_log_msg.append(item.to_string(true));
				sql_log(0, get_log_msg.c_str());
			}

			// move to the end
			sqlite3_step(m_select_item_by_target_stmt);
            return true;
        }
        else
        {
			std::string log_msg("can't get item by target:");
			log_msg.append(aux::to_hex(target));
			sql_log(ok, log_msg.c_str());

			return false;
        }
    }
    else
    {
#ifndef TORRENT_DISABLE_LOGGING
        if (m_observer->should_log(dht_logger::items_db, aux::LOG_ERR))
        {
            m_observer->log(dht_logger::items_db, "get mutable item: sqlite databse is invalid");
        }
#endif

        return false;
    }
}

bool items_db_sqlite::get_mutable_item_target(sha256_hash const& prefix
	, sha256_hash& target) const
{
	return false;
}

void items_db_sqlite::put_mutable_item(sha256_hash const& target
	, span<char const> buf
	, signature const& sig
	, timestamp ts
	, public_key const& pk
	, span<char const> salt
	, address const& addr)
{
	sqlite3* db = m_observer->get_items_database();

	if (db != NULL && m_insert_or_replace_items_stmt != NULL)
	{
		entry e;
		error_code ec;
		entry value = bdecode(buf.first(buf.size()), ec);
		// TODO: how to handle decoding error
		if (ec.value() != 0)
		{
			std::string err_msg("put item bdecoding error:");
			err_msg.append(buf.data(), buf.size());
			sql_error(ec.value(), err_msg.c_str());

			return;
		}

		e["k"] = pk.bytes;
		e["salt"] = salt;
		e["ts"] = ts.value;
		e["v"] = value;
		e["sig"] = sig.bytes;

		m_mutable_item.clear();
		bencode(std::back_inserter(m_mutable_item), e);

		sqlite3_reset(m_insert_or_replace_items_stmt);

		sqlite3_bind_text(m_insert_or_replace_items_stmt, 1
			, target.data(), 32, nullptr);
		sqlite3_bind_int(m_insert_or_replace_items_stmt, 2, aux::numeric_cast<int>(ts.value));
		sqlite3_bind_text(m_insert_or_replace_items_stmt, 3
			, m_mutable_item.data(), m_mutable_item.size(), SQLITE_STATIC);

		time_point const start = aux::time_now();
		int ok = sqlite3_step(m_insert_or_replace_items_stmt);
		int const cost = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start));
		if (ok == SQLITE_DONE)
		{
			sql_time_cost(cost, "put item");
			std::string log_msg("insert or update successfully:");
			log_msg.append(e.to_string(true));
			sql_log(ok, log_msg.c_str());
		}
		else
		{
			std::string err_msg("insert or update error:");
			err_msg.append(e.to_string(true));
			sql_error(ok, err_msg.c_str());
		}
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::items_db, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::items_db, "put mutable item: sqlite databse is invalid");
		}
#endif
	}
}

void items_db_sqlite::remove_mutable_item(sha256_hash const& target)
{
}

void items_db_sqlite::tick()
{
	time_point const now = aux::time_now();
	int refresh_period = m_settings.get_int(settings_pack::dht_items_db_refresh_time);
	if (m_last_refresh + seconds(refresh_period) > now) return;
	m_last_refresh = now;

	int max = m_settings.get_int(settings_pack::dht_items_db_max_count);
	int count = 0;

	sqlite3* db = m_observer->get_items_database();

	if (db != NULL && m_items_count_stmt != NULL
		&& m_delete_items_stmt != NULL && m_select_ts_threshold_stmt != NULL)
	{
		sqlite3_reset(m_items_count_stmt);

		time_point const start = aux::time_now();
		int ok = sqlite3_step(m_items_count_stmt);
		int const cost = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start));
		if (ok == SQLITE_ROW)
		{
			sql_time_cost(cost, "count:");

            count = sqlite3_column_int(m_items_count_stmt, 0);
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer->should_log(dht_logger::items_db, aux::LOG_INFO))
			{
				m_observer->log(dht_logger::items_db, "items count:%d, max:%d"
					, count, max);
			}
#endif

			// move to the end
			sqlite3_step(m_items_count_stmt);
        }
		else
		{
			sql_error(ok, items_count.c_str());
			return;
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
				if (m_observer->should_log(dht_logger::items_db, aux::LOG_DEBUG))
				{
					m_observer->log(dht_logger::items_db, "timestamp threshold:%d"
						, timestamp);
				}
#endif

				// move to the end
				sqlite3_step(m_select_ts_threshold_stmt);
			}
			else
			{
				sql_error(ok, select_ts_threshold.c_str());
				return;
			}

			sqlite3_reset(m_delete_items_stmt);
			sqlite3_bind_int(m_delete_items_stmt, 1, timestamp);

			time_point const start2 = aux::time_now();
			ok = sqlite3_step(m_delete_items_stmt);
			int const cost2 = aux::numeric_cast<int>(total_microseconds(aux::time_now() - start2));
			if (ok == SQLITE_DONE)
			{
				this->sql_time_cost(cost2, "delete:");

#ifndef TORRENT_DISABLE_LOGGING
				if (m_observer->should_log(dht_logger::items_db, aux::LOG_INFO))
				{
					m_observer->log(dht_logger::items_db, "delete %d items successfully"
						, count - max);
				}
#endif
			}
			else
			{
				sql_error(ok, delete_items.c_str());
				return;
			}
		}
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer->should_log(dht_logger::items_db, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::items_db, "tick: sqlite databse is invalid");
		}
#endif
	}
}

void items_db_sqlite::close()
{
	if (m_select_ts_by_target_stmt != NULL) sqlite3_finalize(m_select_ts_by_target_stmt);
	if (m_select_item_by_target_stmt != NULL) sqlite3_finalize(m_select_item_by_target_stmt);
	if (m_insert_or_replace_items_stmt != NULL) sqlite3_finalize(m_insert_or_replace_items_stmt);
	if (m_items_count_stmt != NULL) sqlite3_finalize(m_items_count_stmt);
	if (m_delete_items_stmt != NULL) sqlite3_finalize(m_delete_items_stmt);
	if (m_select_ts_threshold_stmt != NULL) sqlite3_finalize(m_select_ts_threshold_stmt);
}

void items_db_sqlite::sql_error(int err_code, const char* err_str) const
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer->should_log(dht_logger::items_db, aux::LOG_ERR))
	{
		m_observer->log(dht_logger::items_db, "sql error: %d: %s", err_code, err_str);
	}
#endif
}

void items_db_sqlite::sql_log(int code, const char* msg) const
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer->should_log(dht_logger::items_db, aux::LOG_DEBUG))
	{
		m_observer->log(dht_logger::items_db, "sql log: %d: %s", code, msg);
	}
#endif
}

void items_db_sqlite::sql_time_cost(int const microseconds, const char* msg) const
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer->should_log(dht_logger::items_db, aux::LOG_DEBUG))
	{
		m_observer->log(dht_logger::items_db, "sql %s time cost %dus", msg, microseconds);
	}
#endif
}

} } // namespace libTAU::dht
