/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <libTAU/kademlia/items_db_sqlite.hpp>

namespace libTAU { namespace dht {

items_db_sqlite::items_db_sqlite(settings_interface const& settings
	, dht_observer* observer)
	: m_settings(settings)
	, m_observer(observer)
{
	init();
}

void items_db_sqlite::init()
{
	// first of all, create table if not exist.

	// create index
}

bool items_db_sqlite::get_mutable_item_timestamp(sha256_hash const& target
	, timestamp& ts) const
{
	return false;
}

bool items_db_sqlite::get_mutable_item(sha256_hash const& target
	, timestamp ts, bool force_fill
	, entry& item) const
{
	return false;
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
}

void items_db_sqlite::remove_mutable_item(sha256_hash const& target)
{
}

} } // namespace libTAU::dht
