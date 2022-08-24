/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <libTAU/config.hpp>
#include "libTAU/hex.hpp" // to_hex
#include <libTAU/aux_/io_bytes.hpp>
#include <libTAU/aux_/random.hpp>
#include <libTAU/aux_/session_settings.hpp>
#include <libTAU/aux_/socket_io.hpp> // for print_endpoint
#include <libTAU/aux_/time.hpp> // for aux::time_now
#include <libTAU/aux_/ip_helpers.hpp> // for is_v6

#include <libTAU/kademlia/bs_nodes_learner.hpp>
#include <libTAU/kademlia/node.hpp>

#include <type_traits>
#include <functional>

namespace libTAU::dht {

bs_nodes_learner::bs_nodes_learner(node_id const& our_id
	, aux::session_settings const& settings
	, routing_table& table
	, bs_nodes_storage_interface& bs_nodes_storage
	, dht_logger* log)
	: m_settings(settings)
	, m_table(table)
	, m_bs_nodes_storage(bs_nodes_storage)
	, m_our_id(our_id)
#ifndef TORRENT_DISABLE_LOGGING
	, m_log(log)
#endif
{
#ifdef TORRENT_DISABLE_LOGGING
	TORRENT_UNUSED(log);
#endif

	m_last_refresh = min_time();

	m_storage_size = bs_nodes_storage.size();
}

void bs_nodes_learner::get_bootstrap_nodes(std::vector<bs_node_entry>& nodes, int count)
{
	if (count <= 0 || m_storage_iterator >= m_storage_size)
	{
		return;
	}

	nodes.clear();

	int offset = m_storage_iterator;

	bool ok = m_bs_nodes_storage.get(nodes, offset, count);
	if (!ok)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
		{
			m_log->log(dht_logger::bs_nodes_db, "get bs nodes error");
		}
#endif

		return;
	}

	m_storage_iterator += nodes.size();
}

void bs_nodes_learner::add_bootstrap_nodes(std::vector<bs_node_entry> const& nodes)
{
	bool ok = m_bs_nodes_storage.put(nodes);
	if (!ok)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
		{
			m_log->log(dht_logger::bs_nodes_db, "add bs nodes error");
		}
#endif
	}
}

void bs_nodes_learner::tick()
{
	time_point const now = aux::time_now();
	int refresh_period = m_settings.get_int(settings_pack::dht_bs_nodes_db_refresh_time);
	if (m_last_refresh + seconds(refresh_period) > now) return;
	m_last_refresh = now;

	// fetch live nodes from routing table and put them into storage.
	std::vector<bs_node_entry> nodes;
	m_table.for_each_node([&nodes](node_entry const& e)
			{ nodes.emplace_back(bs_node_entry(e.id, e.endpoint)); }, nullptr);

#ifndef TORRENT_DISABLE_LOGGING
	for (auto& bsn : nodes)
	{
		if (m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_INFO))
		{
			m_log->log(dht_logger::bs_nodes_db, "collect live node as bs node:%s, %s"
				, aux::to_hex(bsn.m_nid).c_str()
				, aux::print_endpoint(bsn.m_ep).c_str());
		}
	}
#endif

	bool ok = m_bs_nodes_storage.put(nodes);
	if (!ok)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
		{
			m_log->log(dht_logger::bs_nodes_db, "put bs nodes error");
		}
#endif

		return;
	}

	m_storage_size = m_bs_nodes_storage.tick();
}

} // namespace libTAU::dht
