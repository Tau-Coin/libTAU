/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <algorithm>
#include <cinttypes> // for PRId64 et.al.
#include <map>

#include <libTAU/kademlia/incoming_table.hpp>

#include "libTAU/address.hpp"
#include <libTAU/hex.hpp>
#include "libTAU/aux_/socket_io.hpp" // for print_endpoint
#include "libTAU/aux_/time.hpp"

namespace libTAU { namespace dht {

namespace {

	// return true of the first argument is a better candidate for removal, i.e.
	// less important to keep
	struct node_entry_comparator
	{
		explicit node_entry_comparator(node_id const& id) : m_id(id) {}

		node_entry_comparator(node_entry_comparator const&) = default;

		// explicitly disallow assignment, to silence msvc warning
		node_entry_comparator& operator=(node_entry_comparator const&) = delete;

		template <typename NodeEntry>
		bool operator()(std::pair<node_id const, NodeEntry> const& lhs
			, std::pair<node_id const, NodeEntry> const& rhs) const
		{
			int const l_distance = distance_exp(lhs.first, m_id);
			int const r_distance = distance_exp(rhs.first, m_id);

			if (lhs.second.last_seen == rhs.second.last_seen)
			{
				return l_distance > r_distance;
			}
			else
			{
				return lhs.second.last_seen < rhs.second.last_seen;
			}
	}

	private:

		node_id const& m_id;
	};

	// picks the least important one
	template<class NodeEntry>
	typename std::map<node_id, NodeEntry>::const_iterator pick_least_important_endpoint(
		node_id const& id, std::map<node_id, NodeEntry> const& table)
	{
		return std::min_element(table.begin(), table.end()
			, node_entry_comparator(id));
	}
} // namespace

incoming_table::incoming_table(node_id const& id, udp proto
	, aux::session_settings const& settings
	, routing_table& table
	, dht_logger* log)
	:
#ifndef TORRENT_DISABLE_LOGGING
	m_log(log),
#endif
	m_settings(settings)
	, m_id(id)
	, m_protocol(proto)
	, m_table(table)
	, m_last_refresh(min_time())
{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_log != nullptr && m_log->should_log(dht_logger::incoming_table, aux::LOG_NOTICE))
		{
			m_log->log(dht_logger::incoming_table
				, "config: non-referrable: %s, cap: %d, refresh: %ds, expire: %ds"
				, m_settings.get_bool(settings_pack::dht_non_referrable) ? "true" : "false"
				, m_settings.get_int(settings_pack::dht_incoming_table_max_count)
				, m_settings.get_int(settings_pack::dht_incoming_table_refresh_time)
				, m_settings.get_int(settings_pack::dht_incoming_table_lifetime));
		}
#endif
}

bool incoming_table::incoming_endpoint(node_id const& id
	, udp::endpoint const& ep, bool non_referrable)
{
	if (!non_referrable)
	{
		remove_node(id);
		//m_table.heard_about(id, ep);

		//return true;

		return m_table.node_seen(id, ep, 2000, non_referrable);
	}

	if (m_settings.get_bool(settings_pack::dht_non_referrable))
	{
		return false;
	}

	// try to remove this node from routing table
	m_table.remove_node(id);

	return add_node(id, ep);
}

bool incoming_table::node_seen(node_id const& id
	, udp::endpoint const& ep, int rtt, bool non_referrable)
{
	if (!non_referrable)
	{
		remove_node(id);
		return m_table.node_seen(id, ep, rtt, non_referrable);
	}

	if (m_settings.get_bool(settings_pack::dht_non_referrable))
	{
		return false;
	}

	// try to remove this node from routing table
	m_table.remove_node(id);

	return add_node(id, ep);
}

node_entry* incoming_table::find_node(node_id const& nid)
{
	auto i = m_nr_table.find(nid);

	if (i != m_nr_table.end())
	{
		return &(i->second);
	}

	return m_table.find_node(nid);
}

void incoming_table::tick()
{
	if (m_settings.get_bool(settings_pack::dht_non_referrable)) return;

	if (0 == endpoint_lifetime()) return;

	time_point const now = aux::time_now();
	if (m_last_refresh + seconds(refresh_time()) > now) return;
	m_last_refresh = now;

	for (auto i = m_nr_table.begin(); i != m_nr_table.end();)
	{
		if (i->second.last_seen + seconds(endpoint_lifetime()) > now)
		{
			++i;
			continue;
		}

#ifndef TORRENT_DISABLE_LOGGING
		if (m_log != nullptr && m_log->should_log(dht_logger::incoming_table, aux::LOG_WARNING))
		{
			m_log->log(dht_logger::incoming_table
				, "expire endpoint id: %s, addr: %s:%d, size:%" PRId64
				, aux::to_hex(i->second.id).c_str()
				, aux::print_address(i->second.addr()).c_str()
				, i->second.port()
				, m_nr_table.size());
		}
#endif

		i = m_nr_table.erase(i);
	}
}

bool incoming_table::add_node(node_id const& id, udp::endpoint const& ep)
{
	auto i = m_nr_table.find(id);

	if (i != m_nr_table.end())
	{
		if (i->second.addr() != ep.address() || i->second.port() != ep.port())
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (m_log != nullptr && m_log->should_log(dht_logger::incoming_table, aux::LOG_NOTICE))
			{
				m_log->log(dht_logger::incoming_table
					, "update endpoint id: %s, new: %s:%d, old: %s:%d, size:%" PRId64
					, aux::to_hex(i->second.id).c_str()
					, aux::print_address(ep.address()).c_str()
					, ep.port()
					, aux::print_address(i->second.addr()).c_str()
					, i->second.port()
					, m_nr_table.size());
			}
#endif

			i->second.update_endpoint(ep);
		}

		i->second.last_seen = aux::time_now();

		return true;
	}

	if (m_nr_table.size() > endpoint_max_count())
	{
		auto const j = pick_least_important_endpoint(m_id, m_nr_table);

#ifndef TORRENT_DISABLE_LOGGING
		if (m_log != nullptr && m_log->should_log(dht_logger::incoming_table, aux::LOG_NOTICE))
		{
			m_log->log(dht_logger::incoming_table
				, "erase endpoint id: %s, addr: %s:%d, size: %" PRId64
				, aux::to_hex(j->second.id).c_str()
				, aux::print_address(j->second.addr()).c_str()
				, j->second.port()
				, m_nr_table.size());
		}
#endif

		m_nr_table.erase(j);
	}

	node_entry to_add(id, ep);
	to_add.last_seen = aux::time_now();
	std::tie(i, std::ignore) = m_nr_table.insert(
		std::make_pair(id, std::move(to_add)));

#ifndef TORRENT_DISABLE_LOGGING
	if (m_log != nullptr && m_log->should_log(dht_logger::incoming_table, aux::LOG_NOTICE))
	{
		m_log->log(dht_logger::incoming_table, "new endpoint id: %s, addr: %s:%d, size: %" PRId64
			, aux::to_hex(id).c_str()
			, aux::print_address(ep.address()).c_str()
			, ep.port()
			, m_nr_table.size());
	}
#endif

	return true;
}

void incoming_table::remove_node(node_id const& id)
{
	auto const i = m_nr_table.find(id);
	if (i == m_nr_table.end()) return;

#ifndef TORRENT_DISABLE_LOGGING
	if (m_log != nullptr && m_log->should_log(dht_logger::incoming_table))
	{
		m_log->log(dht_logger::incoming_table
			, "erase endpoint id: %s, addr: %s:%d, size:%" PRId64
			, aux::to_hex(i->second.id).c_str()
			, aux::print_address(i->second.addr()).c_str()
			, i->second.port()
			, m_nr_table.size());
	}
#endif

	m_nr_table.erase(i);
}

int incoming_table::endpoint_max_count() const
{
	return m_settings.get_int(settings_pack::dht_incoming_table_max_count);
}

int incoming_table::refresh_time() const
{
	return m_settings.get_int(settings_pack::dht_incoming_table_refresh_time);
}

int incoming_table::endpoint_lifetime() const
{
	return m_settings.get_int(settings_pack::dht_incoming_table_lifetime);
}

} } // namespace libTAU::dht
