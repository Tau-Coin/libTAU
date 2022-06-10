/*

Copyright (c) 2006, Daniel Wallin
Copyright (c) 2013-2020, Arvid Norberg
Copyright (c) 2015, Thomas Yuan
Copyright (c) 2015, Steven Siloti
Copyright (c) 2016-2017, Pavel Pimenov
Copyright (c) 2016-2017, 2021, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <libTAU/kademlia/get_peers.hpp>
#include <libTAU/kademlia/node.hpp>
#include <libTAU/kademlia/dht_observer.hpp>
#include <libTAU/aux_/socket_io.hpp>
#include <libTAU/performance_counters.hpp>
#include <libTAU/aux_/ip_helpers.hpp> // for is_v4

#ifndef TORRENT_DISABLE_LOGGING
#include <libTAU/hex.hpp> // to_hex
#endif

namespace libTAU::dht {

void get_peers_observer::reply(msg const& m, node_id const& from)
{
	bdecode_node const r = m.message.dict_find_dict("r");
	if (!r)
	{
#ifndef TORRENT_DISABLE_LOGGING
		get_observer()->log(dht_logger::traversal, "[%u] missing response dict"
			, algorithm()->id());
#endif
		timeout();
		return;
	}

	// look for peers
	bdecode_node const n = r.dict_find_list("values");
	if (n)
	{
		std::vector<tcp::endpoint> peer_list;
		if (n.list_size() == 1 && n.list_at(0).type() == bdecode_node::string_t
			&& aux::is_v4(m.addr))
		{
			// assume it's mainline format
			char const* peers = n.list_at(0).string_ptr();
			char const* end = peers + n.list_at(0).string_length();

#ifndef TORRENT_DISABLE_LOGGING
			log_peers(m, r, int((end - peers) / 6), from);
#endif
			while (end - peers >= 6)
				peer_list.push_back(aux::read_v4_endpoint<tcp::endpoint>(peers));
		}
		else
		{
			// assume it's uTorrent/libTAU format
			peer_list = aux::read_endpoint_list<tcp::endpoint>(n);
#ifndef TORRENT_DISABLE_LOGGING
			log_peers(m, r, n.list_size(), from);
#endif
		}
		static_cast<get_peers*>(algorithm())->got_peers(peer_list);
	}

	find_data_observer::reply(m, from);
}
#ifndef TORRENT_DISABLE_LOGGING
void get_peers_observer::log_peers(msg const& m, bdecode_node const& r
	, int const size, node_id const& from) const
{
			auto* logger = get_observer();
			if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
			{
				logger->log(dht_logger::traversal, "[%u] PEERS "
					"invoke-count: %d branch-factor: %d addr: %s id: %s distance: %d p: %d"
					, algorithm()->id()
					, algorithm()->invoke_count()
					, algorithm()->branch_factor()
					, aux::print_endpoint(m.addr).c_str()
					, aux::to_hex({from.data(), 32}).c_str()
					, distance_exp(algorithm()->target(), from)
					, size);
			}
}
#endif
void get_peers::got_peers(std::vector<tcp::endpoint> const& peers)
{
	if (m_data_callback) m_data_callback(peers);
}

get_peers::get_peers(
	node& dht_node
	, node_id const& target
	, data_callback dcallback
	, nodes_callback ncallback
	, bool noseeds)
	: find_data(dht_node, target, std::move(ncallback))
	, m_data_callback(std::move(dcallback))
	, m_noseeds(noseeds)
{
	set_invoke_limit(16);
}

char const* get_peers::name() const { return "get_peers"; }

bool get_peers::invoke(observer_ptr o)
{
	if (m_done) return false;

	entry e;
	e["y"] = "q";
	entry& a = e["a"];

	e["q"] = "get_peers";
	a["info_hash"] = target().to_string();
	if (m_noseeds) a["noseed"] = 1;

	if (m_node.observer() != nullptr)
	{
		m_node.observer()->outgoing_get_peers(target(), target(), o->target_ep());
	}

	m_node.stats_counters().inc_stats_counter(counters::dht_get_peers_out);

	return m_node.m_rpc.invoke(e, o->target_ep(), o);
}

observer_ptr get_peers::new_observer(udp::endpoint const& ep
	, node_id const& id)
{
	auto o = m_node.m_rpc.allocate_observer<get_peers_observer>(self(), ep, id);
#if TORRENT_USE_ASSERTS
	if (o) o->m_in_constructor = false;
#endif
	return o;
}

} // namespace libTAU::dht
