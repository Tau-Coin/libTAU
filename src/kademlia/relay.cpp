/*

Copyright (c) 2006, Daniel Wallin
Copyright (c) 2015, Thomas Yuan
Copyright (c) 2015, Steven Siloti
Copyright (c) 2016-2020, Arvid Norberg
Copyright (c) 2016-2018, 2020, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <libTAU/kademlia/relay.hpp>
#include <libTAU/kademlia/dht_observer.hpp>
#include <libTAU/kademlia/node.hpp>
#include <libTAU/aux_/socket_io.hpp>
#include <libTAU/aux_/io_bytes.hpp>
#include <libTAU/aux_/random.hpp>
#include <libTAU/performance_counters.hpp>
#include <libTAU/hex.hpp>

namespace libTAU { namespace dht {

void relay_observer::reply(msg const& m, node_id const& from)
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

	// add referred nodes into routing table.
    traversal_observer::reply(m, from);
    done();
}

relay::relay(node& dht_node, node_id const& to, completed_callback callback)
	: traversal_algorithm(dht_node, to)
	, m_to(to)
	, m_completed_callback(std::move(callback))
{}

void relay::add_relays_nodes(std::vector<node_entry> const& nodes)
{
	for (auto& n : nodes)
	{
		m_relay_nodes.push_back({n.id, n.endpoint});
	}
}

char const* relay::name() const { return "relay"; }

void relay::start()
{
	// for "XX" channel, set fixed allow distance into 255.
	if (m_node.nid() == m_to)
	{
		set_fixed_distance(256);
	}

	// if the user didn't add seed-nodes manually, grab k (bucket size)
	// nodes from routing table.
	if (m_results.empty() && !m_direct_invoking)
	{
		std::vector<node_entry> nodes = m_node.m_table.find_node(
			target(), routing_table::include_pinged, invoke_window());

		if (nodes.size() < invoke_window())
		{
			nodes.clear();
			nodes = m_node.m_table.find_node(target()
					, routing_table::include_failed, invoke_window());
		}

		for (auto& n : nodes)
		{
			add_entry(n.id, n.ep(), observer::flag_initial);
		}

		// fill aux endpoints
		std::vector<node_entry> aux_nodes;
		m_node.m_storage.find_relays(target(), aux_nodes, 1, m_node.protocol());
		for (auto& an : aux_nodes)
		{
#ifndef TORRENT_DISABLE_LOGGING
			get_node().observer()->log(dht_logger::traversal, "add relay, id: %s, ep:%s"
				, aux::to_hex(an.id).c_str()
				, aux::print_endpoint(an.ep()).c_str());
#endif
			add_entry(an.id, an.ep(), observer::flag_initial);
		}
	}

	traversal_algorithm::start();
}

void relay::done()
{
	m_done = true;

#ifndef TORRENT_DISABLE_LOGGING
	get_node().observer()->log(dht_logger::traversal, "[%u] %s DONE, response %d, timeout %d"
		, id(), name(), num_responses(), num_timeouts());
#endif

	m_completed_callback(m_payload, num_responses());
	traversal_algorithm::done();
}

bool relay::invoke(observer_ptr o)
{
	if (m_done) return false;

	entry e;
	e["y"] = "h"; // hop
	e["q"] = "relay";
	entry& a = e["a"];
	a["pl"] = m_payload; // payload
	a["f"] = m_node.nid().to_string(); // from
	a["t"] = m_to.to_string(); // to
	a["dis"] = traversal_algorithm::allow_distance();
	if (!m_relay_nodes.empty())
	{
		// relay nodes
		a[m_node.protocol_relay_nodes_key()] = write_nodes_entry(m_relay_nodes);;
	}

	return m_node.m_rpc.invoke(e, o->target_ep(), o, m_discard_response);
}

observer_ptr relay::new_observer(udp::endpoint const& ep
	, node_id const& id)
{
	auto o = m_node.m_rpc.allocate_observer<relay_observer>(self(), ep, id);
#if TORRENT_USE_ASSERTS
	if (o) o->m_in_constructor = false;
#endif
	return o;
}

} } // namespace libTAU::dht
