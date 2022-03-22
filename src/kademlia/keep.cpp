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

#include <libTAU/kademlia/keep.hpp>
#include <libTAU/kademlia/dht_observer.hpp>
#include <libTAU/kademlia/node.hpp>
#include <libTAU/aux_/socket_io.hpp>
#include <libTAU/aux_/io_bytes.hpp>
#include <libTAU/performance_counters.hpp>
#include <libTAU/hex.hpp>

namespace libTAU { namespace dht {

keep::keep(node& dht_node, node_id const& to)
	: traversal_algorithm(dht_node, to)
{}

char const* keep::name() const { return "keep"; }

void keep::start()
{
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

		/*
		for (auto& n : nodes)
		{
			add_entry(n.id, n.ep(), observer::flag_initial);
		}
		*/

		set_direct_endpoints(nodes);
	}

	traversal_algorithm::start();
}

void keep::done()
{
	m_done = true;

#ifndef TORRENT_DISABLE_LOGGING
	get_node().observer()->log(dht_logger::traversal, "[%u] %s DONE, response %d, timeout %d"
		, id(), name(), num_responses(), num_timeouts());
#endif

	traversal_algorithm::done();
}

bool keep::invoke(observer_ptr o)
{
	if (m_done) return false;

	entry e;
	e["a"] = entry(entry::dictionary_t);
	e["y"] = "q";
	e["q"] = "keep";

	return m_node.m_rpc.invoke(e, o->target_ep(), o, m_discard_response);
}

observer_ptr keep::new_observer(udp::endpoint const& ep
	, node_id const& id)
{
	auto o = m_node.m_rpc.allocate_observer<keep_observer>(self(), ep, id);
#if TORRENT_USE_ASSERTS
	if (o) o->m_in_constructor = false;
#endif
	return o;
}

} } // namespace libTAU::dht
