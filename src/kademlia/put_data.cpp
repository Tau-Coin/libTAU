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

#include <libTAU/kademlia/put_data.hpp>
#include <libTAU/kademlia/dht_observer.hpp>
#include <libTAU/kademlia/node.hpp>
#include <libTAU/aux_/io_bytes.hpp>
#include <libTAU/aux_/random.hpp>
#include <libTAU/performance_counters.hpp>

namespace libTAU { namespace dht {

void put_data_observer::reply(msg const& m, node_id const& from)
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

	bdecode_node const hit_ent = r.dict_find_int("hit");
	bool const hit = hit_ent && hit_ent.int_value() != 0;
	static_cast<put_data*>(algorithm())->on_put_success(from, m.addr, hit);

	// For putting mutable item, add refer nodes into routing table.
    traversal_observer::reply(m, from);
    done();
}

put_data::put_data(node& dht_node, node_id const& target
	, public_key const& to, put_callback callback, nodes_callback ncallback)
	: traversal_algorithm(dht_node, target)
	, m_to(to)
	, m_put_callback(std::move(callback))
	, m_nodes_callback(std::move(ncallback))
{}

char const* put_data::name() const { return "put_data"; }

void put_data::start()
{
	// for "XX" channel, set fixed allow distance into 255.
	if (m_data.is_mutable() && m_data.pk() == m_to)
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
	}

	traversal_algorithm::start();
}

bool put_data::is_done() const
{
	return m_hits != 0 && m_hits >= m_hit_limit;
}

void put_data::done()
{
	m_done = true;

#ifndef TORRENT_DISABLE_LOGGING
	get_node().observer()->log(dht_logger::traversal, "[%u] %s DONE, response %d, timeout %d"
		, id(), name(), num_responses(), num_timeouts());
#endif

	if (m_nodes_callback) m_nodes_callback(m_success_nodes);
	m_put_callback(m_data, num_responses());
	traversal_algorithm::done();
}

bool put_data::invoke(observer_ptr o)
{
	if (m_done) return false;

	entry e;
	e["y"] = "q";
	e["q"] = "put";
	entry& a = e["a"];
	a["v"] = m_data.value();
	a["token"] = libtau_token;
	if (!m_to.is_all_zeros())
	{
		a["to"] = m_to.bytes;
	}
	if (m_data.is_mutable())
	{
		a["k"] = m_data.pk().bytes;
		a["ts"] = m_data.ts().value;
		a["sig"] = m_data.sig().bytes;
		a["distance"] = traversal_algorithm::allow_distance();
		a["cache"] = m_cache ? 1 : 0;
		if (!m_data.salt().empty())
		{
			a["salt"] = m_data.salt();
		}
	}

	m_node.stats_counters().inc_stats_counter(counters::dht_put_out);

	return m_node.m_rpc.invoke(e, o->target_ep(), o, m_discard_response);
}

void put_data::on_put_success(node_id const& nid, udp::endpoint const& ep, bool hit)
{
	m_success_nodes.push_back(std::make_pair(node_entry(nid, ep), hit));
	if (hit) ++m_hits;
}

observer_ptr put_data::new_observer(udp::endpoint const& ep
	, node_id const& id)
{
	auto o = m_node.m_rpc.allocate_observer<put_data_observer>(self(), ep, id);
#if TORRENT_USE_ASSERTS
	if (o) o->m_in_constructor = false;
#endif
	return o;
}

} } // namespace libTAU::dht
