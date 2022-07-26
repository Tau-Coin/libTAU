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
#include <libTAU/hasher.hpp>
#include <libTAU/hex.hpp>

namespace libTAU { namespace dht {

relay_hmac gen_relay_hmac(span<char const> payload
		, span<char const> aux_nodes)
{
	hasher256 h(payload);
	if (!aux_nodes.empty()) h.update(aux_nodes);
	sha256_hash hash = h.final();
	return relay_hmac(hash.data());
}

bool verify_relay_hmac(relay_hmac const& hmac
		, span<char const> payload
		, span<char const> aux_nodes)
{
	relay_hmac h = gen_relay_hmac(payload, aux_nodes);
	return h == hmac;
}

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

	bdecode_node const hit_ent = r.dict_find_int("hit");
	bool const hit = hit_ent && hit_ent.int_value() != 0;
	static_cast<relay*>(algorithm())->on_put_success(from, m.addr, hit);

	// add referred nodes into routing table.
    traversal_observer::reply(m, from);
    done();
}

relay::relay(node& dht_node
	, node_id const& to
	, entry payload
	, entry aux_nodes
	, relay_hmac const& hmac
	, completed_callback callback)
	: traversal_algorithm(dht_node, to)
	, m_to(to)
	, m_payload(std::move(payload))
	, m_aux_nodes(std::move(aux_nodes))
	, m_hmac(hmac)
	, m_completed_callback(std::move(callback))
{}

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
		// fill aux endpoints
		std::vector<node_entry> aux_nodes;
		m_node.m_storage.find_relays(target(), aux_nodes
			, invoke_window(), m_node.protocol());
		for (auto& an : aux_nodes)
		{
#ifndef TORRENT_DISABLE_LOGGING
			get_node().observer()->log(dht_logger::traversal, "add relay, id: %s, ep:%s"
				, aux::to_hex(an.id).c_str()
				, aux::print_endpoint(an.ep()).c_str());
#endif
			add_entry(an.id, an.ep()
				, observer::flag_initial | observer::flag_high_priority);
		}

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

bool relay::is_done() const
{
	return m_hits != 0 && m_hits >= m_hit_limit;
}

void relay::done()
{
	m_done = true;

#ifndef TORRENT_DISABLE_LOGGING
	get_node().observer()->log(dht_logger::traversal, "[%u] %s DONE, response %d, timeout %d"
		, id(), name(), num_responses(), num_timeouts());
#endif

	m_completed_callback(m_payload, m_success_nodes);
	traversal_algorithm::done();
}

bool relay::invoke(observer_ptr o)
{
	if (m_done) return false;

	entry e;
	e["y"] = "h"; // hop
	e["q"] = "relay";
	entry& a = e["a"];
	a["pl"] = m_encrypted_payload; // payload
	// a["f"] = m_node.nid().to_string(); // from
	a["t"] = m_to.to_string(); // to
	a["dis"] = traversal_algorithm::allow_distance();
	if (m_aux_nodes.type() != entry::data_type::undefined_t)
	{
		// relay nodes
		a[m_node.protocol_relay_nodes_key()] = m_aux_nodes;
	}
	a["hmac"] = m_hmac.bytes;

	return m_node.m_rpc.invoke(e, o->target_ep(), o, m_discard_response);
}

void relay::on_put_success(node_id const& nid, udp::endpoint const& ep, bool hit)
{
	if (hit) ++m_hits;
	m_success_nodes.push_back(std::make_pair(node_entry(nid, ep), hit));
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
