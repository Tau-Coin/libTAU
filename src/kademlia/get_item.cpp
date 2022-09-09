/*

Copyright (c) 2013, Steven Siloti
Copyright (c) 2015, Thomas
Copyright (c) 2013-2020, Arvid Norberg
Copyright (c) 2015, Thomas Yuan
Copyright (c) 2016-2017, Alden Torres
Copyright (c) 2017, Pavel Pimenov
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <libTAU/config.hpp>
#include <libTAU/bdecode.hpp>
#include <libTAU/aux_/random.hpp>
#include <libTAU/kademlia/get_item.hpp>
#include <libTAU/kademlia/node.hpp>
#include <libTAU/kademlia/dht_observer.hpp>
#include <libTAU/performance_counters.hpp>
#include <libTAU/hex.hpp>

namespace libTAU { namespace dht {

namespace {

	std::string trim_tailing_zeros(std::string const& str)
	{
		return str.substr(0, str.find_last_not_of(char(0)) + 1);
	}

}

void get_item::got_data(bdecode_node const& v,
	public_key const& pk,
	timestamp const ts,
	signature const& sig)
{
	// we received data!
	// if no data_callback, we needn't care about the data we get.
	// only put_immutable_item no data_callback
	if (!m_data_callback) return;

	// for get_immutable_item
	if (m_immutable)
	{
		// If m_data isn't empty, we should have post alert.
		if (!m_data.empty()) return;

		sha256_hash incoming_target = item_target_id(v.data_section());
		if (incoming_target != target()) return;

		m_data.assign(v);

		// There can only be one true immutable item with a given id
		// Now that we've got it and the user doesn't want to do a put
		// there's no point in continuing to query other nodes
		m_data_callback(m_data, true);
		done();

		return;
	}

	// immutable data should have been handled before this line, only mutable
	// data can reach here, which means pk, sig and timestamp must be valid.

	std::string const salt_copy(m_data.salt());
	sha256_hash const incoming_target = item_target_id(salt_copy, pk);
	if (incoming_target != target()) return;

	// this is mutable data. If it passes the signature
	// check, remember it. Just keep the version with
	// the highest timestamp.
	if (m_data.empty() || m_data.ts() < ts)
	{
		if (!m_data.assign(v, salt_copy, ts, pk, sig))
			return;

		// for get_item, we should call callback when we get data,
		// even if the date is not authoritative, we can update later.
		// so caller can get response ASAP without waiting transaction
		// time-out (15 seconds).
		// for put_item, the callback function will do nothing
		// if the data is non-authoritative.
		// m_data_callback(m_data, false);
	}

	// call data callback anyway.
	item mutable_data(pk, salt_copy);
	if (mutable_data.assign(v, salt_copy, ts, pk, sig))
	{
		if (m_timestamp != -1 && m_timestamp <= ts.value)
		{
			++m_got_items_count;
		}

		if (!mutable_data.empty())
		{
			m_data_callback(mutable_data, false);
		}
	}
}

get_item::get_item(
	node& dht_node
	, node_id const& target
	, data_callback dcallback
	, nodes_callback ncallback)
	: find_data(dht_node, target, std::move(ncallback))
	, m_data_callback(std::move(dcallback))
	, m_immutable(true)
{
}

get_item::get_item(
	node& dht_node
	, public_key const& pk
	, span<char const> salt
	, data_callback dcallback
	, nodes_callback ncallback)
	: find_data(dht_node, item_target_id(salt, pk), std::move(ncallback))
	, m_data_callback(std::move(dcallback))
	, m_data(pk, salt)
	, m_pk(pk)
	, m_immutable(false)
{
}

void get_item::start()
{
	// if the user didn't add seed-nodes manually, grab k (bucket size)
	// nodes from routing table.
	if (m_results.empty() && !m_direct_invoking)
	{
		if (!m_immutable)
		{
			// fill aux endpoints
			std::vector<node_entry> aux_nodes;
			sha256_hash target;
			std::memcpy(&target[0], m_pk.bytes.begin(), 32);
			m_node.m_storage.find_relays(target, aux_nodes
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

char const* get_item::name() const { return "get"; }

observer_ptr get_item::new_observer(udp::endpoint const& ep
	, node_id const& id)
{
	auto o = m_node.m_rpc.allocate_observer<get_item_observer>(self(), ep, id);
#if TORRENT_USE_ASSERTS
	if (o) o->m_in_constructor = false;
#endif
	return o;
}

bool get_item::invoke(observer_ptr o)
{
	if (m_done) return false;

	entry e;
	e["y"] = "q";
	entry& a = e["a"];

	e["q"] = "get";
	std::string raw = target().to_string();
	std::string trim = trim_tailing_zeros(raw);
	a["target"] = trim_tailing_zeros(target().to_string());
	a["mutable"] = m_immutable ? 0 : 1;

	if (!m_immutable)
	{
		a["distance"] = traversal_algorithm::allow_distance();
		if (m_timestamp > 0)
		{
			a["ts"] = m_timestamp;
		}
	}

	m_node.stats_counters().inc_stats_counter(counters::dht_get_out);

	return m_node.m_rpc.invoke(e, o->target_ep(), o);
}

void get_item::done()
{
	// no data_callback for immutable item put
	if (!m_data_callback) return find_data::done();

	if (m_data.is_mutable() || m_data.empty())
	{
		// for mutable data, now we have authoritative data since
		// we've heard from everyone, to be sure we got the
		// latest version of the data (i.e. highest timestamp)
		m_data_callback(m_data, true);

#if TORRENT_USE_ASSERTS
		if (m_data.is_mutable())
		{
			TORRENT_ASSERT(target() == item_target_id(m_data.salt(), m_data.pk()));
		}
#endif
	}

	find_data::done();
}

bool get_item::is_done() const
{
	return m_timestamp != -1 && m_got_items_count >= got_items_max_count;
}

void get_item_observer::reply(msg const& m, node_id const& from)
{
	public_key pk{};
	signature sig{};
	timestamp ts{0};

	bdecode_node const r = m.message.dict_find_dict("r");
	if (!r)
	{
#ifndef TORRENT_DISABLE_LOGGING
		get_observer()->log(dht_logger::traversal, "[%p] missing response dict"
			, static_cast<void*>(algorithm()));
#endif
		timeout();
		return;
	}

	bdecode_node const k = r.dict_find_string("k");
	if (k && k.string_length() == public_key::len)
		std::memcpy(pk.bytes.data(), k.string_ptr(), public_key::len);

	bdecode_node const s = r.dict_find_string("sig");
	if (s && s.string_length() == signature::len)
		std::memcpy(sig.bytes.data(), s.string_ptr(), signature::len);

	bdecode_node const q = r.dict_find_int("ts");
	if (q)
	{
		ts = timestamp(q.int_value());
	}
	else if (k && s)
	{
		timeout();
		return;
	}

	bdecode_node v = r.dict_find("v");
	if (v)
	{
		static_cast<get_item*>(algorithm())->got_data(v, pk, ts, sig);
	}

	find_data_observer::reply(m, from);
}

} } // namespace libTAU::dht
