/*

Copyright (c) 2006-2020, Arvid Norberg
Copyright (c) 2014-2018, Steven Siloti
Copyright (c) 2015-2019, 2021, Alden Torres
Copyright (c) 2015, Thomas Yuan
Copyright (c) 2016-2017, Pavel Pimenov
Copyright (c) 2019, Amir Abrams
Copyright (c) 2020, Fonic
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libtorrent/config.hpp"

#include <utility>
#include <cinttypes> // for PRId64 et.al.
#include <functional>
#include <tuple>
#include <array>

#ifndef TORRENT_DISABLE_LOGGING
#include "libtorrent/hex.hpp" // to_hex
#endif

#include <libtorrent/aux_/socket_io.hpp>
#include <libtorrent/session_status.hpp>
#include "libtorrent/bencode.hpp"
#include "libtorrent/hasher.hpp"
#include "libtorrent/aux_/random.hpp"
#include <libtorrent/assert.hpp>
#include <libtorrent/aux_/time.hpp>
#include "libtorrent/aux_/throw.hpp"
#include "libtorrent/aux_/session_settings.hpp"
#include "libtorrent/alert_types.hpp" // for dht_lookup
#include "libtorrent/performance_counters.hpp" // for counters
#include "libtorrent/aux_/ip_helpers.hpp" // for is_v4

#include "libtorrent/kademlia/node.hpp"
#include "libtorrent/kademlia/dht_observer.hpp"
#include "libtorrent/kademlia/io.hpp"
#include "libtorrent/kademlia/dht_settings.hpp"

#include "libtorrent/kademlia/refresh.hpp"
#include "libtorrent/kademlia/get_peers.hpp"
#include "libtorrent/kademlia/get_item.hpp"
#include "libtorrent/kademlia/msg.hpp"
#include <libtorrent/kademlia/put_data.hpp>

using namespace std::placeholders;

namespace libtorrent::dht {

namespace {

// the write tokens we generate are 4 bytes
constexpr int write_token_size = 4;

void nop() {}

// generate an error response message
void incoming_error(entry& e, char const* msg, int error_code = 203)
{
	e["y"] = "e";
	entry::list_type& l = e["e"].list();
	l.emplace_back(error_code);
	l.emplace_back(msg);
}

} // anonymous namespace

node::node(aux::listen_socket_handle const& sock, socket_manager* sock_man
	, aux::session_settings const& settings
	, node_id const& nid
	, dht_observer* observer
	, counters& cnt
	, get_foreign_node_t get_foreign_node
	, dht_storage_interface& storage)
	: m_settings(settings)
	, m_id(nid)
	, m_table(m_id, aux::is_v4(sock.get_local_endpoint()) ? udp::v4() : udp::v6(), 8, settings, observer)
	, m_rpc(m_id, m_settings, m_table, sock, sock_man, observer)
	, m_sock(sock)
	, m_sock_man(sock_man)
	, m_get_foreign_node(std::move(get_foreign_node))
	, m_observer(observer)
	, m_protocol(map_protocol_to_descriptor(aux::is_v4(sock.get_local_endpoint()) ? udp::v4() : udp::v6()))
	, m_last_tracker_tick(aux::time_now())
	, m_last_self_refresh(min_time())
	, m_counters(cnt)
	, m_storage(storage)
{
	aux::crypto_random_bytes(m_secret[0]);
	aux::crypto_random_bytes(m_secret[1]);
}

node::~node() = default;

int node::branch_factor() const { return m_settings.get_int(settings_pack::dht_search_branching); }

bool node::verify_token(string_view token, sha256_hash const& info_hash
	, udp::endpoint const& addr) const
{
	if (token.length() != write_token_size)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer != nullptr)
		{
			m_observer->log(dht_logger::node, "token of incorrect length: %d"
				, int(token.length()));
		}
#endif
		return false;
	}

	hasher256 h1;
	std::string const address = addr.address().to_string();
	h1.update(address);
	h1.update(m_secret[0]);
	h1.update(info_hash);

	sha256_hash h = h1.final();
	if (std::equal(token.begin(), token.end(), reinterpret_cast<char*>(&h[0])))
		return true;

	hasher256 h2;
	h2.update(address);
	h2.update(m_secret[1]);
	h2.update(info_hash);
	h = h2.final();
	return std::equal(token.begin(), token.end(), reinterpret_cast<char*>(&h[0]));
}

std::string node::generate_token(udp::endpoint const& addr
	, sha256_hash const& info_hash)
{
	std::string token;
	token.resize(write_token_size);
	hasher256 h;
	std::string const address = addr.address().to_string();
	h.update(address);
	h.update(m_secret[0]);
	h.update(info_hash);

	sha256_hash const hash = h.final();
	std::copy(hash.begin(), hash.begin() + write_token_size, token.begin());
	TORRENT_ASSERT(std::equal(token.begin(), token.end(), hash.data()));
	return token;
}

void node::bootstrap(std::vector<udp::endpoint> const& nodes
	, find_data::nodes_callback const& f)
{
	node_id target = m_id;
	make_id_secret(target);

	auto r = std::make_shared<dht::bootstrap>(*this, target, f);
	m_last_self_refresh = aux::time_now();

#ifndef TORRENT_DISABLE_LOGGING
	int count = 0;
#endif

	for (auto const& n : nodes)
	{
#ifndef TORRENT_DISABLE_LOGGING
		++count;
#endif
		r->add_entry(node_id(), n, observer::flag_initial);
	}

#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr)
		m_observer->log(dht_logger::node, "bootstrapping with %d nodes", count);
#endif
	r->start();
}

int node::bucket_size(int bucket)
{
	return m_table.bucket_size(bucket);
}

void node::new_write_key()
{
	m_secret[1] = m_secret[0];
	aux::crypto_random_bytes(m_secret[0]);
}

void node::unreachable(udp::endpoint const& ep)
{
	m_rpc.unreachable(ep);
}

void node::incoming(aux::listen_socket_handle const& s, msg const& m)
{
	// is this a reply?
	bdecode_node const y_ent = m.message.dict_find_string("y");
	if (!y_ent || y_ent.string_length() != 1)
	{
		// don't respond to this obviously broken messages. We don't
		// want to open up a magnification opportunity
//		entry e;
//		incoming_error(e, "missing 'y' entry");
//		m_sock.send_packet(e, m.addr);
		return;
	}

	char const y = *(y_ent.string_ptr());

	// we can only ascribe the external IP this node is saying we have to the
	// listen socket the packet was received on
	if (s == m_sock)
	{
		bdecode_node ext_ip = m.message.dict_find_string("ip");

		if (ext_ip && ext_ip.string_length() >= int(aux::address_size(udp::v6())))
		{
			// this node claims we use the wrong node-ID!
			char const* ptr = ext_ip.string_ptr();
			if (m_observer != nullptr)
				m_observer->set_external_address(m_sock, aux::read_v6_address(ptr)
					, m.addr.address());
		}
		else if (ext_ip && ext_ip.string_length() >= int(aux::address_size(udp::v4())))
		{
			char const* ptr = ext_ip.string_ptr();
			if (m_observer != nullptr)
				m_observer->set_external_address(m_sock, aux::read_v4_address(ptr)
					, m.addr.address());
		}
	}

	switch (y)
	{
		case 'r':
		{
			node_id id;
			m_rpc.incoming(m, &id);
			break;
		}
		case 'q':
		{
			TORRENT_ASSERT(m.message.dict_find_string_value("y") == "q");
			// When a DHT node enters the read-only state, it no longer
			// responds to 'query' messages that it receives.
			if (m_settings.get_bool(settings_pack::dht_read_only)) break;

			// ignore packets arriving on a different interface than the one we're
			// associated with
			if (s != m_sock) return;

			if (!m_sock_man->has_quota())
			{
				m_counters.inc_stats_counter(counters::dht_messages_in_dropped);
				return;
			}

			entry e;
			incoming_request(m, e);
			m_sock_man->send_packet(m_sock, e, m.addr);
			break;
		}
		case 'e':
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer != nullptr && m_observer->should_log(dht_logger::node))
			{
				bdecode_node const err = m.message.dict_find_list("e");
				if (err && err.list_size() >= 2
					&& err.list_at(0).type() == bdecode_node::int_t
					&& err.list_at(1).type() == bdecode_node::string_t)
				{
					m_observer->log(dht_logger::node, "INCOMING ERROR: (%" PRId64 ") %s"
						, err.list_int_value_at(0)
						, std::string(err.list_string_value_at(1)).c_str());
				}
				else
				{
					m_observer->log(dht_logger::node, "INCOMING ERROR (malformed)");
				}
			}
#endif
			node_id id;
			m_rpc.incoming(m, &id);
			break;
		}
	}
}

void node::add_router_node(udp::endpoint const& router)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node))
	{
		m_observer->log(dht_logger::node, "adding router node: %s"
			, aux::print_endpoint(router).c_str());
	}
#endif
	m_table.add_router_node(router);
}

void node::add_node(udp::endpoint const& node)
{
	if (!native_address(node)) return;
	// ping the node, and if we get a reply, it
	// will be added to the routing table
	send_single_refresh(node, m_table.num_active_buckets());
}

void node::get_item(sha256_hash const& target, std::function<void(item const&)> f)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node))
	{
		m_observer->log(dht_logger::node, "starting get for [ hash: %s ]"
			, aux::to_hex(target).c_str());
	}
#endif

	auto ta = std::make_shared<dht::get_item>(*this, target
		, std::bind(f, _1), find_data::nodes_callback());
	ta->start();
}

void node::get_item(public_key const& pk, std::string const& salt
	, std::function<void(item const&, bool)> f)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node))
	{
		char hex_key[65];
		aux::to_hex(pk.bytes, hex_key);
		m_observer->log(dht_logger::node, "starting get for [ key: %s ]", hex_key);
	}
#endif

	auto ta = std::make_shared<dht::get_item>(*this, pk, salt, std::move(f)
		, find_data::nodes_callback());
	ta->start();
}

namespace {

void put(std::vector<std::pair<node_entry, std::string>> const& nodes
	, std::shared_ptr<put_data> const& ta)
{
	ta->set_targets(nodes);
	ta->start();
}

void put_data_cb(item const& i, bool auth
	, std::shared_ptr<put_data> const& ta
	, std::function<void(item&)> const& f)
{
	// call data_callback only when we got authoritative data.
	if (auth)
	{
		item copy(i);
		f(copy);
		ta->set_data(std::move(copy));
	}
}

} // namespace

void node::put_item(sha256_hash const& target, entry const& data, std::function<void(int)> f)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node))
	{
		m_observer->log(dht_logger::node, "starting put for [ hash: %s ]"
			, aux::to_hex(target).c_str());
	}
#endif

	item i;
	i.assign(data);
	auto put_ta = std::make_shared<dht::put_data>(*this, std::bind(f, _2));
	put_ta->set_data(std::move(i));

	auto ta = std::make_shared<dht::get_item>(*this, target
		, get_item::data_callback(), std::bind(&put, _1, put_ta));
	ta->start();
}

void node::put_item(public_key const& pk, std::string const& salt
	, std::function<void(item const&, int)> f
	, std::function<void(item&)> data_cb)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node))
	{
		char hex_key[65];
		aux::to_hex(pk.bytes, hex_key);
		m_observer->log(dht_logger::node, "starting put for [ key: %s ]", hex_key);
	}
#endif

	auto put_ta = std::make_shared<dht::put_data>(*this, f);

	auto ta = std::make_shared<dht::get_item>(*this, pk, salt
		, std::bind(&put_data_cb, _1, _2, put_ta, data_cb)
		, std::bind(&put, _1, put_ta));
	ta->start();
}

struct ping_observer : observer
{
	ping_observer(
		std::shared_ptr<traversal_algorithm> algorithm
		, udp::endpoint const& ep, node_id const& id)
		: observer(std::move(algorithm), ep, id)
	{}

	// parses out "nodes"
	void reply(msg const& m) override
	{
		flags |= flag_done;

		bdecode_node const r = m.message.dict_find_dict("r");
		if (!r)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (get_observer())
			{
				get_observer()->log(dht_logger::node
					, "[%p] missing response dict"
					, static_cast<void*>(algorithm()));
			}
#endif
			return;
		}
		look_for_nodes(algorithm()->get_node().protocol_nodes_key(), algorithm()->get_node().protocol(), r,
			[this](node_endpoint const& nep) { algorithm()->get_node().m_table.heard_about(nep.id, nep.ep); });
	}
};

void node::tick()
{
	// every now and then we refresh our own ID, just to keep
	// expanding the routing table buckets closer to us.
	// if m_table.depth() < 4, means routing_table doesn't
	// have enough nodes.
	time_point const now = aux::time_now();
	if (m_last_self_refresh + minutes(10) < now && m_table.depth() < 4)
	{
		node_id target = m_id;
		make_id_secret(target);
		auto const r = std::make_shared<dht::bootstrap>(*this, target, std::bind(&nop));
		r->start();
		m_last_self_refresh = now;
		return;
	}

	node_entry const* ne = m_table.next_refresh();
	if (ne == nullptr) return;

	// this shouldn't happen
	TORRENT_ASSERT(m_id != ne->id);
	if (ne->id == m_id) return;

	int const bucket = 255 - distance_exp(m_id, ne->id);
	TORRENT_ASSERT(bucket < 256);
	send_single_refresh(ne->ep(), bucket, ne->id);
}

void node::send_single_refresh(udp::endpoint const& ep, int const bucket
	, node_id const& id)
{
	TORRENT_ASSERT(id != m_id);
	TORRENT_ASSERT(bucket >= 0);
	TORRENT_ASSERT(bucket <= 255);

	// generate a random node_id within the given bucket
	// TODO: 2 it would be nice to have a bias towards node-id prefixes that
	// are missing in the bucket
	node_id mask = generate_prefix_mask(bucket + 1);
	node_id target = generate_secret_id() & ~mask;
	target |= m_id & mask;

	// create a dummy traversal_algorithm
	auto algo = std::make_shared<traversal_algorithm>(*this, node_id());
	auto o = m_rpc.allocate_observer<ping_observer>(std::move(algo), ep, id);
	if (!o) return;
#if TORRENT_USE_ASSERTS
	o->m_in_constructor = false;
#endif
	entry e;
	e["y"] = "q";

	if (m_table.is_full(bucket))
	{
		// current bucket is full, just ping it.
		e["q"] = "ping";
		m_counters.inc_stats_counter(counters::dht_ping_out);
	}
	else
	{
		// use get_peers instead of find_node. We'll get nodes in the response
		// either way.
		e["q"] = "get_peers";
		e["a"]["info_hash"] = target.to_string();
		m_counters.inc_stats_counter(counters::dht_get_peers_out);
	}

	m_rpc.invoke(e, ep, o);
}

time_duration node::connection_timeout()
{
	time_duration d = m_rpc.tick();
	time_point now(aux::time_now());
	if (now - minutes(2) < m_last_tracker_tick) return d;
	m_last_tracker_tick = now;

	m_storage.tick();

	return d;
}

dht_status node::status() const
{
	std::lock_guard<std::mutex> l(m_mutex);

	dht_status ret;
	ret.our_id = m_id;
	ret.local_endpoint = make_udp(m_sock.get_local_endpoint());
	m_table.status(ret.table);

	for (auto const& r : m_running_requests)
	{
		ret.requests.emplace_back();
		dht_lookup& lookup = ret.requests.back();
		r->status(lookup);
	}
	return ret;
}

std::tuple<int, int, int> node::get_stats_counters() const
{
	int nodes, replacements;
	std::tie(nodes, replacements, std::ignore) = size();
	return std::make_tuple(nodes, replacements, m_rpc.num_allocated_observers());
}

#if TORRENT_ABI_VERSION == 1
// TODO: 2 use the non deprecated function instead of this one
void node::status(session_status& s)
{
	std::lock_guard<std::mutex> l(m_mutex);

	m_table.status(s);
	s.dht_total_allocations += m_rpc.num_allocated_observers();
	for (auto const& r : m_running_requests)
	{
		s.active_requests.emplace_back();
		dht_lookup& lookup = s.active_requests.back();
		r->status(lookup);
	}
}
#endif

bool node::lookup_peers(sha256_hash const& info_hash, entry& reply
	, bool noseed, bool scrape, address const& requester) const
{
	if (m_observer)
		m_observer->get_peers(info_hash);

	// return m_storage.get_peers(info_hash, noseed, scrape, requester, reply);
    return false;
}

entry write_nodes_entry(std::vector<node_entry> const& nodes)
{
	entry r;
	std::back_insert_iterator<std::string> out(r.string());
	for (auto const& n : nodes)
	{
		std::copy(n.id.begin(), n.id.end(), out);
		aux::write_endpoint(n.ep(), out);
	}
	return r;
}

// build response
void node::incoming_request(msg const& m, entry& e)
{
	e = entry(entry::dictionary_t);
	e["y"] = "r";
	e["t"] = m.message.dict_find_string_value("t");

	static key_desc_t const top_desc[] = {
		{"q", bdecode_node::string_t, 0, 0},
		{"ro", bdecode_node::int_t, 0, key_desc_t::optional},
		{"a", bdecode_node::dict_t, 0, key_desc_t::parse_children},
			{"id", bdecode_node::string_t, 32, key_desc_t::last_child},
	};

	bdecode_node top_level[4];
	char error_string[200];
	if (!verify_message(m.message, top_desc, top_level, error_string))
	{
		incoming_error(e, error_string);
		return;
	}

	e["ip"] = aux::endpoint_to_bytes(m.addr);

	bdecode_node const arg_ent = top_level[2];
	bool const read_only = top_level[1] && top_level[1].int_value() != 0;
	node_id const id(top_level[3].string_ptr());

	if (!read_only)
		m_table.heard_about(id, m.addr);

	entry& reply = e["r"];
	m_rpc.add_our_id(reply);

	// mirror back the other node's external port
	reply["p"] = m.addr.port();

	string_view const query = top_level[0].string_value();

	if (m_observer && m_observer->on_dht_request(query, m, e))
		return;

	if (query == "ping")
	{
		m_counters.inc_stats_counter(counters::dht_ping_in);
		// we already have 't' and 'id' in the response
		// no more left to add
	}
	else if (query == "get_peers")
	{
		static key_desc_t const msg_desc[] = {
			{"info_hash", bdecode_node::string_t, 32, 0},
			{"noseed", bdecode_node::int_t, 0, key_desc_t::optional},
			{"scrape", bdecode_node::int_t, 0, key_desc_t::optional},
			{"want", bdecode_node::list_t, 0, key_desc_t::optional},
		};

		bdecode_node msg_keys[4];
		if (!verify_message(arg_ent, msg_desc, msg_keys, error_string))
		{
			m_counters.inc_stats_counter(counters::dht_invalid_get_peers);
			incoming_error(e, error_string);
			return;
		}

		sha256_hash const info_hash(msg_keys[0].string_ptr());

		m_counters.inc_stats_counter(counters::dht_get_peers_in);

		// always return nodes as well as peers
		write_nodes_entries(info_hash, msg_keys[3], reply);

		bool const noseed = msg_keys[1] && msg_keys[1].int_value() != 0;
		bool const scrape = msg_keys[2] && msg_keys[2].int_value() != 0;
		// If our storage is full we want to withhold the write token so that
		// announces will spill over to our neighbors. This widens the
		// perimeter of nodes which store peers for this torrent
		bool const full = lookup_peers(info_hash, reply, noseed, scrape, m.addr.address());
		if (!full) reply["token"] = generate_token(m.addr, info_hash);

#ifndef TORRENT_DISABLE_LOGGING
		if (reply.find_key("values") && m_observer)
		{
			m_observer->log(dht_logger::node, "values: %d"
				, int(reply["values"].list().size()));
		}
#endif
	}
	else if (query == "find_node")
	{
		static key_desc_t const msg_desc[] = {
			{"target", bdecode_node::string_t, 32, 0},
			{"want", bdecode_node::list_t, 0, key_desc_t::optional},
		};

		bdecode_node msg_keys[2];
		if (!verify_message(arg_ent, msg_desc, msg_keys, error_string))
		{
			m_counters.inc_stats_counter(counters::dht_invalid_find_node);
			incoming_error(e, error_string);
			return;
		}

		m_counters.inc_stats_counter(counters::dht_find_node_in);
		sha256_hash const target(msg_keys[0].string_ptr());

		write_nodes_entries(target, msg_keys[1], reply);
	}
	else if (query == "put")
	{
		// the first 2 entries are for both mutable and
		// immutable puts
		static key_desc_t const msg_desc[] = {
			{"token", bdecode_node::string_t, 0, 0},
			{"v", bdecode_node::none_t, 0, 0},
			{"seq", bdecode_node::int_t, 0, key_desc_t::optional},
			// public key
			{"k", bdecode_node::string_t, public_key::len, key_desc_t::optional},
			{"sig", bdecode_node::string_t, signature::len, key_desc_t::optional},
			{"cas", bdecode_node::int_t, 0, key_desc_t::optional},
			{"salt", bdecode_node::string_t, 0, key_desc_t::optional},
		};

		// attempt to parse the message
		// also reject the message if it has any non-fatal encoding errors
		// because put messages contain a signed value they must have correct bencoding
		// otherwise the value will not round-trip without breaking the signature
		bdecode_node msg_keys[7];
		if (!verify_message(arg_ent, msg_desc, msg_keys, error_string)
			|| arg_ent.has_soft_error(error_string))
		{
			m_counters.inc_stats_counter(counters::dht_invalid_put);
			incoming_error(e, error_string);
			return;
		}

		m_counters.inc_stats_counter(counters::dht_put_in);

		// is this a mutable put?
		bool const mutable_put = (msg_keys[2] && msg_keys[3] && msg_keys[4]);

		// public key (only set if it's a mutable put)
		char const* pub_key = nullptr;
		if (msg_keys[3]) pub_key = msg_keys[3].string_ptr();

		// signature (only set if it's a mutable put)
		char const* sign = nullptr;
		if (msg_keys[4]) sign = msg_keys[4].string_ptr();

		// pointer and length to the whole entry
		span<char const> buf = msg_keys[1].data_section();
		if (buf.size() > 1000 || buf.empty())
		{
			m_counters.inc_stats_counter(counters::dht_invalid_put);
			incoming_error(e, "message too big", 205);
			return;
		}

		span<char const> salt;
		if (msg_keys[6])
			salt = {msg_keys[6].string_ptr(), msg_keys[6].string_length()};
		if (salt.size() > 64)
		{
			m_counters.inc_stats_counter(counters::dht_invalid_put);
			incoming_error(e, "salt too big", 207);
			return;
		}

		sha256_hash const target = pub_key
			? item_target_id(salt, public_key(pub_key))
			: item_target_id(buf);

//		std::fprintf(stderr, "%s PUT target: %s salt: %s key: %s\n"
//			, mutable_put ? "mutable":"immutable"
//			, aux::to_hex(target).c_str()
//			, salt.second > 0 ? std::string(salt.first, salt.second).c_str() : ""
//			, pk ? aux::to_hex(pk).c_str() : "");

		// verify the write-token. tokens are only valid to write to
		// specific target hashes. it must match the one we got a "get" for
		if (!verify_token(msg_keys[0].string_value(), target, m.addr))
		{
			m_counters.inc_stats_counter(counters::dht_invalid_put);
			incoming_error(e, "invalid token");
			return;
		}

		if (!mutable_put)
		{
			m_storage.put_immutable_item(target, buf, m.addr.address());
		}
		else
		{
			// mutable put, we must verify the signature
			sequence_number const seq(msg_keys[2].int_value());
			public_key const pk(pub_key);
			signature const sig(sign);

			if (seq < sequence_number(0))
			{
				m_counters.inc_stats_counter(counters::dht_invalid_put);
				incoming_error(e, "invalid (negative) sequence number");
				return;
			}

			// msg_keys[4] is the signature, msg_keys[3] is the public key
			if (!verify_mutable_item(buf, salt, seq, pk, sig))
			{
				m_counters.inc_stats_counter(counters::dht_invalid_put);
				incoming_error(e, "invalid signature", 206);
				return;
			}

			TORRENT_ASSERT(signature::len == msg_keys[4].string_length());

			sequence_number item_seq;
			if (!m_storage.get_mutable_item_seq(target, item_seq))
			{
				m_storage.put_mutable_item(target, buf, sig, seq, pk, salt
					, m.addr.address());
			}
			else
			{
				// this is the "cas" field in the put message
				// if it was specified, we MUST make sure the current sequence
				// number matches the expected value before replacing it
				// this is critical for avoiding race conditions when multiple
				// writers are accessing the same slot
				if (msg_keys[5] && item_seq.value != msg_keys[5].int_value())
				{
					m_counters.inc_stats_counter(counters::dht_invalid_put);
					incoming_error(e, "CAS mismatch", 301);
					return;
				}

				if (item_seq > seq)
				{
					m_counters.inc_stats_counter(counters::dht_invalid_put);
					incoming_error(e, "old sequence number", 302);
					return;
				}

				m_storage.put_mutable_item(target, buf, sig, seq, pk, salt
					, m.addr.address());
			}
		}

		m_table.node_seen(id, m.addr, 0xffff);
	}
	else if (query == "get")
	{
		static key_desc_t const msg_desc[] = {
			{"seq", bdecode_node::int_t, 0, key_desc_t::optional},
			{"target", bdecode_node::string_t, 32, 0},
			{"want", bdecode_node::list_t, 0, key_desc_t::optional},
		};

		// k is not used for now

		// attempt to parse the message
		bdecode_node msg_keys[3];
		if (!verify_message(arg_ent, msg_desc, msg_keys, error_string))
		{
			m_counters.inc_stats_counter(counters::dht_invalid_get);
			incoming_error(e, error_string);
			return;
		}

		m_counters.inc_stats_counter(counters::dht_get_in);
		sha256_hash const target(msg_keys[1].string_ptr());

//		std::fprintf(stderr, "%s GET target: %s\n"
//			, msg_keys[1] ? "mutable":"immutable"
//			, aux::to_hex(target).c_str());

		reply["token"] = generate_token(m.addr, target);

		// always return nodes as well as peers
		write_nodes_entries(target, msg_keys[2], reply);

		// if the get has a sequence number it must be for a mutable item
		// so don't bother searching the immutable table
		if (!msg_keys[0])
		{
			if (!m_storage.get_immutable_item(target, reply)) // ok, check for a mutable one
			{
				m_storage.get_mutable_item(target, sequence_number(0)
					, true, reply);
			}
		}
		else
		{
			m_storage.get_mutable_item(target
				, sequence_number(msg_keys[0].int_value()), false
				, reply);
		}
	}
	else
	{
		// if we don't recognize the message but there's a
		// 'target' or 'info_hash' in the arguments, treat it
		// as find_node to be future compatible
		bdecode_node target_ent = arg_ent.dict_find_string("target");
		if (!target_ent || target_ent.string_length() != 32)
		{
			target_ent = arg_ent.dict_find_string("info_hash");
			if (!target_ent || target_ent.string_length() != 32)
			{
				incoming_error(e, "unknown message");
				return;
			}
		}

		sha256_hash const target(target_ent.string_ptr());
		// always return nodes as well as peers
		write_nodes_entries(target, arg_ent.dict_find_list("want"), reply);
	}
}

// TODO: limit number of entries in the result
void node::write_nodes_entries(sha256_hash const& info_hash
	, bdecode_node const& want, entry& r)
{
	// if no wants entry was specified, include a nodes
	// entry based on the protocol the request came in with
	if (want.type() != bdecode_node::list_t)
	{
		std::vector<node_entry> const n = m_table.find_node(info_hash, {});
		r[protocol_nodes_key()] = write_nodes_entry(n);
		return;
	}

	// if there is a wants entry then we may need to reach into
	// another node's routing table to get nodes of the requested type
	// we use a map maintained by the owning dht_tracker to find the
	// node associated with each string in the want list, which may
	// include this node
	for (int i = 0; i < want.list_size(); ++i)
	{
		bdecode_node wanted = want.list_at(i);
		if (wanted.type() != bdecode_node::string_t)
			continue;
		node* wanted_node = m_get_foreign_node(info_hash, wanted.string_value());
		if (!wanted_node) continue;
		std::vector<node_entry> const n = wanted_node->m_table.find_node(info_hash, {});
		r[wanted_node->protocol_nodes_key()] = write_nodes_entry(n);
	}
}

node::protocol_descriptor const& node::map_protocol_to_descriptor(udp const protocol)
{
	static std::array<protocol_descriptor, 2> const descriptors =
	{{
		{udp::v4(), "n4", "nodes"},
		{udp::v6(), "n6", "nodes6"}
	}};

	auto const iter = std::find_if(descriptors.begin(), descriptors.end()
		, [&protocol](protocol_descriptor const& d) { return d.protocol == protocol; });

	if (iter == descriptors.end())
	{
		TORRENT_ASSERT_FAIL();
		aux::throw_ex<std::out_of_range>("unknown protocol");
	}

	return *iter;
}

} // namespace libtorrent::dht
