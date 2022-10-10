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

#include "libTAU/config.hpp"

#include <utility>
#include <cinttypes> // for PRId64 et.al.
#include <functional>
#include <tuple>
#include <array>
#include <chrono>
#include <random>

#ifndef TORRENT_DISABLE_LOGGING
#include "libTAU/hex.hpp" // to_hex
#endif

#include <libTAU/aux_/common.h> // for utcTime()
#include <libTAU/aux_/socket_io.hpp>
#include <libTAU/session_status.hpp>
#include "libTAU/bencode.hpp"
#include "libTAU/crypto.hpp"
#include "libTAU/hasher.hpp"
#include "libTAU/aux_/random.hpp"
#include <libTAU/assert.hpp>
#include <libTAU/aux_/time.hpp>
#include "libTAU/aux_/throw.hpp"
#include "libTAU/aux_/session_settings.hpp"
#include "libTAU/alert_types.hpp" // for dht_lookup
#include "libTAU/performance_counters.hpp" // for counters
#include "libTAU/aux_/ip_helpers.hpp" // for is_v4

#include "libTAU/kademlia/node.hpp"
#include "libTAU/kademlia/dht_observer.hpp"
#include "libTAU/kademlia/io.hpp"
#include "libTAU/kademlia/dht_settings.hpp"

#include "libTAU/kademlia/refresh.hpp"
#include "libTAU/kademlia/get_peers.hpp"
#include "libTAU/kademlia/get_item.hpp"
#include "libTAU/kademlia/keep.hpp"
#include "libTAU/kademlia/msg.hpp"
#include <libTAU/kademlia/put_data.hpp>
#include <libTAU/kademlia/relay.hpp>
#include <libTAU/kademlia/version.hpp>

using namespace std::placeholders;
using namespace std::chrono;

namespace libTAU::dht {

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
	, dht_storage_interface& storage
	, std::shared_ptr<account_manager> account_manager
	, bs_nodes_storage_interface& bs_nodes_storage)
	: m_settings(settings)
	, m_id(nid)
	, m_table(m_id, aux::is_v4(sock.get_local_endpoint()) ? udp::v4() : udp::v6(), 8, settings, observer)
	, m_incoming_table(m_id, aux::is_v4(sock.get_local_endpoint()) ? udp::v4() : udp::v6(), settings, m_table, observer)
	, m_rpc(m_id, m_settings, m_table, m_incoming_table, sock, sock_man, observer)
	, m_sock(sock)
	, m_sock_man(sock_man)
	, m_get_foreign_node(std::move(get_foreign_node))
	, m_observer(observer)
	, m_protocol(map_protocol_to_descriptor(aux::is_v4(sock.get_local_endpoint()) ? udp::v4() : udp::v6()))
	, m_last_tracker_tick(aux::time_now())
	, m_last_self_refresh(min_time())
	, m_last_ping(min_time())
	, m_last_keep(min_time())
	, m_counters(cnt)
	, m_storage(storage)
	, m_account_manager(std::move(account_manager))
	, m_bs_nodes_storage(bs_nodes_storage)
	, m_bs_nodes_learner(m_id, m_settings, m_table, bs_nodes_storage, observer)
{
	aux::crypto_random_bytes(m_secret[0]);
	aux::crypto_random_bytes(m_secret[1]);
}

node::~node() = default;

int node::branch_factor() const { return m_settings.get_int(settings_pack::dht_search_branching); }

int node::invoke_window() const { return m_settings.get_int(settings_pack::dht_invoke_window); }

int node::invoke_limit() const { return m_settings.get_int(settings_pack::dht_invoke_limit); }

int node::bootstrap_interval() const { return m_settings.get_int(settings_pack::dht_bootstrap_interval); }

int node::ping_interval() const { return m_settings.get_int(settings_pack::dht_ping_interval); }

int node::keep_interval() const { return m_settings.get_int(settings_pack::dht_keep_interval); }

bool node::verify_token(string_view token, sha256_hash const& info_hash
	, udp::endpoint const& addr) const
{
	// For libtau, there is no need for getting token before putting.
	// Any token is OK.
	return true;

	/*
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
	*/
}

std::string node::generate_token(udp::endpoint const& addr
	, sha256_hash const& info_hash)
{
	/*
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
	 */

	return libtau_token;
}

void node::prepare_bootstrap_nodes(std::vector<node_entry>& nodes
	, node_id const& target, bool first_bootstrap)
{
	if (first_bootstrap)
	{
		std::vector<node_entry> community_nodes(m_table.begin(), m_table.end());
		auto rng = std::default_random_engine {};
		std::shuffle(std::begin(community_nodes), std::end(community_nodes), rng);

		// copy first 4 nodes
		int i = 0;
		for (auto it = community_nodes.begin(), end = community_nodes.end()
			; it != end && i < 4; ++it, ++i)
		{
			nodes.push_back(*it);

#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer != nullptr
				&& m_observer->should_log(dht_logger::node, aux::LOG_DEBUG))
			{
				m_observer->log(dht_logger::node, "add bs tau community node:%s, %s"
					, aux::to_hex(it->id).c_str()
					, aux::print_endpoint(it->ep()).c_str());
			}
#endif
		}

		std::vector<bs_node_entry> referred_nodes;
		m_bs_nodes_learner.get_bootstrap_nodes(referred_nodes, 4);
		for (auto& bsn : referred_nodes)
		{
			nodes.push_back(node_entry(bsn.m_nid, bsn.m_ep));

#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer != nullptr
				&& m_observer->should_log(dht_logger::node, aux::LOG_DEBUG))
			{
				m_observer->log(dht_logger::node, "add bs referred node:%s, %s"
					, aux::to_hex(bsn.m_nid).c_str()
					, aux::print_endpoint(bsn.m_ep).c_str());
			}
#endif
		}
	}
	else
	{
		std::vector<bs_node_entry> referred_nodes;
		m_bs_nodes_learner.get_bootstrap_nodes(referred_nodes, 4);
		for (auto& bsn : referred_nodes)
		{
			nodes.push_back(node_entry(bsn.m_nid, bsn.m_ep));

#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer != nullptr
				&& m_observer->should_log(dht_logger::node, aux::LOG_DEBUG))
			{
				m_observer->log(dht_logger::node, "add bs referred node:%s, %s"
					, aux::to_hex(bsn.m_nid).c_str()
					, aux::print_endpoint(bsn.m_ep).c_str());
			}
#endif
		}

		std::vector<node_entry> live_nodes = m_table.find_node(
			target, routing_table::include_pinged, 8 - referred_nodes.size());

		if (live_nodes.size() < 8 - referred_nodes.size())
		{
			live_nodes.clear();
			live_nodes = m_table.find_node(target
				, routing_table::include_failed, 8 - referred_nodes.size());
		}

		for (auto& n : live_nodes)
		{
			nodes.push_back(n);

#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer != nullptr
				&& m_observer->should_log(dht_logger::node, aux::LOG_DEBUG))
			{
				m_observer->log(dht_logger::node, "add bs live node:%s, %s"
					, aux::to_hex(n.id).c_str()
					, aux::print_endpoint(n.ep()).c_str());
			}
#endif
		}
	}
}

void node::bootstrap(std::vector<node_entry> const& nodes
	, find_data::nodes_callback const& f)
{
	node_id target = m_id;
	make_id_secret(target);

	auto r = std::make_shared<dht::bootstrap>(*this, target, f);
	m_last_self_refresh = aux::time_now();

#ifndef TORRENT_DISABLE_LOGGING
	int count = 0;
#endif

	std::vector<node_entry> bs_nodes(nodes.begin(), nodes.end());

	if (nodes.size() == 0)
	{
		prepare_bootstrap_nodes(bs_nodes, target, true);
	}

	for (auto const& n : bs_nodes)
	{
#ifndef TORRENT_DISABLE_LOGGING
		++count;
#endif
		r->add_entry(n.id, n.ep(), observer::flag_initial);
	}

#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr)
		m_observer->log(dht_logger::node, "bootstrapping with %d nodes", count);
#endif
	r->start();
}

void node::update_node_id(node_id const& id)
{
	m_id = id;
	m_table.update_node_id(m_id);
	m_rpc.update_node_id(m_id);
	m_incoming_table.update_node_id(m_id);
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

void node::incoming_decryption_error(aux::listen_socket_handle const& s
	, udp::endpoint const& ep, sha256_hash const& pk)
{
	// ignore packets arriving on a different interface than the one we're
	// associated with
	if (s != m_sock) return;

	entry e;

	e["y"] = "e";
	entry::list_type& l = e["e"].list();
	l.emplace_back(protocol_decryption_error_code);
	l.emplace_back(protocol_decryption_error);

	entry& a = e["a"];

	m_sock_man->send_packet(m_sock, e, ep, pk);
}

void node::handle_decryption_error(msg const& m)
{
	bdecode_node const a_ent = m.message.dict_find_dict("a");
	if (!a_ent)
	{
		return;
	}

	// TODO: update routing table
}

void node::incoming(aux::listen_socket_handle const& s, msg const& m, node_id const& from)
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

	// version match or not
	bdecode_node const version_ent = m.message.dict_find_string("v");
	if (!version_ent || version_ent.string_length() != dht::version_length)
	{
		// entry e;
		// incoming_error(e, "version format error", protocol_version_error_code);
		// m_sock_man->send_packet(m_sock, e, m.addr, from);
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer != nullptr
			&& m_observer->should_log(dht_logger::node, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::node, "version fromat error");
		}
#endif
		return;
	}
	std::string ver(version_ent.string_ptr(), version_ent.string_length());
	if (!dht::version_match(ver))
	{
		// entry e;
		// incoming_error(e, "version mismatch", protocol_version_mismatch_error_code);
		// m_sock_man->send_packet(m_sock, e, m.addr, from);
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer != nullptr
			&& m_observer->should_log(dht_logger::node, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::node, "version mismatch, peer:%s, ourself:%s"
				, ver.c_str(), dht::version.c_str());
		}
#endif
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
			m_rpc.incoming(m, from);
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

			/*
			if (!m_sock_man->has_quota())
			{
			if (!m_sock_man->has_quota())
			{
				m_counters.inc_stats_counter(counters::dht_messages_in_dropped);
				return;
			}
			 */

			entry e;
			node_id to;
			bool need_response;
			bool need_push;
			udp::endpoint to_ep;
			// maybe 'keep' trigger 'push' operation.
			node_id push_candidate;

			std::tie(need_response, need_push)
					= incoming_request(m, e, from, &to, &to_ep, push_candidate);
			if (need_response)
			{
				m_sock_man->send_packet(m_sock, e, m.addr, from);
			}
			if (need_push)
			{
				// push message
				push(to, to_ep, m, from);
			}
			else if (from == push_candidate)
			{
				// max items number pushed once 'keep'
				constexpr int max_items_once = 8;

				// find relay from storage and push
				sha256_hash key;
				bool item_exists = false;

				for (int i = 0; i < max_items_once; i++)
				{
					key.clear();
					item_exists = m_storage.get_random_relay_entry(from, key);
					if (!item_exists)
					{
#ifndef TORRENT_DISABLE_LOGGING
						if (m_observer != nullptr
							&& m_observer->should_log(dht_logger::node, aux::LOG_NOTICE))
						{
							m_observer->log(dht_logger::node, "No relay entry pushed(%d):%s"
								, i , aux::to_hex(from).c_str());
						}
#endif
						break;
					}
					else
					{
						entry re;
						bool ok = m_storage.get_relay_entry(key, re);
						if (ok)
						{
							// push item
#ifndef TORRENT_DISABLE_LOGGING
							if (m_observer != nullptr
								&& m_observer->should_log(dht_logger::node, aux::LOG_INFO))
							{
								m_observer->log(dht_logger::node, "Push relay entry(%d) :%s to %s"
									, i , aux::to_hex(key).c_str()
									, aux::to_hex(from).c_str());
							}
#endif

							push(from, m.addr, re);

							// remove this item
							m_storage.remove_relay_entry(key);
						}
					}
				}
			}
			break;
		}
		case 'p':
		{
			TORRENT_ASSERT(m.message.dict_find_string_value("y") == "p");

			// ignore packets arriving on a different interface than the one we're
			// associated with
			if (s != m_sock) return;

			entry e;
			item i;
			bool need_resp = incoming_push(m, e, from, i);
			if (need_resp)
			{
				// Don't respond to relay node
				// m_sock_man->send_packet(m_sock, e, m.addr, from);
			}
			if (m_observer && !i.empty()) m_observer->on_dht_item(i);

			break;
		}
		case 'h': // hop
		{
			TORRENT_ASSERT(m.message.dict_find_string_value("y") == "h");

			// ignore packets arriving on a different interface than the one we're
			// associated with
			if (s != m_sock) return;

			entry resp;
			entry payload;
			node_id to;
			udp::endpoint to_ep;
			node_id sender;
			std::string decrypted_payload;

			bool need_relay = incoming_relay(m, resp, payload, &to,
					&to_ep, sender, from, decrypted_payload);
			if (to != m_id)
			{
				m_sock_man->send_packet(m_sock, resp, m.addr, from);
			}

			if (need_relay)
			{
				if (to == m_id)
				{
					// TODO: transfer payload
					if (m_observer) m_observer->on_dht_relay(
						public_key(sender.data()), payload);
				}
				else
				{
					relay(to, to_ep, m, from);
				}
			}

			break;
		}
		case 'e':
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer != nullptr
				&& m_observer->should_log(dht_logger::node, aux::LOG_ERR))
			{
				bdecode_node const err = m.message.dict_find_list("e");
				if (err && err.list_size() >= 2
					&& err.list_at(0).type() == bdecode_node::int_t
					&& err.list_at(1).type() == bdecode_node::string_t)
				{
					m_observer->log(dht_logger::node, "INCOMING ERROR: (%" PRId64 ") %s"
						, err.list_int_value_at(0)
						, std::string(err.list_string_value_at(1)).c_str());
					/*
					if (err.list_int_value_at(0) == protocol_decryption_error_code)
					{
						handle_decryption_error(m);
						break;
					}*/
				}
				else
				{
					m_observer->log(dht_logger::node, "INCOMING ERROR (malformed)");
				}
			}
#endif
			m_rpc.incoming(m, from);
			break;
		}
	}
}

void node::add_router_node(node_entry const& router)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		m_observer->log(dht_logger::node, "adding router node: %s"
			, aux::print_endpoint(router.ep()).c_str());
	}
#endif
	m_table.add_router_node(router);
}

void node::add_bootstrap_nodes(std::vector<node_entry> const& nodes)
{
	std::vector<bs_node_entry> bs_nodes;
	for (auto& n: nodes)
	{
		bs_nodes.push_back(bs_node_entry(n.id, n.ep()));
	}

	m_bs_nodes_learner.add_bootstrap_nodes(bs_nodes);
}

void node::add_node(node_entry const& node)
{
	if (!native_address(node.ep())) return;
	// ping the node, and if we get a reply, it
	// will be added to the routing table
	send_single_refresh(node.ep(), m_table.num_active_buckets(), node.id);
}

void node::get_item(sha256_hash const& target, std::function<void(item const&)> f)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		m_observer->log(dht_logger::node, "starting get for [ hash: %s ]"
			, aux::to_hex(target).c_str());
	}
#endif

	auto ta = std::make_shared<dht::get_item>(*this, target
		, std::bind(f, _1), find_data::nodes_callback());
	ta->start();
}

void node::get_item(sha256_hash const& target
	, std::vector<node_entry> const& eps
	, std::function<void(item const&)> f)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		m_observer->log(dht_logger::node, "starting get for [ hash: %s, target endpoints:%" PRId64 " ]"
			, aux::to_hex(target).c_str(), eps.size());
	}
#endif

	auto ta = std::make_shared<dht::get_item>(*this, target
		, std::bind(f, _1), find_data::nodes_callback());
	// set target endpoints instead of depth traversal
	ta->set_direct_endpoints(eps);
	// invoke as soon as possible
	ta->set_invoke_window(eps.size());
	ta->set_invoke_limit(eps.size());
	ta->start();
}

void node::get_item(public_key const& pk, std::string const& salt
	, std::int64_t timestamp, std::function<void(item const&, bool)> f)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		char hex_key[65];
		char hex_salt[129]; // 64*2 + 1
		aux::to_hex(pk.bytes, hex_key);
		aux::to_hex(salt, hex_salt);
		m_observer->log(dht_logger::node, "starting get for [ key: %s, salt: %s ]"
			, hex_key, hex_salt);
	}
#endif

	auto ta = std::make_shared<dht::get_item>(*this, pk, salt, std::move(f)
		, find_data::nodes_callback());
	ta->set_timestamp(timestamp);
	// TODO: removed
	ta->set_fixed_distance(256);
	ta->start();
}

void node::get_item(public_key const& pk, std::string const& salt
	, std::int64_t timestamp, std::int8_t alpha, std::int8_t invoke_window
	, std::int8_t invoke_limit, std::function<void(item const&, bool)> f)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		char hex_key[65];
		char hex_salt[129]; // 64*2 + 1
		aux::to_hex(pk.bytes, hex_key);
		aux::to_hex(salt, hex_salt);
		m_observer->log(dht_logger::node, "start getting for [k:%s, s:%s, beta:%d, limit:%d]"
			, hex_key, hex_salt, invoke_window, invoke_limit);
	}
#endif

	auto ta = std::make_shared<dht::get_item>(*this, pk, salt, std::move(f)
		, find_data::nodes_callback());
	ta->set_timestamp(timestamp);
	ta->set_invoke_window(invoke_window);
	ta->set_invoke_limit(invoke_limit);
	// TODO: removed
	ta->set_fixed_distance(256);
	ta->start();
}

namespace {

void put(std::vector<std::pair<node_entry, std::string>> const& nodes
	, std::shared_ptr<put_data> const& ta)
{
	std::vector<node_entry> eps;
	for (auto& n : nodes)
	{
		eps.push_back(n.first);
	}

	ta->set_direct_endpoints(eps);
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

void construct_mutable_item(item& i
	, entry const& value
	, span<char const> salt
	, public_key const& pk
	, secret_key const& sk)
{
	entry v = value;
	std::vector<char> buf;
	bencode(std::back_inserter(buf), v);
	std::int64_t ts = libTAU::aux::utcTime();
	dht::signature sign = sign_mutable_item(buf, salt
		, dht::timestamp(ts), pk, sk);
	i.assign(std::move(v), salt, dht::timestamp(ts), pk, sign);
}

} // namespace

void node::put_item(sha256_hash const& target
	, entry const& data
	, public_key const& to
	, std::function<void(int)> f)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		m_observer->log(dht_logger::node, "starting put for [ hash: %s ]"
			, aux::to_hex(target).c_str());
	}
#endif

	/*
	item i;
	i.assign(data);
	auto put_ta = std::make_shared<dht::put_data>(*this, target, to, std::bind(f, _2));
	put_ta->set_data(std::move(i));

	auto ta = std::make_shared<dht::get_item>(*this, target
		, get_item::data_callback(), std::bind(&put, _1, put_ta));
	ta->start();
	*/
}

void node::put_item(sha256_hash const& target
	, entry const& data
	, std::vector<node_entry> const& eps
	, public_key const& to
	, std::function<void(int)> f)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		m_observer->log(dht_logger::node, "starting put for [ hash: %s, target endpoints:%" PRId64 " ]"
			, aux::to_hex(target).c_str(), eps.size());
	}
#endif

	/*
	item i;
	i.assign(data);

	auto ta = std::make_shared<dht::put_data>(*this, target, to, std::bind(f, _2));
	ta->set_data(std::move(i));
	ta->set_direct_endpoints(eps);
	ta->set_discard_response(true);
	ta->start();
	*/
}

void node::put_item(public_key const& pk
	, std::string const& salt
	, public_key const& to
	, std::function<void(item const&, int)> f
	, std::function<void(item&)> data_cb)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		char hex_key[65];
		char hex_salt[129]; // 64*2 + 1
		aux::to_hex(pk.bytes, hex_key);
		aux::to_hex(salt, hex_salt);
		m_observer->log(dht_logger::node, "starting put for [ key: %s, salt:%s ]"
			, hex_key, hex_salt);
	}
#endif

	/*
	item i(pk, salt);
	data_cb(i);

	auto put_ta = std::make_shared<dht::put_data>(*this, item_target_id(to), to, f);
	put_ta->set_data(std::move(i));

	put_ta->start();
	*/
}

void node::put_item(public_key const& pk
	, std::string const& salt
	, public_key const& to
	, std::int8_t alpha
	, std::int8_t beta
	, std::int8_t invoke_limit
	, bool cache
	, std::function<void(item const&, int)> f
	, std::function<void(item&)> data_cb)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		char hex_key[65];
		char hex_salt[129]; // 64*2 + 1
		aux::to_hex(pk.bytes, hex_key);
		aux::to_hex(salt, hex_salt);
		m_observer->log(dht_logger::node
			, "starting put for [ key: %s, salt:%s, beta:%d, invoke-limit:%d, cache:%s ]"
			, hex_key, hex_salt, beta, invoke_limit, cache ? "true" : "false");
	}
#endif

	/*
	item i(pk, salt);
	data_cb(i);

	auto put_ta = std::make_shared<dht::put_data>(*this, item_target_id(to), to, f);
	put_ta->set_data(std::move(i));
	put_ta->set_invoke_window(beta);
	put_ta->set_invoke_limit(invoke_limit);
	put_ta->set_cache(cache);
	// TODO: removed
	put_ta->set_fixed_distance(256);

	put_ta->start();
	*/
}

void node::put_item(public_key const& pk
	, std::string const& salt
	, public_key const& to
	, std::int8_t alpha
	, std::int8_t beta
	, std::int8_t invoke_limit
	, bool cache
	, std::function<void(item const&, int)> f
	, std::function<void(item&)> data_cb
	, std::function<void(std::vector<std::pair<node_entry, bool>> const&)> ncb)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		char hex_key[65];
		char hex_salt[129]; // 64*2 + 1
		aux::to_hex(pk.bytes, hex_key);
		aux::to_hex(salt, hex_salt);
		m_observer->log(dht_logger::node
			, "starting put for [ key: %s, salt:%s, beta:%d, invoke-limit:%d, cache:%s ]"
			, hex_key, hex_salt, beta, invoke_limit, cache ? "true" : "false");
	}
#endif

	/*
	item i(pk, salt);
	data_cb(i);

	auto put_ta = std::make_shared<dht::put_data>(*this, item_target_id(to), to, f, ncb);
	put_ta->set_data(std::move(i));
	put_ta->set_invoke_window(beta);
	put_ta->set_invoke_limit(invoke_limit);
	put_ta->set_cache(cache);
	put_ta->set_hit_limit(m_settings.get_int(settings_pack::dht_hit_limit));
	// TODO: removed
	put_ta->set_fixed_distance(256);

	put_ta->start();
	*/
}

void node::put_item(public_key const& pk
	, std::string const& salt
	, entry const& data
	, std::int8_t alpha
	, std::int8_t invoke_window
	, std::int8_t invoke_limit
	, std::function<void(item const&, int)> f)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		char hex_key[65];
		char hex_salt[129]; // 64*2 + 1
		aux::to_hex(pk.bytes, hex_key);
		aux::to_hex(salt, hex_salt);
		m_observer->log(dht_logger::node
			, "starting put for [ key: %s, salt:%s, invoke_window:%d, invoke-limit:%d]"
			, hex_key, hex_salt, invoke_window, invoke_limit);
	}
#endif

	item i(pk, salt);
	construct_mutable_item(i, data, salt
		, m_account_manager->pub_key(), m_account_manager->priv_key());

	auto put_ta = std::make_shared<dht::put_data>(*this, item_target_id(salt, pk), f);
	put_ta->set_data(std::move(i));
	put_ta->set_invoke_window(invoke_window);
	put_ta->set_invoke_limit(invoke_limit);
	// TODO: removed
	put_ta->set_fixed_distance(256);

	put_ta->start();
}

void node::send(public_key const& to
	, entry const& payload
	, std::int8_t alpha
	, std::int8_t beta
	, std::int8_t invoke_limit
	, std::function<void(entry const&, int)> cb)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		char hex_to[65];
		aux::to_hex(to.bytes, hex_to);
		m_observer->log(dht_logger::node, "starting sending to: %s", hex_to);
    }
#endif

	/*
	sha256_hash const& dest = item_target_id(to);
	auto ta = std::make_shared<dht::relay>(*this, dest, cb);

	ta->set_payload(std::move(payload));
	ta->set_invoke_window(beta);
	ta->set_invoke_limit(invoke_limit);
	ta->set_hit_limit(m_settings.get_int(settings_pack::dht_hit_limit));
	// TODO: removed
	ta->set_fixed_distance(256);

	// find relay aux info
	std::vector<node_entry> l;
	std::vector<node_entry> aux_nodes = m_table.find_node(
		m_id, routing_table::include_pinged);
	auto const new_end = std::remove_if(aux_nodes.begin(), aux_nodes.end()
		, [&](node_entry const& ne) { return ne.id == dest; });
	aux_nodes.erase(new_end, aux_nodes.end());
	if (aux_nodes.size() > 0)
	{
		std::uint32_t const random_max = aux_nodes.size() - 1;
		std::uint32_t const r = aux::random(random_max);
		l.push_back(aux_nodes[r]);
	}
	ta->add_relays_nodes(l);

	ta->start();
	*/
}

void node::send(public_key const& to
	, entry const& payload
	, std::int8_t alpha
	, std::int8_t beta
	, std::int8_t invoke_limit
	, std::int8_t hit_limit
	, std::function<void(entry const& payload
		, std::vector<std::pair<node_entry, bool>> const& nodes)> cb)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		char hex_to[65];
		aux::to_hex(to.bytes, hex_to);
		m_observer->log(dht_logger::node, "starting sending to: %s", hex_to);
	}
#endif

	sha256_hash const& dest = item_target_id(to);

	// find relay aux info
	std::vector<node_entry> l;
	std::vector<node_entry> aux_nodes = m_table.find_node(
		m_id, routing_table::include_pinged);
	// remove the target endpoint from aux nodes
	auto const new_end = std::remove_if(aux_nodes.begin(), aux_nodes.end()
		, [&](node_entry const& ne) { return ne.id == dest; });
	aux_nodes.erase(new_end, aux_nodes.end());
	if (aux_nodes.size() > 0)
	{
		std::uint32_t const random_max = aux_nodes.size() - 1;
		std::uint32_t const r = aux::random(random_max);
		l.push_back(aux_nodes[r]);
	}

	// encode aux nodes
	entry aux_nodes_entry;
	std::string encoding_aux_nodes;
	if (!l.empty())
	{
		aux_nodes_entry = write_nodes_entry(l);
		bencode(std::back_inserter(encoding_aux_nodes), aux_nodes_entry);
	}

	// encoding payload
	std::string encoding_payload;
	bencode(std::back_inserter(encoding_payload), payload);
	if (encoding_payload.size() > 80)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::node, "payload is too large: %d", encoding_payload.size());
		}
#endif

		std::vector<std::pair<node_entry, bool>> empty_nodes;
		cb(payload, empty_nodes);
		return;
	}

	// sign relay payload and aux_nodes
	relay_hmac hmac = gen_relay_hmac(encoding_payload, encoding_aux_nodes);

	auto ta = std::make_shared<dht::relay>(*this, dest, payload
			, aux_nodes_entry, hmac, cb);

	// encypt payload
	std::string encypt_err;
	bool result = encrypt(to, encoding_payload, ta->encrypted_payload(), encypt_err);
	if (!result)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_ERR))
		{
			m_observer->log(dht_logger::node, "send encryption err: %s", encypt_err.c_str());
		}
#endif

		std::vector<std::pair<node_entry, bool>> empty_nodes;
		cb(payload, empty_nodes);

		return;
	}

	ta->set_invoke_window(beta);
	ta->set_invoke_limit(invoke_limit);
	ta->set_hit_limit(hit_limit);
	// TODO: removed
	ta->set_fixed_distance(256);

	ta->start();
}

void node::get_peers(public_key const& pk, std::string const& salt)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		char hex_key[65];
		char hex_salt[129]; // 64*2 + 1
		aux::to_hex(pk.bytes, hex_key);
		aux::to_hex(salt, hex_salt);
		m_observer->log(dht_logger::node, "starting get_peers for [ key: %s, salt: %s ]"
			, hex_key, hex_salt);
	}
#endif

	auto ta = std::make_shared<dht::get_peers>(*this, item_target_id(salt, pk)
		, get_peers::data_callback(), find_data::nodes_callback(), false);
	ta->start();
}

void node::find_live_nodes(node_id const& id
	, std::vector<node_entry>& l
	, int count)
{
	auto nes = m_table.find_node(id, routing_table::include_pinged, count);

	for (auto& ne : nes)
	{
		l.push_back(ne);
	}

#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		m_observer->log(dht_logger::node, "find node for [ hash: %s nodes:%d ]"
			, aux::to_hex(id).c_str(), int(l.size()));
	}
#endif
}

struct ping_observer : observer
{
	ping_observer(
		std::shared_ptr<traversal_algorithm> algorithm
		, udp::endpoint const& ep, node_id const& id)
		: observer(std::move(algorithm), ep, id)
	{}

	// parses out "nodes"
	void reply(msg const& m, node_id const& from) override
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
	// libtorrent:
	// every now and then we refresh our own ID, just to keep
	// expanding the routing table buckets closer to us.
	// if m_table.depth() < 4, means routing_table doesn't
	// have enough nodes.
	//
	// libTAU:
	// every now and then we refresh our own ID, just to keep
	// expanding the routing table buckets closer to us.
	// So by these nodes closer to us other nodes can send data by 'push' protocol. 
	time_point const now = aux::time_now();
	int live_nodes_count;
	std::tie(live_nodes_count, std::ignore, std::ignore) = size();
	if (m_last_self_refresh + seconds(bootstrap_interval()) < now
		&& live_nodes_count < 100 /*&& m_table.depth() < 4*/)
	{
		node_id target = m_id;
		make_id_secret(target);

		auto const r = std::make_shared<dht::bootstrap>(*this, target, std::bind(&nop));

		std::vector<node_entry> nodes;
		prepare_bootstrap_nodes(nodes, target, false);
		for (auto const& n : nodes)
		{
			r->add_entry(n.id, n.ep(), observer::flag_initial);
		}

		// set referrable nodes' max XOR distance into 256
		r->set_fixed_distance(256);
		r->start();
		m_last_self_refresh = now;
		return;
	}

	if (m_last_keep + seconds(keep_interval()) < now)
	{
		auto const r = std::make_shared<dht::keep>(*this, m_id);
		r->set_invoke_window(8);
		r->set_invoke_limit(8);
		r->set_discard_response(true);
		r->start();
		m_last_keep = now;
		return;
	}

	if (m_last_ping + seconds(ping_interval()) > now) return;

	node_entry const* ne = m_table.next_refresh();
	if (ne == nullptr) return;

	// this shouldn't happen
	TORRENT_ASSERT(m_id != ne->id);
	if (ne->id == m_id) return;

	int const bucket = 255 - distance_exp(m_id, ne->id);
	TORRENT_ASSERT(bucket < 256);
	send_single_refresh(ne->ep(), bucket, ne->id);
	m_last_ping = now;
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
/*
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_DEBUG))
	{
		auto x = std::chrono::duration_cast<std::chrono::milliseconds>(d);
		m_observer->log(dht_logger::node, "connection_timeout called, duration:%" PRId64 " ms"
			, x.count());
	}
#endif
*/

	std::size_t orig_size = m_relay_pkt_deduplicater.size();
	if (orig_size > 0)
	{
		// std::vector<std::int64_t> before;
		// std::vector<std::int64_t> after;
		// m_relay_pkt_deduplicater.get_all_timestamps(before);
		m_relay_pkt_deduplicater.tick(relay_pkt_timeout);
		// m_relay_pkt_deduplicater.get_all_timestamps(after);
#ifndef TORRENT_DISABLE_LOGGING
		if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_DEBUG))
		{
			m_observer->log(dht_logger::node, "relay pkt deduplicater:%d,%d"
				, int(orig_size), int(m_relay_pkt_deduplicater.size()));

			/*
			m_observer->log(dht_logger::node, "relay pkt deduplicater tick before:%d"
				, before.size());
			for (auto it = before.begin(); it != before.end(); it++)
			{
				m_observer->log(dht_logger::node, "relay pkt deduplicater:%d", *it);
			}

			m_observer->log(dht_logger::node, "relay pkt deduplicater tick after:%d"
				, after.size());
			for (auto it = after.begin(); it != after.end(); it++)
			{
				m_observer->log(dht_logger::node, "relay pkt deduplicater:%d", *it);
			}
			 */
		}
#endif
	}

	time_point now(aux::time_now());
	if (now - minutes(1) < m_last_tracker_tick) return d;
	m_last_tracker_tick = now;

	m_storage.tick();
	m_incoming_table.tick();
	m_bs_nodes_learner.tick();

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

std::tuple<int, int, int, std::int64_t> node::get_stats_counters() const
{
	int nodes, replacements;
	std::tie(nodes, replacements, std::ignore) = size();
	return std::make_tuple(nodes, replacements
			, m_rpc.num_allocated_observers()
			, m_rpc.num_invoked_requests());
}

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
std::tuple<bool, bool> node::incoming_request(msg const& m, entry& e
	, node_id const& id, node_id *to, udp::endpoint *to_ep, node_id& push_candidate)
{
	bool need_response = true;
	bool need_push = false;

	e = entry(entry::dictionary_t);
	e["y"] = "r";
	e["t"] = m.message.dict_find_string_value("t");
	if (m_settings.get_bool(settings_pack::dht_non_referrable)) e["nr"] = 1;

	static key_desc_t const top_desc[] = {
		{"q", bdecode_node::string_t, 0, 0},
		{"ro", bdecode_node::int_t, 0, key_desc_t::optional},
		{"nr", bdecode_node::int_t, 0, key_desc_t::optional},
		{"a", bdecode_node::dict_t, 0, key_desc_t::parse_children},
	};

	bdecode_node top_level[4];
	char error_string[200];
	if (!verify_message(m.message, top_desc, top_level, error_string))
	{
		incoming_error(e, error_string);
		return std::make_tuple(need_response, need_push);
	}

	e["ip"] = aux::endpoint_to_bytes(m.addr);

	bdecode_node const arg_ent = top_level[3];
	bool const read_only = top_level[1] && top_level[1].int_value() != 0;
	bool const non_referrable = top_level[2] && top_level[2].int_value() != 0;

	// m_table.heard_about(id, m.addr);

	entry& reply = e["r"];

	// mirror back the other node's external port
	// reply["p"] = m.addr.port();

	string_view const query = top_level[0].string_value();

	if (query != "put" && !read_only)
	{
		// for multi online devices, another devices with the same node id
		// may be in our routing table.
		m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
	}

	if (m_observer && m_observer->on_dht_request(query, m, e))
		return std::make_tuple(need_response, need_push);

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
			return std::make_tuple(need_response, need_push);
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
			return std::make_tuple(need_response, need_push);
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
			{"ts", bdecode_node::int_t, 0, key_desc_t::optional},
			// public key
			{"k", bdecode_node::string_t, public_key::len, key_desc_t::optional},
			{"sig", bdecode_node::string_t, signature::len, key_desc_t::optional},
			{"cas", bdecode_node::int_t, 0, key_desc_t::optional},
			{"salt", bdecode_node::string_t, 0, key_desc_t::optional},
			{"want", bdecode_node::list_t, 0, key_desc_t::optional},
			{"distance", bdecode_node::int_t, 0, key_desc_t::optional},
		};

		// attempt to parse the message
		// also reject the message if it has any non-fatal encoding errors
		// because put messages contain a signed value they must have correct bencoding
		// otherwise the value will not round-trip without breaking the signature
		bdecode_node msg_keys[9];
		if (!verify_message(arg_ent, msg_desc, msg_keys, error_string)
			|| arg_ent.has_soft_error(error_string))
		{
			m_counters.inc_stats_counter(counters::dht_invalid_put);
			incoming_error(e, error_string);
			m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
			return std::make_tuple(need_response, need_push);
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
			m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
			return std::make_tuple(need_response, need_push);
		}

		span<char const> salt;
		if (msg_keys[6])
			salt = {msg_keys[6].string_ptr(), msg_keys[6].string_length()};
		if (salt.size() > 64)
		{
			m_counters.inc_stats_counter(counters::dht_invalid_put);
			incoming_error(e, "salt too big", 207);
			m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
			return std::make_tuple(need_response, need_push);
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
			m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
			return std::make_tuple(need_response, need_push);
		}

		int min_distance_exp = -1;

		if (!mutable_put)
		{
			m_storage.put_immutable_item(target, buf, m.addr.address());
			need_response = false;
		}
		else
		{
			// mutable put, we must verify the signature
			timestamp const ts(msg_keys[2].int_value());
			public_key const pk(pub_key);
			signature const sig(sign);

			if (ts < timestamp(0))
			{
				m_counters.inc_stats_counter(counters::dht_invalid_put);
				incoming_error(e, "invalid (negative) timestamp");
				m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
				return std::make_tuple(need_response, need_push);
			}

			// msg_keys[4] is the signature, msg_keys[3] is the public key
			if (!verify_mutable_item(buf, salt, ts, pk, sig))
			{
				m_counters.inc_stats_counter(counters::dht_invalid_put);
				incoming_error(e, "invalid signature", 206);
				m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
				return std::make_tuple(need_response, need_push);
			}

			TORRENT_ASSERT(signature::len == msg_keys[4].string_length());

			timestamp item_ts;
			if (!m_storage.get_mutable_item_timestamp(target, item_ts))
			{
				m_storage.put_mutable_item(target, buf, sig, ts, pk, salt
					, m.addr.address());
			}
			else
			{
				// this is the "cas" field in the put message
				// if it was specified, we MUST make sure the current timestamp
				// matches the expected value before replacing it
				// this is critical for avoiding race conditions when multiple
				// writers are accessing the same slot
				if (msg_keys[5] && item_ts.value != msg_keys[5].int_value())
				{
					m_counters.inc_stats_counter(counters::dht_invalid_put);
					incoming_error(e, "CAS mismatch", 301);
					m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
					return std::make_tuple(need_response, need_push);
				}

				if (item_ts > ts)
				{
					m_counters.inc_stats_counter(counters::dht_invalid_put);
					incoming_error(e, "old timestamp", 302);
					m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
					return std::make_tuple(need_response, need_push);
				}

				m_storage.put_mutable_item(target, buf, sig, ts, pk, salt
					, m.addr.address());
			}

			if (msg_keys[8])
			{
				min_distance_exp = msg_keys[8].int_value();
			}
			// for mutable item, return 'nodes' field
			write_nodes_entries(target, msg_keys[7], reply, min_distance_exp);
		}

		/*
		if (!read_only)
		{
			m_table.node_seen(id, m.addr, 0xffff);
		}
		 */

		// remove relay logic
		/*
		if (msg_keys[9])
		{
			node_id const receiver(msg_keys[9].string_ptr());
			*to = receiver;
			auto ne = m_incoming_table.find_node(receiver);
			if (receiver == m_id)
			{
				// push to ourself
				need_push = true;
				reply["hit"] = 1;
			}
			else if (ne != nullptr && ne->ep() != m.addr)
			{
				*to_ep = ne->ep();
				need_push = true;
				reply["hit"] = 1;
			}
		}*/

		// for multi online devices, another devices with the same node id
		// may be in our routing table.
		if (!read_only)
		{
			m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
		}
	}
	else if (query == "get")
	{
		static key_desc_t const msg_desc[] = {
			{"ts", bdecode_node::int_t, 0, key_desc_t::optional},
			{"target", bdecode_node::string_t, 0, 0},
			{"mutable", bdecode_node::int_t, 0, key_desc_t::optional},
			{"want", bdecode_node::list_t, 0, key_desc_t::optional},
			{"distance", bdecode_node::int_t, 0, key_desc_t::optional},
		};

		// k is not used for now

		// attempt to parse the message
		bdecode_node msg_keys[5];
		if (!verify_message(arg_ent, msg_desc, msg_keys, error_string))
		{
			m_counters.inc_stats_counter(counters::dht_invalid_get);
			incoming_error(e, error_string);
			return std::make_tuple(need_response, need_push);
		}

		m_counters.inc_stats_counter(counters::dht_get_in);

		span<char const> target_str;
		if (msg_keys[1])
			target_str = {msg_keys[1].string_ptr(), msg_keys[1].string_length()};
		if (target_str.size() > 32)
		{
			m_counters.inc_stats_counter(counters::dht_invalid_put);
			incoming_error(e, "target too big", 407);
			return std::make_tuple(need_response, need_push);
		}

		sha256_hash target;
		std::memcpy(&target[0], target_str.data(), target_str.size());

//		std::fprintf(stderr, "%s GET target: %s\n"
//			, msg_keys[1] ? "mutable":"immutable"
//			, aux::to_hex(target).c_str());

		reply["token"] = generate_token(m.addr, target);

		// always return nodes as well as peers for mutable item
		bool const get_mutable = msg_keys[2] && msg_keys[2].int_value() != 0;
		int min_distance_exp = -1;
		if (get_mutable)
		{
			if (msg_keys[4])
			{
				min_distance_exp = msg_keys[4].int_value();
			}
			write_nodes_entries(target, msg_keys[3], reply, min_distance_exp);
		}

		// if the get has a timestamp it must be for a mutable item
		// so don't bother searching the immutable table
		if (!msg_keys[0])
		{
			if (!m_storage.get_immutable_item(target, reply)) // ok, check for a mutable one
			{
				m_storage.get_mutable_item(target, timestamp(0)
					, true, reply);
			}
		}
		else
		{
			m_storage.get_mutable_item(target
				, timestamp(msg_keys[0].int_value()), false
				, reply);
		}
	}
	else if (query == "keep")
	{
		// nothing to do
		need_response = false;
		push_candidate = id;
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
				return std::make_tuple(need_response, need_push);
			}
		}

		sha256_hash const target(target_ent.string_ptr());
		// always return nodes as well as peers
		write_nodes_entries(target, arg_ent.dict_find_list("want"), reply);
	}

	return std::make_tuple(need_response, need_push);
}

struct push_observer : observer
{
	push_observer(
		std::shared_ptr<traversal_algorithm> algorithm
		, udp::endpoint const& ep, node_id const& id)
		: observer(std::move(algorithm), ep, id)
	{}

	void reply(msg const& m, node_id const& from) override
	{}
};

void node::push(node_id const& to, udp::endpoint const& to_ep, msg const& m, node_id const& from)
{
	// don't push to ourself
	if (to == m_id)
	{
		incoming_push_ourself(m, from);
		return;
	}

	// don't push this message to sender
	if (to_ep == m.addr) return;

	// construct push protocol
	entry e(m.message);
	e["y"] = "p";
	e["ro"] = m_settings.get_bool(settings_pack::dht_read_only) ? 1 : 0;
	e["nr"] = m_settings.get_bool(settings_pack::dht_non_referrable) ? 1 : 0;

	// create a dummy traversal_algorithm
	auto algo = std::make_shared<traversal_algorithm>(*this, to);
	auto o = m_rpc.allocate_observer<push_observer>(std::move(algo), to_ep, to);
	if (!o) return;
#if TORRENT_USE_ASSERTS
	o->m_in_constructor = false;
#endif

	// discard target node's response
	m_rpc.invoke(e, to_ep, o, true);
}

void node::push(node_id const& to, udp::endpoint const& to_ep, entry& re)
{
	entry e = entry(entry::dictionary_t);

	e["a"] = re;
	e["y"] = "h";
	e["q"] = "relay";

	// create a dummy traversal_algorithm
	auto algo = std::make_shared<traversal_algorithm>(*this, to);
	auto o = m_rpc.allocate_observer<push_observer>(std::move(algo), to_ep, to);
	if (!o) return;
#if TORRENT_USE_ASSERTS
	o->m_in_constructor = false;
#endif

	// discard target node's response
	m_rpc.invoke(e, to_ep, o, true);
}

void node::incoming_push_ourself(msg const& m, node_id const& from)
{
	entry e;
	item i;

	incoming_push(m, e, from, i);
	if (m_observer && !i.empty()) m_observer->on_dht_item(i);
}

bool node::incoming_push(msg const& m, entry& e, node_id const& id, item& i)
{
	e = entry(entry::dictionary_t);
	e["y"] = "r";
	e["t"] = m.message.dict_find_string_value("t");
	e["ip"] = aux::endpoint_to_bytes(m.addr);
	if (m_settings.get_bool(settings_pack::dht_non_referrable)) e["nr"] = 1;

	entry& reply = e["r"];
	// mirror back the other node's external port
	// reply["p"] = m.addr.port();

	static key_desc_t const top_desc[] = {
		{"q", bdecode_node::string_t, 0, 0},
		{"ro", bdecode_node::int_t, 0, key_desc_t::optional},
		{"nr", bdecode_node::int_t, 0, key_desc_t::optional},
		{"a", bdecode_node::dict_t, 0, key_desc_t::parse_children},
	};

	bdecode_node top_level[4];
	char error_string[200];
	if (!verify_message(m.message, top_desc, top_level, error_string))
	{
		incoming_push_error(error_string);
		return true;
	}

	bool const read_only = top_level[1] && top_level[1].int_value() != 0;
	bool const non_referrable = top_level[2] && top_level[2].int_value() != 0;
	if (!read_only)
	{
		m_incoming_table.incoming_endpoint(id, m.addr, non_referrable);
	}

	bdecode_node const arg_ent = top_level[3];
	string_view const query = top_level[0].string_value();

	if (query == "put")
	{
		// the first 2 entries are for both mutable and
		// immutable puts
		static key_desc_t const msg_desc[] = {
			{"token", bdecode_node::string_t, 0, 0},
			{"v", bdecode_node::none_t, 0, 0},
			{"ts", bdecode_node::int_t, 0, key_desc_t::optional},
			// public key
			{"k", bdecode_node::string_t, public_key::len, key_desc_t::optional},
			{"sig", bdecode_node::string_t, signature::len, key_desc_t::optional},
			{"cas", bdecode_node::int_t, 0, key_desc_t::optional},
			{"salt", bdecode_node::string_t, 0, key_desc_t::optional},
			{"want", bdecode_node::list_t, 0, key_desc_t::optional},
			{"distance", bdecode_node::int_t, 0, key_desc_t::optional},
			{"to", bdecode_node::string_t, public_key::len, key_desc_t::optional},
		};

		// attempt to parse the message
		// also reject the message if it has any non-fatal encoding errors
		// because put messages contain a signed value they must have correct bencoding
		// otherwise the value will not round-trip without breaking the signature
		bdecode_node msg_keys[10];
		if (!verify_message(arg_ent, msg_desc, msg_keys, error_string)
			|| arg_ent.has_soft_error(error_string))
		{
			incoming_push_error(error_string);
			return true;
		}

		if (!msg_keys[9]) return true;

		node_id const to(msg_keys[9].string_ptr());
		if (to != m_id) return false;

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
			incoming_push_error("message too big");
			return true;
		}

		span<char const> salt;
		if (msg_keys[6])
			salt = {msg_keys[6].string_ptr(), msg_keys[6].string_length()};
		if (salt.size() > 64)
		{
			incoming_push_error("salt too big");
			return true;
		}

		sha256_hash const target = pub_key
			? item_target_id(salt, public_key(pub_key))
			: item_target_id(buf);

		if (!mutable_put)
		{
			error_code errc;
			auto v = bdecode(buf.first(buf.size()), errc);
			i.assign(v);
		}
		else
		{
			// mutable put, we must verify the signature
			timestamp const ts(msg_keys[2].int_value());
			public_key const pk(pub_key);
			signature const sig(sign);

			if (ts < timestamp(0))
			{
				incoming_push_error("invalid (negative) timestamp");
				return true;
			}

			// msg_keys[4] is the signature, msg_keys[3] is the public key
			if (!verify_mutable_item(buf, salt, ts, pk, sig))
			{
				incoming_push_error("invalid signature");
				return true;
			}

			TORRENT_ASSERT(signature::len == msg_keys[4].string_length());

			error_code errc;
			auto v = bdecode(buf.first(buf.size()), errc);
			i.assign(v, salt, ts, pk, sig);
        }
	}

	return true;
}

void node::incoming_push_error(const char *err_str)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_ERR))
	{
		m_observer->log(dht_logger::node, "INCOMING PUSH ERROR:%s", err_str);
	}
#endif
}

bool node::incoming_relay(msg const& m, entry& e, entry& payload
		, node_id *to, udp::endpoint *to_ep, node_id& sender
		, node_id const& from, std::string& decrypted_pl)
{
	e = entry(entry::dictionary_t);
	e["y"] = "r";
	e["t"] = m.message.dict_find_string_value("t");
	e["ip"] = aux::endpoint_to_bytes(m.addr);
	if (m_settings.get_bool(settings_pack::dht_non_referrable)) e["nr"] = 1;

	entry& reply = e["r"];
	// mirror back the other node's external port
	// reply["p"] = m.addr.port();

	static key_desc_t const top_desc[] = {
		{"q", bdecode_node::string_t, 0, 0},
		{"ro", bdecode_node::int_t, 0, key_desc_t::optional},
		{"nr", bdecode_node::int_t, 0, key_desc_t::optional},
		{"a", bdecode_node::dict_t, 0, key_desc_t::parse_children},
			{"hmac", bdecode_node::string_t
				, relay_hmac::len, key_desc_t::last_child},
	};

	bdecode_node top_level[5];
	char error_string[200];
	if (!verify_message(m.message, top_desc, top_level, error_string))
	{
		incoming_relay_error(error_string);
		return false;
	}

	node_id target_id = m_id;
	*to = target_id;

	bool const read_only = top_level[1] && top_level[1].int_value() != 0;
	bool const non_referrable = top_level[2] && top_level[2].int_value() != 0;
	if (!read_only)
	{
		m_incoming_table.incoming_endpoint(from, m.addr, non_referrable);
	}

	bdecode_node const arg_ent = top_level[3];
	string_view const query = top_level[0].string_value();

	if (query == "relay")
	{
		static key_desc_t const msg_desc[] = {
			// from: sender public key
			{"f", bdecode_node::string_t, public_key::len, key_desc_t::optional},
			{"pl", bdecode_node::string_t, 0, 0},
			{"want", bdecode_node::list_t, 0, key_desc_t::optional},
			{"dis", bdecode_node::int_t, 0, key_desc_t::optional},
			// ipv4 aux nodes
			{"rn", bdecode_node::none_t, 0, key_desc_t::optional},
			// ipv6 aux nodes
			{"rn6", bdecode_node::none_t, 0, key_desc_t::optional},
			{"hmac", bdecode_node::string_t, relay_hmac::len, 0},
			{"t", bdecode_node::string_t, public_key::len, key_desc_t::optional},
		};

		// attempt to parse the message
		// also reject the message if it has any non-fatal encoding errors
		bdecode_node msg_keys[8];
		if (!verify_message(arg_ent, msg_desc, msg_keys, error_string)
			|| arg_ent.has_soft_error(error_string))
		{
			incoming_relay_error(error_string);
			return false;
		}

		// From relay node view, if 'from' field isn't specified,
		// treat the public key parsed from udp packet header as sender public key.
		char const* sender_pk = nullptr;
		if (msg_keys[0])
		{
			sender_pk = msg_keys[0].string_ptr();
			sender.assign(sender_pk);
		}
		else
		{
			sender = from;
		}

		if (msg_keys[7])
		{
			target_id.assign(msg_keys[7].string_ptr());
			*to = target_id;
		}

		// parse payload
		// pointer and length to the whole entry
		// for 'relay' protocol, tha max size of decrypted 'payload' is 16 bytes.
		// and the encyption algorithm is AES(encryption block size is 16 bytes).
		span<char const> buffer = msg_keys[1].data_section();
		if (buffer.size() > 96 || buffer.empty())
		{
			incoming_relay_error("message too big");
			return false;
		}

		// parse aux nodes
		span<char const> aux_buf;
		udp proto = udp::v4();

		if (msg_keys[4])
		{
			aux_buf = msg_keys[4].data_section();
		}
		else if (msg_keys[5])
		{
			aux_buf = msg_keys[5].data_section();
			proto = udp::v6();
		}
		// the max size of aux info is 400:
		// 8 ipv6 endpoints: 8 * 50 (node id 32 + ipv6 16 + port 2).
		if (aux_buf.size() > 400)
		{
			incoming_relay_error("aux nodes too big");
			return false;
		}

		// parse hmac
		if (!msg_keys[6])
		{
			incoming_relay_error("empty hmac");
			return false;
		}

		relay_hmac hmac(msg_keys[6].string_ptr());

		// push to ourself
		if (target_id == m_id)
		{
			// decoding 'payload' entry and get responding string.
			error_code errc;
			entry pl_entry = bdecode(buffer.first(buffer.size()), errc);
			std::string payload_buf;
			payload_buf.assign(pl_entry.string());
			// decrypt payload
			std::string decrypt_err;
			dht::public_key dht_pk(sender.data());
			bool result = decrypt(dht_pk, payload_buf, decrypted_pl, decrypt_err);
			if (!result)
			{
				incoming_relay_error(decrypt_err.c_str());
#ifndef TORRENT_DISABLE_LOGGING
				if (m_observer != nullptr
					&& m_observer->should_log(dht_logger::node, aux::LOG_ERR))
				{
					m_observer->log(dht_logger::node, "payload size:%" PRId64, payload_buf.size());
				}
#endif
				return false;
			}

			if (!verify_relay_hmac(hmac, decrypted_pl, aux_buf))
			{
				incoming_relay_error("hmac verification error");
				return false;
			}

			span<char const> buf = decrypted_pl;
			payload = bdecode(buf.first(buf.size()), errc);
#ifndef TORRENT_DISABLE_LOGGING
			if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_DEBUG))
			{
				m_observer->log(dht_logger::node, "relay payload: %s"
					, payload.to_string(true).c_str());
			}
#endif
			// handle referred relay nodes
			look_for_nodes(protocol_relay_nodes_key(), protocol(), arg_ent,
				[this, &sender](node_endpoint const& nep)
					{ handle_referred_relays(sender, {nep.id, nep.ep});});

			reply["hit"] = 1;

			// de-duplicate relay packet
			std::string hmac_str(hmac.bytes.data(), 4);
			hmac_str.append(sender.data(), 4);
			if (m_relay_pkt_deduplicater.exist(hmac_str))
			{
#ifndef TORRENT_DISABLE_LOGGING
				if (m_observer != nullptr
					&& m_observer->should_log(dht_logger::node, aux::LOG_DEBUG))
				{
					m_observer->log(dht_logger::node, "drop duplicate relay packet");
				}
#endif
				return false;
			}
			else
			{
				m_relay_pkt_deduplicater.add(hmac_str);
			}
		}
		else
		{
			int min_distance_exp = -1;
			if (msg_keys[3])
			{
				min_distance_exp = msg_keys[3].int_value();
			}
			// write referred nodes
			write_nodes_entries(target_id, msg_keys[2], reply, min_distance_exp);

			auto ne = m_incoming_table.find_node(target_id);
			if (ne == nullptr || ne->ep() == m.addr) return false;
			*to_ep = ne->ep();
			reply["hit"] = 1;

			m_storage.put_relay_entry(from, target_id, buffer
					, aux_buf, proto, hmac);
		}

		return true;
	}

	return false;
}

void node::relay(node_id const& to, udp::endpoint const& to_ep
	, msg const& m, node_id const& from)
{
    // don't relay to ourself
	if (to == m_id)
	{
		return;
	}

	// don't push this message to sender
	if (to_ep == m.addr) return;

	// construct push protocol
	entry orig(m.message);
	entry& orig_a = orig["a"];

	entry e(entry::dictionary_t);
	entry& a = e["a"];
	e["y"] = "h"; // hop"
	e["q"] = "relay";
	e["ro"] = m_settings.get_bool(settings_pack::dht_read_only) ? 1 : 0;
	e["nr"] = m_settings.get_bool(settings_pack::dht_non_referrable) ? 1 : 0;

	public_key pk(from.data());
	a["f"] = pk.bytes;
	a["pl"] = orig_a["pl"];
	a["hmac"] = orig_a["hmac"];

	if (orig_a.find_key("rn"))
	{
		a["rn"] = *orig_a.find_key("rn");
	}
	if (orig_a.find_key("rn6"))
	{
		a["rn6"] = *orig_a.find_key("rn6");
	}

	// create a dummy traversal_algorithm
	auto algo = std::make_shared<traversal_algorithm>(*this, to);
	auto o = m_rpc.allocate_observer<push_observer>(std::move(algo), to_ep, to);
	if (!o) return;
#if TORRENT_USE_ASSERTS
	o->m_in_constructor = false;
#endif

	// discard target node's response
	m_rpc.invoke(e, to_ep, o, true);
}

void node::handle_referred_relays(node_id const& peer, node_entry const& ne)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_INFO))
	{
		m_observer->log(dht_logger::node, "push relay from:%s, id: %s, ep:%s"
			, aux::to_hex(peer).c_str()
			, aux::to_hex(ne.id).c_str()
			, aux::print_endpoint(ne.ep()).c_str());
	}
#endif

	m_storage.relay_referred(peer, ne);
}

void node::incoming_relay_error(const char *err_str)
{
#ifndef TORRENT_DISABLE_LOGGING
	if (m_observer != nullptr && m_observer->should_log(dht_logger::node, aux::LOG_ERR))
	{
		m_observer->log(dht_logger::node, "INCOMING RELAY ERROR:%s", err_str);
	}
#endif
}

// TODO: limit number of entries in the result
void node::write_nodes_entries(sha256_hash const& info_hash
	, bdecode_node const& want, entry& r, int min_distance_exp)
{
	// if no wants entry was specified, include a nodes
	// entry based on the protocol the request came in with
	if (want.type() != bdecode_node::list_t)
	{
		std::vector<node_entry> n = m_table.find_node(info_hash, {});
		if (min_distance_exp > 0)
		{
			auto it = std::find_if(n.begin(), n.end()
				, [&] (node_entry const& ne)
				  { return distance_exp(info_hash, ne.id) > min_distance_exp; });
			if (it != n.end())
			{
				n.erase(it, n.end());
			}
		}
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
		std::vector<node_entry> n = wanted_node->m_table.find_node(info_hash, {});
		if (min_distance_exp > 0)
		{
			auto it = std::find_if(n.begin(), n.end()
				, [&] (node_entry const& ne)
				  { return distance_exp(info_hash, ne.id) > min_distance_exp; });
			if (it != n.end())
			{
				n.erase(it, n.end());
			}
		}
		r[wanted_node->protocol_nodes_key()] = write_nodes_entry(n);
	}
}

node::protocol_descriptor const& node::map_protocol_to_descriptor(udp const protocol)
{
	static std::array<protocol_descriptor, 2> const descriptors =
	{{
		{udp::v4(), "n4", "nodes", "rn"},
		{udp::v6(), "n6", "nodes6", "rn6"}
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

bool node::encrypt(dht::public_key const& dht_pk, const std::string& in
	, std::string& out, std::string& err_str)
{
	// generate serect key
	std::array<char, 32> key = m_account_manager->key_exchange(dht_pk);
	std::string keystr;
	keystr.insert(0, key.data(), 32);

	return aux::aes_encrypt(in, out, keystr, err_str);
}

bool node::decrypt(dht::public_key const& dht_pk, const std::string& in
	, std::string& out, std::string& err_str)
{
	// generate secret key
	std::array<char, 32> key = m_account_manager->key_exchange(dht_pk);
	std::string keystr;
	keystr.insert(0, key.data(), 32);

	return aux::aes_decrypt(in, out, keystr, err_str);
}

} // namespace libTAU::dht
