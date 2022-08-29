/*

Copyright (c) 2006-2021, Arvid Norberg
Copyright (c) 2014-2017, Steven Siloti
Copyright (c) 2015, Thomas Yuan
Copyright (c) 2015-2017, Alden Torres
Copyright (c) 2020, Fonic
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef NODE_HPP
#define NODE_HPP

#include <map>
#include <set>
#include <mutex>
#include <cstdint>
#include <tuple>

#include <libTAU/config.hpp>
#include <libTAU/kademlia/dht_storage.hpp>
#include <libTAU/kademlia/incoming_table.hpp>
#include <libTAU/kademlia/routing_table.hpp>
#include <libTAU/kademlia/rpc_manager.hpp>
#include <libTAU/kademlia/node_id.hpp>
#include <libTAU/kademlia/find_data.hpp>
#include <libTAU/kademlia/item.hpp>
#include <libTAU/kademlia/announce_flags.hpp>
#include <libTAU/kademlia/bs_nodes_storage.hpp>
#include <libTAU/kademlia/bs_nodes_learner.hpp>

#include <libTAU/account_manager.hpp>
#include <libTAU/fwd.hpp>
#include <libTAU/socket.hpp> // for udp::endpoint
#include <libTAU/string_view.hpp>
#include <libTAU/aux_/listen_socket_handle.hpp>

// for dht_lookup and dht_routing_bucket
#include <libTAU/alert_types.hpp>

#include <boost/bimap/bimap.hpp>
#include <boost/bimap/multiset_of.hpp>
#include <boost/bimap/set_of.hpp>

using namespace boost::bimaps;
using libTAU::aux::account_manager;

namespace libTAU {
	struct counters;
}

namespace libTAU {
namespace dht {

struct traversal_algorithm;
struct dht_observer;
struct msg;
struct settings;

// libtau token
static const std::string libtau_token = "taut";

// decryption error string
static const std::string protocol_decryption_error = "decryption error";

// decryption error code
static constexpr int protocol_decryption_error_code = 303;

static constexpr int protocol_version_error_code = 401;
static constexpr int protocol_version_mismatch_error_code = 402;

TORRENT_EXTRA_EXPORT entry write_nodes_entry(std::vector<node_entry> const& nodes);

struct socket_manager
{
	virtual bool has_quota() = 0;
	virtual bool send_packet(aux::listen_socket_handle const& s, entry& e
		, udp::endpoint const& addr, sha256_hash const& pk) = 0;
protected:
	~socket_manager() = default;
};

// get the closest node to the id with the given family_name
using get_foreign_node_t = std::function<node*(node_id const&, string_view)>;

struct dht_status
{
	node_id our_id;
	udp::endpoint local_endpoint;
	std::vector<dht_routing_bucket> table;
	std::vector<dht_lookup> requests;
};

static constexpr int relay_pkt_timeout = 10; // keep_interval / 2 seconds

typedef bimap<

	set_of<std::string>,

	multiset_of<std::int64_t, std::less<std::int64_t> >

> relay_pkt_deduplicater_type;

typedef relay_pkt_deduplicater_type::value_type relay_pkt;

struct relay_pkt_deduplicater
{
	relay_pkt_deduplicater_type m_deduplicater;

	time_point m_last_tick = aux::time_now();

	std::size_t size()
	{
		return m_deduplicater.left.size();
	}

	bool exist(std::string const& hmac)
	{
		return m_deduplicater.left.find(hmac) != m_deduplicater.left.end();
	}

	void add(std::string const& hmac)
	{
		std::int64_t ts = libTAU::aux::utcTime();
		m_deduplicater.insert(relay_pkt(hmac, ts));
	}

	void tick(std::int64_t timeout)
	{
		if (m_deduplicater.left.size() == 0) return;

		time_point now(aux::time_now());
		if (now - seconds(1) < m_last_tick) return;

		m_last_tick = now;

		std::int64_t ts = libTAU::aux::utcTime() - timeout + 1;
		relay_pkt_deduplicater_type::right_iterator it = m_deduplicater.right.lower_bound(ts);
		m_deduplicater.right.erase(m_deduplicater.right.begin(), it);
	}

	void get_all_timestamps(std::vector<std::int64_t>& vec)
	{
		for (auto it = m_deduplicater.right.begin();
			it != m_deduplicater.right.end();
			it++)
		{
			vec.push_back(it->first);
		}
	}
};

class TORRENT_EXTRA_EXPORT node
{
public:
	node(aux::listen_socket_handle const& sock, socket_manager* sock_man
		, aux::session_settings const& settings
		, node_id const& nid
		, dht_observer* observer, counters& cnt
		, get_foreign_node_t get_foreign_node
		, dht_storage_interface& storage
		, std::shared_ptr<account_manager> account_manager
		, bs_nodes_storage_interface& bs_nodes_storage);

	~node();

	node(node const&) = delete;
	node& operator=(node const&) = delete;
	node(node&&) = delete;
	node& operator=(node&&) = delete;

	void tick();
	void prepare_bootstrap_nodes(std::vector<node_entry>& nodes
		, node_id const& target, bool first_bootstrap);
	void bootstrap(std::vector<node_entry> const& nodes
		, find_data::nodes_callback const& f);
	void add_router_node(node_entry const& router);
	void add_bootstrap_nodes(std::vector<node_entry> const& nodes);

	void unreachable(udp::endpoint const& ep);
	void incoming(aux::listen_socket_handle const& s, msg const& m, node_id const& from);
	void incoming_decryption_error(aux::listen_socket_handle const& s
		, udp::endpoint const& ep, sha256_hash const& pk);
	void handle_decryption_error(msg const& m);

#if TORRENT_ABI_VERSION == 1
	int num_torrents() const { return 0; }
	int num_peers() const { return 0; }
#endif

	int bucket_size(int bucket);

	node_id const& nid() const { return m_id; }

	void update_node_id(node_id const& id);

#ifndef TORRENT_DISABLE_LOGGING
	std::uint32_t search_id() { return m_search_id++; }
#endif

	std::tuple<int, int, int> size() const { return m_table.size(); }
	std::int64_t num_global_nodes() const
	{ return m_table.num_global_nodes(); }

#if TORRENT_ABI_VERSION == 1
	int data_size() const { return 0; }
#endif

	void get_item(sha256_hash const& target, std::function<void(item const&)> f);
	void get_item(sha256_hash const& target
		, std::vector<node_entry> const& eps
		, std::function<void(item const&)> f);
	void get_item(public_key const& pk
		, std::string const& salt
		, std::int64_t timestamp
		, std::function<void(item const&, bool)> f);

	void get_item(public_key const& pk
		, std::string const& salt
		, std::int64_t timestamp
		, std::int8_t alpha
		, std::int8_t invoke_window
		, std::int8_t invoke_limit
		, std::function<void(item const&, bool)> f);

	void put_item(sha256_hash const& target
		, entry const& data
		, public_key const& to
		, std::function<void(int)> f);
	void put_item(sha256_hash const& target
		, entry const& data
		, std::vector<node_entry> const& eps
		, public_key const& to
		, std::function<void(int)> f);
	void put_item(public_key const& pk
		, std::string const& salt
		, public_key const& to
		, std::function<void(item const&, int)> f
		, std::function<void(item&)> data_cb);

	void put_item(public_key const& pk
		, std::string const& salt
		, public_key const& to
		, std::int8_t alpha
		, std::int8_t beta
		, std::int8_t invoke_limit
		, bool cache
		, std::function<void(item const&, int)> f
		, std::function<void(item&)> data_cb);

	void put_item(public_key const& pk
		, std::string const& salt
		, public_key const& to
		, std::int8_t alpha
		, std::int8_t beta
		, std::int8_t invoke_limit
		, bool cache
		, std::function<void(item const&, int)> f
		, std::function<void(item&)> data_cb
		, std::function<void(std::vector<std::pair<node_entry, bool>> const&)> ncb);

	void put_item(public_key const& pk
		, std::string const& salt
		, entry const& data
		, std::int8_t alpha
		, std::int8_t invoke_window
		, std::int8_t invoke_limit
		, std::function<void(item const&, int)> f);

	// relay protocol
	void send(public_key const& to
		, entry const& payload
		, std::int8_t alpha
		, std::int8_t beta
		, std::int8_t invoke_limit
		, std::function<void(entry const&, int)> cb);

	void send(public_key const& to
		, entry const& payload
		, std::int8_t alpha
		, std::int8_t beta
		, std::int8_t invoke_limit
		, std::int8_t hit_limit
		, std::function<void(entry const& payload
			, std::vector<std::pair<node_entry, bool>> const& nodes)> cb);

	void get_peers(public_key const& pk, std::string const& salt);

	// fills the vector with the count nodes from routing table buckets that
	// are nearest to the given id.
	void find_live_nodes(node_id const& id
		, std::vector<node_entry>& l
		, int count);

	bool verify_token(string_view token, sha256_hash const& info_hash
		, udp::endpoint const& addr) const;

	std::string generate_token(udp::endpoint const& addr, sha256_hash const& info_hash);

	// the returned time is the delay until connection_timeout()
	// should be called again the next time
	time_duration connection_timeout();

	// generates a new secret number used to generate write tokens
	void new_write_key();

	// pings the given node, and adds it to
	// the routing table if it response and if the
	// bucket is not full.
	void add_node(node_entry const& node);

	int branch_factor() const;

	int invoke_window() const;

	int invoke_limit() const;

	int bootstrap_interval() const;
	int ping_interval() const;
	int keep_interval() const;

	void add_traversal_algorithm(traversal_algorithm* a)
	{
		std::lock_guard<std::mutex> l(m_mutex);
		m_running_requests.insert(a);
	}

	void remove_traversal_algorithm(traversal_algorithm* a)
	{
		std::lock_guard<std::mutex> l(m_mutex);
		m_running_requests.erase(a);
	}

	dht_status status() const;

	std::tuple<int, int, int, std::int64_t> get_stats_counters() const;

	aux::session_settings const& settings() const { return m_settings; }
	counters& stats_counters() const { return m_counters; }

	dht_observer* observer() const { return m_observer; }

	udp protocol() const { return m_protocol.protocol; }
	char const* protocol_family_name() const { return m_protocol.family_name; }
	char const* protocol_nodes_key() const { return m_protocol.nodes_key; }
	char const* protocol_relay_nodes_key() const { return m_protocol.relay_nodes_key; }

	bool native_address(udp::endpoint const& ep) const
	{ return ep.protocol().family() == m_protocol.protocol.family(); }
	bool native_address(tcp::endpoint const& ep) const
	{ return ep.protocol().family() == m_protocol.protocol.family(); }
	bool native_address(address const& addr) const
	{
		return (addr.is_v4() && m_protocol.protocol == udp::v4())
			|| (addr.is_v6() && m_protocol.protocol == udp::v6());
	}

private:

	void send_single_refresh(udp::endpoint const& ep, int bucket
		, node_id const& id = node_id());
	bool lookup_peers(sha256_hash const& info_hash, entry& reply
		, bool noseed, bool scrape, address const& requester) const;

	aux::session_settings const& m_settings;

	mutable std::mutex m_mutex;

	// this list must be destructed after the rpc manager
	// since it might have references to it
	std::set<traversal_algorithm*> m_running_requests;

	std::tuple<bool, bool> incoming_request(msg const&, entry&
		, node_id const& id, node_id *to, udp::endpoint *to_ep, node_id& push_candidate);

	void push(node_id const& to, udp::endpoint const& to_ep, msg const& m, node_id const& from);
	void push(node_id const& to, udp::endpoint const& to_ep, entry& relay_entry);

	bool incoming_push(msg const& m, entry& e, node_id const& from, item& i);

	void incoming_push_ourself(msg const& m, node_id const& from);

	void incoming_push_error(const char* err_str);

	bool incoming_relay(msg const& m, entry& e, entry& payload
		, node_id *to, udp::endpoint *to_ep, node_id& sender
		, node_id const& from, std::string& decrypted_pl);

	void relay(node_id const& to, udp::endpoint const& to_ep
		, msg const& m, node_id const& from);

	void handle_referred_relays(node_id const& peer, node_entry const& ne);

	void incoming_relay_error(const char* err_str);

	void write_nodes_entries(sha256_hash const& info_hash
		, bdecode_node const& want, entry& r, int min_distance_exp = -1);

	bool encrypt(dht::public_key const& dht_pk, const std::string& in
		, std::string& out, std::string& err_str);

	bool decrypt(dht::public_key const& dht_pk, const std::string& in
		, std::string& out, std::string& err_str);

	node_id m_id;

public:
	routing_table m_table;
	incoming_table m_incoming_table;
	rpc_manager m_rpc;
	bs_nodes_learner m_bs_nodes_learner;
	aux::listen_socket_handle const m_sock;
	dht_storage_interface& m_storage;

private:

	struct protocol_descriptor
	{
		udp protocol;
		char const* family_name;
		char const* nodes_key;
		char const* relay_nodes_key;
	};

	static protocol_descriptor const& map_protocol_to_descriptor(udp protocol);

	socket_manager* m_sock_man;

	get_foreign_node_t m_get_foreign_node;

	dht_observer* m_observer;

	protocol_descriptor const& m_protocol;

	time_point m_last_tracker_tick;

	// the last time we issued a bootstrap or a refresh on our own ID, to expand
	// the routing table buckets close to us.
	time_point m_last_self_refresh;

	// the last time we pinged a node.
	time_point m_last_ping;

	time_point m_last_keep;

	// secret random numbers used to create write tokens
	std::array<char, 4> m_secret[2];

	counters& m_counters;

	std::shared_ptr<account_manager> m_account_manager;

	relay_pkt_deduplicater m_relay_pkt_deduplicater;

	bs_nodes_storage_interface& m_bs_nodes_storage;

#ifndef TORRENT_DISABLE_LOGGING
	std::uint32_t m_search_id = 0;
#endif
};

} // namespace dht
} // namespace libTAU

#endif // NODE_HPP
