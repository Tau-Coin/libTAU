/*

Copyright (c) 2017, toinetoine
Copyright (c) 2004-2021, Arvid Norberg
Copyright (c) 2008, Andrew Resch
Copyright (c) 2014-2018, Steven Siloti
Copyright (c) 2015, Thomas
Copyright (c) 2015-2018, 2020-2021, Alden Torres
Copyright (c) 2017, Antoine Dahan
Copyright (c) 2018, d-komarov
Copyright (c) 2019, ghbplayer
Copyright (c) 2020, Fonic
Copyright (c) 2020, Viktor Elofsson
Copyright (c) 2020, AllSeeingEyeTolledEweSew
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_ALERT_TYPES_HPP_INCLUDED
#define TORRENT_ALERT_TYPES_HPP_INCLUDED

#include "libTAU/config.hpp"
#include "libTAU/alert.hpp"
#include "libTAU/socket.hpp"
#include "libTAU/assert.hpp"
#include "libTAU/identify_client.hpp"
#include "libTAU/address.hpp"
#include "libTAU/aux_/stat.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/peer_request.hpp"
#include "libTAU/performance_counters.hpp"
#include "libTAU/operations.hpp" // for operation_t enum
#include "libTAU/close_reason.hpp"
#include "libTAU/aux_/escape_string.hpp" // for convert_from_native
#include "libTAU/string_view.hpp"
#include "libTAU/aux_/stack_allocator.hpp"
#include "libTAU/aux_/noexcept_movable.hpp"
#include "libTAU/portmap.hpp" // for portmap_transport
#include "libTAU/socket_type.hpp"
#include "libTAU/client_data.hpp"
#include "libTAU/aux_/deprecated.hpp"
#include "libTAU/aux_/common.h"
#include "libTAU/communication/message.hpp"
#include "libTAU/blockchain/account.hpp"
#include "libTAU/blockchain/block.hpp"
#include "libTAU/blockchain/transaction.hpp"
#include "libTAU/blockchain/vote.hpp"

#include "libTAU/aux_/disable_warnings_push.hpp"
#include <boost/shared_array.hpp>
#include "libTAU/aux_/disable_warnings_pop.hpp"

#include <bitset>
#include <cstdarg> // for va_list

#define PROGRESS_NOTIFICATION

namespace libTAU {

	// internal
	TORRENT_EXPORT char const* alert_name(int alert_type);

	// user defined alerts should use IDs greater than this
	constexpr int user_alert_id = 10000;

	// this constant represents "max_alert_index" + 1
	constexpr int num_alert_types = 60;

	// internal
	constexpr int abi_alert_count = 128;

	// internal
	enum class alert_priority : std::uint8_t
	{
		// the order matters here. Lower value means lower priority, and will
		// start getting dropped earlier when the alert queue is filling up
		normal = 0,
		high,
		critical,
		meta
	};

	// struct to hold information about a single DHT routing table bucket
	struct TORRENT_EXPORT dht_routing_bucket
	{
		// the total number of nodes and replacement nodes
		// in the routing table
		int num_nodes;
		int num_replacements;

		// number of seconds since last activity
		int last_active;
	};


#define TORRENT_DEFINE_ALERT_IMPL(name, seq, prio) \
	name(name&&) noexcept = default; \
	static alert_priority const priority = prio; \
	static int const alert_type = seq; \
	virtual int type() const noexcept override { return alert_type; } \
	virtual alert_category_t category() const noexcept override { return static_category; } \
	virtual char const* what() const noexcept override { return alert_name(alert_type); }

#define TORRENT_DEFINE_ALERT(name, seq) \
	TORRENT_DEFINE_ALERT_IMPL(name, seq, alert_priority::normal)

#define TORRENT_DEFINE_ALERT_PRIO(name, seq, prio) \
	TORRENT_DEFINE_ALERT_IMPL(name, seq, prio)

	// This alert is posted when there is an error on a UDP socket. The
	// UDP sockets are used for all uTP, DHT and UDP tracker traffic. They are
	// global to the session.
	struct TORRENT_EXPORT udp_error_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT udp_error_alert(
			aux::stack_allocator& alloc
			, udp::endpoint const& ep
			, operation_t op
			, error_code const& ec);

		TORRENT_DEFINE_ALERT(udp_error_alert, 0)

		static inline constexpr alert_category_t static_category = alert_category::error;
		std::string message() const override;

		// the source address associated with the error (if any)
		aux::noexcept_movable<udp::endpoint> endpoint;

		// the operation that failed
		operation_t operation;

		// the error code describing the error
		error_code const error;
	};

	// Whenever libTAU learns about the machines external IP, this alert is
	// generated. The external IP address can be acquired from the tracker (if it
	// supports that) or from peers that supports the extension protocol.
	// The address can be accessed through the ``external_address`` member.
	struct TORRENT_EXPORT external_ip_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT external_ip_alert(aux::stack_allocator& alloc, address const& ip);

		TORRENT_DEFINE_ALERT(external_ip_alert, 1)

		static inline constexpr alert_category_t static_category = alert_category::status;
		std::string message() const override;

		// the IP address that is believed to be our external IP
		aux::noexcept_movable<address> external_address;
	};

	// This alert is generated when none of the ports, given in the port range, to
	// session can be opened for listening. The ``listen_interface`` member is the
	// interface that failed, ``error`` is the error code describing the failure.
	//
	// In the case an endpoint was created before generating the alert, it is
	// represented by ``address`` and ``port``. The combinations of socket type
	// and operation in which such address and port are not valid are:
	// accept  - i2p
	// accept  - socks5
	// enum_if - tcp
	//
	// libTAU may sometimes try to listen on port 0, if all other ports failed.
	// Port 0 asks the operating system to pick a port that's free). If that fails
	// you may see a listen_failed_alert with port 0 even if you didn't ask to
	// listen on it.
	struct TORRENT_EXPORT listen_failed_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT listen_failed_alert(aux::stack_allocator& alloc, string_view iface
			, lt::address const& listen_addr, int listen_port
			, operation_t op, error_code const& ec, lt::socket_type_t t);
		TORRENT_UNEXPORT listen_failed_alert(aux::stack_allocator& alloc, string_view iface
			, tcp::endpoint const& ep, operation_t op, error_code const& ec
			, lt::socket_type_t t);
		TORRENT_UNEXPORT listen_failed_alert(aux::stack_allocator& alloc, string_view iface
			, udp::endpoint const& ep, operation_t op, error_code const& ec
			, lt::socket_type_t t);
		TORRENT_UNEXPORT listen_failed_alert(aux::stack_allocator& alloc, string_view iface
			, operation_t op, error_code const& ec, lt::socket_type_t t);

		TORRENT_DEFINE_ALERT_PRIO(listen_failed_alert, 2, alert_priority::critical)

		static inline constexpr alert_category_t static_category = alert_category::status | alert_category::error;
		std::string message() const override;

		// the network device libTAU attempted to listen on, or the IP address
		char const* listen_interface() const;

		// the error the system returned
		error_code const error;

		// the underlying operation that failed
		operation_t op;

		// the type of listen socket this alert refers to.
		lt::socket_type_t const socket_type;

		// the address libTAU attempted to listen on
		// see alert documentation for validity of this value
		aux::noexcept_movable<lt::address> address;

		// the port libTAU attempted to listen on
		// see alert documentation for validity of this value
		int const port;

	private:
		std::reference_wrapper<aux::stack_allocator const> m_alloc;
		aux::allocation_slot m_interface_idx;
	};

	// This alert is posted when the listen port succeeds to be opened on a
	// particular interface. ``address`` and ``port`` is the endpoint that
	// successfully was opened for listening.
	struct TORRENT_EXPORT listen_succeeded_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT listen_succeeded_alert(aux::stack_allocator& alloc
			, lt::address const& listen_addr
			, int listen_port
			, lt::socket_type_t t);
		TORRENT_UNEXPORT listen_succeeded_alert(aux::stack_allocator& alloc
			, tcp::endpoint const& ep
			, lt::socket_type_t t);
		TORRENT_UNEXPORT listen_succeeded_alert(aux::stack_allocator& alloc
			, udp::endpoint const& ep
			, lt::socket_type_t t);

		TORRENT_DEFINE_ALERT_PRIO(listen_succeeded_alert, 3, alert_priority::critical)

		static inline constexpr alert_category_t static_category = alert_category::status;
		std::string message() const override;

		// the address libTAU ended up listening on. This address
		// refers to the local interface.
		aux::noexcept_movable<lt::address> address;

		// the port libTAU ended up listening on.
		int const port;

		// the type of listen socket this alert refers to.
		lt::socket_type_t const socket_type;
	};

	// This alert is generated when a NAT router was successfully found but some
	// part of the port mapping request failed. It contains a text message that
	// may help the user figure out what is wrong. This alert is not generated in
	// case it appears the client is not running on a NAT:ed network or if it
	// appears there is no NAT router that can be remote controlled to add port
	// mappings.
	struct TORRENT_EXPORT portmap_error_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT portmap_error_alert(aux::stack_allocator& alloc, port_mapping_t i
			, portmap_transport t, error_code const& e, address const& local);

		TORRENT_DEFINE_ALERT(portmap_error_alert, 4)

		static inline constexpr alert_category_t static_category = alert_category::port_mapping
			| alert_category::error;
		std::string message() const override;

		// refers to the mapping index of the port map that failed, i.e.
		// the index returned from add_mapping().
		port_mapping_t const mapping;

		// UPnP or NAT-PMP
		portmap_transport map_transport;

		// the local network the port mapper is running on
		aux::noexcept_movable<address> local_address;

		// tells you what failed.
		error_code const error;
	};

	// This alert is generated when a NAT router was successfully found and
	// a port was successfully mapped on it. On a NAT:ed network with a NAT-PMP
	// capable router, this is typically generated once when mapping the TCP
	// port and, if DHT is enabled, when the UDP port is mapped.
	struct TORRENT_EXPORT portmap_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT portmap_alert(aux::stack_allocator& alloc, port_mapping_t i, int port
			, portmap_transport t, portmap_protocol protocol, address const& local);

		TORRENT_DEFINE_ALERT(portmap_alert, 5)

		static inline constexpr alert_category_t static_category = alert_category::port_mapping;
		std::string message() const override;

		// refers to the mapping index of the port map that failed, i.e.
		// the index returned from add_mapping().
		port_mapping_t const mapping;

		// the external port allocated for the mapping.
		int const external_port;

		portmap_protocol const map_protocol;

		portmap_transport const map_transport;

		// the local network the port mapper is running on
		aux::noexcept_movable<address> local_address;
	};

	// This alert is generated to log informational events related to either
	// UPnP or NAT-PMP. They contain a log line and the type (0 = NAT-PMP
	// and 1 = UPnP). Displaying these messages to an end user is only useful
	// for debugging the UPnP or NAT-PMP implementation. This alert is only
	// posted if the alert_category::port_mapping_log flag is enabled in
	// the alert mask.
	struct TORRENT_EXPORT portmap_log_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT portmap_log_alert(aux::stack_allocator& alloc, portmap_transport t
			, const char* m, address const& local);

		TORRENT_DEFINE_ALERT(portmap_log_alert, 6)

		static inline constexpr alert_category_t static_category = alert_category::port_mapping_log;
		std::string message() const override;

		portmap_transport const map_transport;

		// the local network the port mapper is running on
		aux::noexcept_movable<address> local_address;

		// the message associated with this log line
		char const* log_message() const;

	private:

		std::reference_wrapper<aux::stack_allocator const> m_alloc;

		aux::allocation_slot m_log_idx;
	};

	// This alert is generated when a DHT node announces to an info-hash on our
	// DHT node. It belongs to the ``alert_category::dht`` category.
	struct TORRENT_EXPORT dht_announce_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_announce_alert(aux::stack_allocator& alloc, address const& i, int p
			, sha256_hash const& ih);

		TORRENT_DEFINE_ALERT(dht_announce_alert, 7)

		static inline constexpr alert_category_t static_category = alert_category::dht;
		std::string message() const override;

		aux::noexcept_movable<address> ip;
		int port;
		sha256_hash info_hash;
	};

	// This alert is generated when a DHT node sends a ``get_peers`` message to
	// our DHT node. It belongs to the ``alert_category::dht`` category.
	struct TORRENT_EXPORT dht_get_peers_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_get_peers_alert(aux::stack_allocator& alloc, sha256_hash const& ih);

		TORRENT_DEFINE_ALERT(dht_get_peers_alert, 8)

		static inline constexpr alert_category_t static_category = alert_category::dht;
		std::string message() const override;

		sha256_hash info_hash;
	};

	// This alert is posted when the initial DHT bootstrap is done.
	struct TORRENT_EXPORT dht_bootstrap_alert final : alert
	{
		// internal
		explicit TORRENT_UNEXPORT dht_bootstrap_alert(aux::stack_allocator& alloc);

		TORRENT_DEFINE_ALERT(dht_bootstrap_alert, 9)

		static inline constexpr alert_category_t static_category = alert_category::dht;
		std::string message() const override;
	};

	// This is posted whenever a torrent is transitioned into the error state.
	struct TORRENT_EXPORT session_start_over_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT session_start_over_alert(aux::stack_allocator& alloc, bool over);

		TORRENT_DEFINE_ALERT_PRIO(session_start_over_alert, 10, alert_priority::high)

		static inline constexpr alert_category_t static_category = alert_category::status;
		std::string message() const override;

		// the filename (or object) the error occurred on.
		bool session_start_over;
	};

	// The incoming connection alert is posted every time we successfully accept
	// an incoming connection, through any mean. The most straight-forward ways
	// of accepting incoming connections are through the TCP listen socket and
	// the UDP listen socket for uTP sockets. However, connections may also be
	// accepted through a Socks5 or i2p listen socket, or via an SSL listen
	// socket.
	struct TORRENT_EXPORT incoming_connection_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT incoming_connection_alert(aux::stack_allocator& alloc
			, socket_type_t t, tcp::endpoint const& i);

		TORRENT_DEFINE_ALERT(incoming_connection_alert, 11)

		static inline constexpr alert_category_t static_category = alert_category::peer;
		std::string message() const override;

		// tells you what kind of socket the connection was accepted
		socket_type_t socket_type;

		// is the IP address and port the connection came from.
		aux::noexcept_movable<tcp::endpoint> endpoint;

	};

	struct TORRENT_EXPORT session_stop_over_alert final : alert
	{
		session_stop_over_alert(aux::stack_allocator& alloc , bool over);
		TORRENT_DEFINE_ALERT(session_stop_over_alert, 12)

		static inline constexpr alert_category_t static_category = alert_category::status;

		std::string message() const override;

		bool session_stop_over;
	};

	// The session_stats_alert is posted when the user requests session statistics by
	// calling post_session_stats() on the session object. This alert does not
	// have a category, since it's only posted in response to an API call. It
	// is not subject to the alert_mask filter.
	//
	// the ``message()`` member function returns a string representation of the values that
	// properly match the line returned in ``session_stats_header_alert::message()``.
	//
	// this specific output is parsed by tools/parse_session_stats.py
	// if this is changed, that parser should also be changed
	struct TORRENT_EXPORT session_stats_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT session_stats_alert(aux::stack_allocator& alloc, counters const& cnt);

		TORRENT_DEFINE_ALERT_PRIO(session_stats_alert, 13, alert_priority::critical)

		static inline constexpr alert_category_t static_category = {};
		std::string message() const override;

		// An array are a mix of *counters* and *gauges*, which meanings can be
		// queries via the session_stats_metrics() function on the session. The
		// mapping from a specific metric to an index into this array is constant
		// for a specific version of libTAU, but may differ for other
		// versions. The intended usage is to request the mapping, i.e. call
		// session_stats_metrics(), once on startup, and then use that mapping to
		// interpret these values throughout the process' runtime.
		//
		// For more information, see the session-statistics_ section.
		span<std::int64_t const> counters() const;

	private:
		std::reference_wrapper<aux::stack_allocator const> m_alloc;
		aux::allocation_slot m_counters_idx;
	};

	// posted when something fails in the DHT. This is not necessarily a fatal
	// error, but it could prevent proper operation
	struct TORRENT_EXPORT dht_error_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_error_alert(aux::stack_allocator& alloc, operation_t op
			, error_code const& ec);

		TORRENT_DEFINE_ALERT(dht_error_alert, 14)

		static inline constexpr alert_category_t static_category = alert_category::error | alert_category::dht;
		std::string message() const override;

		// the error code
		error_code error;

		// the operation that failed
		operation_t op;
	};

	// this alert is posted as a response to a call to session::get_item(),
	// specifically the overload for looking up immutable items in the DHT.
	struct TORRENT_EXPORT dht_immutable_item_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_immutable_item_alert(aux::stack_allocator& alloc, sha256_hash const& t
			, entry i);

		TORRENT_DEFINE_ALERT_PRIO(dht_immutable_item_alert, 15, alert_priority::critical)

		static inline constexpr alert_category_t static_category = alert_category::dht;

		std::string message() const override;

		// the target hash of the immutable item. This must
		// match the SHA-2 hash of the bencoded form of ``item``.
		sha256_hash target;

		// the data for this item
		entry item;
	};

	// this alert is posted as a response to a call to session::get_item(),
	// specifically the overload for looking up mutable items in the DHT.
	struct TORRENT_EXPORT dht_mutable_item_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_mutable_item_alert(aux::stack_allocator& alloc
			, std::array<char, 32> const& k, std::array<char, 64> const& sig
			, std::int64_t timestamp, string_view s, entry i, bool a);

		TORRENT_DEFINE_ALERT_PRIO(dht_mutable_item_alert, 16, alert_priority::critical)

		static inline constexpr alert_category_t static_category = alert_category::dht;
		std::string message() const override;

		// the public key that was looked up
		std::array<char, 32> key;

		// the signature of the data. This is not the signature of the
		// plain encoded form of the item, but it includes the timestamp
		// and possibly the hash as well. See the dht_store document for more
		// information. This is primarily useful for echoing back in a store
		// request.
		std::array<char, 64> signature;

		// the timestamp of this item
		std::int64_t ts;

		// the salt, if any, used to lookup and store this item. If no
		// salt was used, this is an empty string
		std::string salt;

		// the data for this item
		entry item;

		// the last response for mutable data is authoritative.
		bool authoritative;
	};

	// this is posted when a DHT put operation completes. This is useful if the
	// client is waiting for a put to complete before shutting down for instance.
	struct TORRENT_EXPORT dht_put_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_put_alert(aux::stack_allocator& alloc, sha256_hash const& t, int n);
		TORRENT_UNEXPORT dht_put_alert(aux::stack_allocator& alloc, std::array<char, 32> const& key
			, std::array<char, 64> const& sig
			, std::string s
			, std::int64_t timestamp
			, int n);

		TORRENT_DEFINE_ALERT(dht_put_alert, 17)

		static inline constexpr alert_category_t static_category = alert_category::dht;
		std::string message() const override;

		// the target hash the item was stored under if this was an *immutable*
		// item.
		sha256_hash target;

		// if a mutable item was stored, these are the public key, signature,
		// salt and timestamp the item was stored under.
		std::array<char, 32> public_key;
		std::array<char, 64> signature;
		std::string salt;
		std::int64_t ts;

		// DHT put operation usually writes item to k nodes, maybe the node
		// is stale so no response, or the node doesn't support 'put', or the
		// token for write is out of date, etc. num_success is the number of
		// successful responses we got from the puts.
		int num_success;
	};

	// This alert is generated when we send a get_peers request
	// It belongs to the ``alert_category::dht`` category.
	struct TORRENT_EXPORT dht_outgoing_get_peers_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_outgoing_get_peers_alert(aux::stack_allocator& alloc
			, sha256_hash const& ih, sha256_hash const& obfih
			, udp::endpoint ep);

		TORRENT_DEFINE_ALERT(dht_outgoing_get_peers_alert, 18)

		static inline constexpr alert_category_t static_category = alert_category::dht;
		std::string message() const override;

		// the info_hash of the torrent we're looking for peers for.
		sha256_hash info_hash;

		// if this was an obfuscated lookup, this is the info-hash target
		// actually sent to the node.
		sha256_hash obfuscated_info_hash;

		// the endpoint we're sending this query to
		aux::noexcept_movable<udp::endpoint> endpoint;
	};

	// This alert is posted by some session wide event. Its main purpose is
	// trouble shooting and debugging. It's not enabled by the default alert
	// mask and is enabled by the ``alert_category::session_log`` bit.
	// Furthermore, it's by default disabled as a build configuration.
	struct TORRENT_EXPORT log_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT log_alert(aux::stack_allocator& alloc, char const* log);
		TORRENT_UNEXPORT log_alert(aux::stack_allocator& alloc, char const* fmt, va_list v);

		TORRENT_DEFINE_ALERT(log_alert, 19)

		static inline constexpr alert_category_t static_category = alert_category::session_log;
		std::string message() const override;

		// returns the log message
		char const* log_message() const;

	private:
		std::reference_wrapper<aux::stack_allocator const> m_alloc;
		aux::allocation_slot m_str_idx;
	};

	// holds statistics about a current dht_lookup operation.
	// a DHT lookup is the traversal of nodes, looking up a
	// set of target nodes in the DHT for retrieving and possibly
	// storing information in the DHT
	struct TORRENT_EXPORT dht_lookup
	{
		// string literal indicating which kind of lookup this is
		char const* type;

		// the number of outstanding request to individual nodes
		// this lookup has right now
		int outstanding_requests;

		// the total number of requests that have timed out so far
		// for this lookup
		int timeouts;

		// the total number of responses we have received for this
		// lookup so far for this lookup
		int responses;

		// the branch factor for this lookup. This is the number of
		// nodes we keep outstanding requests to in parallel by default.
		// when nodes time out we may increase this.
		int branch_factor;

		// the number of nodes left that could be queries for this
		// lookup. Many of these are likely to be part of the trail
		// while performing the lookup and would never end up actually
		// being queried.
		int nodes_left;

		// the number of seconds ago the
		// last message was sent that's still
		// outstanding
		int last_sent;

		// the number of outstanding requests
		// that have exceeded the short timeout
		// and are considered timed out in the
		// sense that they increased the branch
		// factor
		int first_timeout;

		// the node-id or info-hash target for this lookup
		sha1_hash target;
	};

	// contains current DHT state. Posted in response to session::post_dht_stats().
	struct TORRENT_EXPORT dht_stats_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_stats_alert(aux::stack_allocator& alloc
			, std::vector<dht_routing_bucket> table
			, std::vector<dht_lookup> requests
			, sha256_hash id, udp::endpoint ep);

		TORRENT_DEFINE_ALERT(dht_stats_alert, 20)

		static inline constexpr alert_category_t static_category = {};
		std::string message() const override;

		// a vector of the currently running DHT lookups.
		std::vector<dht_lookup> active_requests;

		// contains information about every bucket in the DHT routing
		// table.
		std::vector<dht_routing_bucket> routing_table;

		// the node ID of the DHT node instance
		sha256_hash nid;

		// the local socket this DHT node is running on
		aux::noexcept_movable<udp::endpoint> local_endpoint;
	};

	// debug logging of the DHT when alert_category::dht_log is set in the alert
	// mask.
	struct TORRENT_EXPORT dht_log_alert final : alert
	{
		enum dht_module_t
		{
			tracker,
			node,
			routing_table,
			rpc_manager,
			traversal,
			incoming_table,
			items_db,
			bs_nodes_db
		};

		// internal
		TORRENT_UNEXPORT dht_log_alert(aux::stack_allocator& alloc
			, dht_module_t m, char const* fmt, va_list v);

		static inline constexpr alert_category_t static_category = alert_category::dht_log;
		TORRENT_DEFINE_ALERT(dht_log_alert, 21)

		std::string message() const override;

		// the log message
		char const* log_message() const;

		// the module, or part, of the DHT that produced this log message.
		dht_module_t module;

	private:
		std::reference_wrapper<aux::stack_allocator const> m_alloc;
		aux::allocation_slot m_msg_idx;
	};

	// This alert is posted every time a DHT message is sent or received. It is
	// only posted if the ``alert_category::dht_log`` alert category is
	// enabled. It contains a verbatim copy of the message.
	struct TORRENT_EXPORT dht_pkt_alert final : alert
	{
		enum direction_t
		{ incoming, outgoing };

		// internal
		TORRENT_UNEXPORT dht_pkt_alert(aux::stack_allocator& alloc, span<char const> buf
			, dht_pkt_alert::direction_t d, udp::endpoint const& ep);

		static inline constexpr alert_category_t static_category = alert_category::dht_log;
		TORRENT_DEFINE_ALERT(dht_pkt_alert, 22)

		std::string message() const override;

		// returns a pointer to the packet buffer and size of the packet,
		// respectively. This buffer is only valid for as long as the alert itself
		// is valid, which is owned by libTAU and reclaimed whenever
		// pop_alerts() is called on the session.
		span<char const> pkt_buf() const;

		// whether this is an incoming or outgoing packet.
		direction_t direction;

		// the DHT node we received this packet from, or sent this packet to
		// (depending on ``direction``).
		aux::noexcept_movable<udp::endpoint> node;

	private:
		std::reference_wrapper<aux::stack_allocator> m_alloc;
		aux::allocation_slot m_msg_idx;
		int const m_size;
	};

	// Posted when we receive a response to a DHT get_peers request.
	struct TORRENT_EXPORT dht_get_peers_reply_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_get_peers_reply_alert(aux::stack_allocator& alloc
			, sha1_hash const& ih
			, std::vector<tcp::endpoint> const& peers);

		static inline constexpr alert_category_t static_category = alert_category::dht_operation;
		TORRENT_DEFINE_ALERT(dht_get_peers_reply_alert, 23)

		std::string message() const override;

		sha1_hash info_hash;

		int num_peers() const;

		std::vector<tcp::endpoint> peers() const;

	private:
		std::reference_wrapper<aux::stack_allocator> m_alloc;
		int m_v4_num_peers = 0;
		int m_v6_num_peers = 0;
		aux::allocation_slot m_v4_peers_idx;
		aux::allocation_slot m_v6_peers_idx;
	};

	// This is posted exactly once for every call to session_handle::dht_direct_request.
	// If the request failed, response() will return a default constructed bdecode_node.
	struct TORRENT_EXPORT dht_direct_response_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_direct_response_alert(aux::stack_allocator& alloc, client_data_t userdata
			, udp::endpoint const& addr, bdecode_node const& response);

		// internal
		// for when there was a timeout so we don't have a response
		TORRENT_UNEXPORT dht_direct_response_alert(aux::stack_allocator& alloc, client_data_t userdata
			, udp::endpoint const& addr);

		TORRENT_DEFINE_ALERT_PRIO(dht_direct_response_alert, 24, alert_priority::critical)

		static inline constexpr alert_category_t static_category = alert_category::dht;
		std::string message() const override;

		client_data_t userdata;
		aux::noexcept_movable<udp::endpoint> endpoint;

		bdecode_node response() const;

	private:
		std::reference_wrapper<aux::stack_allocator> m_alloc;
		aux::allocation_slot m_response_idx;
		int const m_response_size;
	};

	// this alert is posted when the session encounters a serious error,
	// potentially fatal
	struct TORRENT_EXPORT session_error_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT session_error_alert(aux::stack_allocator& alloc, error_code err
			, string_view error_str);

		TORRENT_DEFINE_ALERT(session_error_alert, 25)

		static inline constexpr alert_category_t static_category = alert_category::error;
		std::string message() const override;

		// The error code, if one is associated with this error
		error_code const error;

	private:
		std::reference_wrapper<aux::stack_allocator> m_alloc;
		aux::allocation_slot m_msg_idx;
	};

	// posted in response to a call to session::dht_live_nodes(). It contains the
	// live nodes from the DHT routing table of one of the DHT nodes running
	// locally.
	struct TORRENT_EXPORT dht_live_nodes_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_live_nodes_alert(aux::stack_allocator& alloc
			, sha256_hash const& nid
			, std::vector<std::pair<sha256_hash, udp::endpoint>> const& nodes);

		TORRENT_DEFINE_ALERT(dht_live_nodes_alert, 26)

		static inline constexpr alert_category_t static_category = alert_category::dht;
		std::string message() const override;

		// the local DHT node's node-ID this routing table belongs to
		sha256_hash node_id;

		// the number of nodes in the routing table and the actual nodes.
		int num_nodes() const;
		std::vector<std::pair<sha256_hash, udp::endpoint>> nodes() const;

	private:
		std::reference_wrapper<aux::stack_allocator> m_alloc;
		int m_v4_num_nodes = 0;
		int m_v6_num_nodes = 0;
		aux::allocation_slot m_v4_nodes_idx;
		aux::allocation_slot m_v6_nodes_idx;
	};

	// The session_stats_header alert is posted the first time
	// post_session_stats() is called
	//
	// the ``message()`` member function returns a string representation of the
	// header that properly match the stats values string returned in
	// ``session_stats_alert::message()``.
	//
	// this specific output is parsed by tools/parse_session_stats.py
	// if this is changed, that parser should also be changed
	struct TORRENT_EXPORT session_stats_header_alert final : alert
	{
		// internal
		explicit TORRENT_UNEXPORT session_stats_header_alert(aux::stack_allocator& alloc);
		TORRENT_DEFINE_ALERT(session_stats_header_alert, 27)

		static inline constexpr alert_category_t static_category = {};
		std::string message() const override;
	};

	// posted as a response to a call to session::dht_sample_infohashes() with
	// the information from the DHT response message.
	struct TORRENT_EXPORT dht_sample_infohashes_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT dht_sample_infohashes_alert(aux::stack_allocator& alloc
			, sha256_hash const& nid
			, udp::endpoint const& endp
			, time_duration interval
			, int num
			, std::vector<sha256_hash> const& samples
			, std::vector<std::pair<sha256_hash, udp::endpoint>> const& nodes);

		static inline constexpr alert_category_t static_category = alert_category::dht_operation;
		TORRENT_DEFINE_ALERT(dht_sample_infohashes_alert, 28)

		std::string message() const override;

		// id of the node the request was sent to (and this response was received from)
		sha256_hash node_id;

		// the node the request was sent to (and this response was received from)
		aux::noexcept_movable<udp::endpoint> endpoint;

		// the interval to wait before making another request to this node
		time_duration const interval;

		// This field indicates how many info-hash keys are currently in the node's storage.
		// If the value is larger than the number of returned samples it indicates that the
		// indexer may obtain additional samples after waiting out the interval.
		int const num_infohashes;

		// returns the number of info-hashes returned by the node, as well as the
		// actual info-hashes. ``num_samples()`` is more efficient than
		// ``samples().size()``.
		int num_samples() const;
		std::vector<sha256_hash> samples() const;

		// The total number of nodes returned by ``nodes()``.
		int num_nodes() const;

		// This is the set of more DHT nodes returned by the request.
		//
		// The information is included so that indexing nodes can perform a key
		// space traversal with a single RPC per node by adjusting the target
		// value for each RPC.
		std::vector<std::pair<sha256_hash, udp::endpoint>> nodes() const;

	private:
		std::reference_wrapper<aux::stack_allocator> m_alloc;
		int const m_num_samples;
		aux::allocation_slot m_samples_idx;
		int m_v4_num_nodes = 0;
		int m_v6_num_nodes = 0;
		aux::allocation_slot m_v4_nodes_idx;
		aux::allocation_slot m_v6_nodes_idx;
	};

	// this alert is posted to indicate to the client that some alerts were
	// dropped. Dropped meaning that the alert failed to be delivered to the
	// client. The most common cause of such failure is that the internal alert
	// queue grew too big (controlled by alert_queue_size).
	struct TORRENT_EXPORT alerts_dropped_alert final : alert
	{
		// internal
		explicit TORRENT_UNEXPORT alerts_dropped_alert(aux::stack_allocator& alloc
			, std::bitset<abi_alert_count> const&);
		TORRENT_DEFINE_ALERT_PRIO(alerts_dropped_alert, 29, alert_priority::meta)

		static inline constexpr alert_category_t static_category = alert_category::error;
		std::string message() const override;

		// a bitmask indicating which alerts were dropped. Each bit represents the
		// alert type ID, where bit 0 represents whether any alert of type 0 has
		// been dropped, and so on.
		std::bitset<abi_alert_count> dropped_alerts;
		static_assert(num_alert_types <= abi_alert_count, "need to increase bitset. This is an ABI break");
	};

	// this alert is posted with SOCKS5 related errors, when a SOCKS5 proxy is
	// configured. It's enabled with the alert_category::error alert category.
	struct TORRENT_EXPORT socks5_alert final : alert
	{
		// internal
		explicit socks5_alert(aux::stack_allocator& alloc
			, tcp::endpoint const& ep, operation_t operation, error_code const& ec);
		TORRENT_DEFINE_ALERT(socks5_alert, 30)

		static inline constexpr alert_category_t static_category = alert_category::error;
		std::string message() const override;

		// the error
		error_code error;

		// the operation that failed
		operation_t op;

		// the endpoint configured as the proxy
		aux::noexcept_movable<tcp::endpoint> ip;
	};

    // this alert is posted when new device id is found on net.
    struct TORRENT_EXPORT communication_new_device_id_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_new_device_id_alert(aux::stack_allocator& alloc, aux::bytes t);

        TORRENT_DEFINE_ALERT_PRIO(communication_new_device_id_alert, 31, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::communication;

        std::string message() const override;

        // device id found
        aux::bytes device_id;
    };

    // this alert is posted when new message is found from other peers.
    struct TORRENT_EXPORT communication_new_message_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_new_message_alert(aux::stack_allocator& alloc, communication::message e);

        TORRENT_DEFINE_ALERT_PRIO(communication_new_message_alert, 32, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::communication;

        std::string message() const override;

        // message found from peers.
        libTAU::communication::message msg;
    };

    // this alert is posted when message hash is confirmed by peers.
    struct TORRENT_EXPORT communication_confirmation_root_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_confirmation_root_alert(aux::stack_allocator& alloc, dht::public_key p, std::vector<sha1_hash> s, std::int64_t t);

        TORRENT_DEFINE_ALERT_PRIO(communication_confirmation_root_alert, 33, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::communication;

        std::string message() const override;

        // public key
        dht::public_key peer;

        // confirmation root
        std::vector<sha1_hash> confirmation_roots;

        // confirmed time
        std::int64_t time;
    };

    // this alert is posted when a message is syncing.
    struct TORRENT_EXPORT communication_syncing_message_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_syncing_message_alert(aux::stack_allocator& alloc, dht::public_key p, sha1_hash s, std::int64_t t);

        TORRENT_DEFINE_ALERT_PRIO(communication_syncing_message_alert, 34, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::communication;

        std::string message() const override;

        // public key
        dht::public_key peer;

        // syncing message hash
        sha1_hash syncing_msg_hash;

        // syncing msg time
        std::int64_t time;
    };

    // this alert is posted when friend info found in new mutable data.
    struct TORRENT_EXPORT communication_friend_info_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_friend_info_alert(aux::stack_allocator& alloc, dht::public_key p, aux::bytes t);

        TORRENT_DEFINE_ALERT_PRIO(communication_friend_info_alert, 35, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::communication;

        std::string message() const override;

        // public key
        dht::public_key peer;

        // friend info
        aux::bytes friend_info;
    };

    // This alert is posted by communication event. Its main purpose is
    // troubleshooting and debugging. It's not enabled by the default alert
    // mask and is enabled by the ``alert_category::communication_log`` bit.
    // Furthermore, it's by default disabled as a build configuration.
    struct TORRENT_EXPORT communication_log_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_log_alert(aux::stack_allocator& alloc, char const* log);
        TORRENT_UNEXPORT communication_log_alert(aux::stack_allocator& alloc, char const* fmt, va_list v);

        TORRENT_DEFINE_ALERT(communication_log_alert, 36)

        static inline constexpr alert_category_t static_category = alert_category::communication_log;
        std::string message() const override;

        // returns the log message
        char const* log_message() const;

    private:
        std::reference_wrapper<aux::stack_allocator const> m_alloc;
        aux::allocation_slot m_str_idx;
    };

    // this alert is posted when last seen time is updated.
    struct TORRENT_EXPORT communication_last_seen_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_last_seen_alert(aux::stack_allocator& alloc, dht::public_key p, int64_t t);

        TORRENT_DEFINE_ALERT_PRIO(communication_last_seen_alert, 37, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::communication;

        std::string message() const override;

        // public key
        dht::public_key peer;

        // last seen time
        int64_t last_seen;
    };

    // This alert is posted by blockchain event. Its main purpose is
    // troubleshooting and debugging. It's not enabled by the default alert
    // mask and is enabled by the ``alert_category::blockchain_log`` bit.
    // Furthermore, it's by default disabled as a build configuration.
    struct TORRENT_EXPORT blockchain_log_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_log_alert(aux::stack_allocator& alloc, char const* log);
        TORRENT_UNEXPORT blockchain_log_alert(aux::stack_allocator& alloc, char const* fmt, va_list v);

        TORRENT_DEFINE_ALERT(blockchain_log_alert, 38)

        static inline constexpr alert_category_t static_category = alert_category::blockchain_log;
        std::string message() const override;

        // returns the log message
        char const* log_message() const;

    private:
        std::reference_wrapper<aux::stack_allocator const> m_alloc;
        aux::allocation_slot m_str_idx;
    };

    // this alert is posted when new head block is found from other peers.
    struct TORRENT_EXPORT blockchain_new_head_block_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_new_head_block_alert(aux::stack_allocator& alloc, libTAU::blockchain::block blk);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_new_head_block_alert, 39, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // message found from peers.
        libTAU::blockchain::block blk;
    };

    // this alert is posted when new tail block is found from other peers.
    struct TORRENT_EXPORT blockchain_new_tail_block_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_new_tail_block_alert(aux::stack_allocator& alloc, libTAU::blockchain::block blk);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_new_tail_block_alert, 40, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // message found from peers.
        libTAU::blockchain::block blk;
    };

    // this alert is posted when new consensus point block is found from other peers.
    struct TORRENT_EXPORT blockchain_new_consensus_point_block_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_new_consensus_point_block_alert(aux::stack_allocator& alloc, libTAU::blockchain::block blk);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_new_consensus_point_block_alert, 41, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // message found from peers.
        libTAU::blockchain::block blk;
    };

    // this alert is posted when rollback block.
    struct TORRENT_EXPORT blockchain_rollback_block_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_rollback_block_alert(aux::stack_allocator& alloc, libTAU::blockchain::block blk);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_rollback_block_alert, 42, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // message found from peers.
        libTAU::blockchain::block blk;
    };

    // this alert is posted when fork point block is found.
    struct TORRENT_EXPORT blockchain_fork_point_block_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_fork_point_block_alert(aux::stack_allocator& alloc, blockchain::block blk);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_fork_point_block_alert, 43, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // message found from peers.
        libTAU::blockchain::block blk;
    };

    // this alert is posted when voting end.
    struct TORRENT_EXPORT blockchain_top_three_votes_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_top_three_votes_alert(aux::stack_allocator& alloc, aux::bytes id, std::vector<libTAU::blockchain::vote> vs);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_top_three_votes_alert, 44, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        aux::bytes chain_id;

        // top three votes
        std::vector<libTAU::blockchain::vote> votes;
    };

    // this alert is posted when get new tx from other peers.
    struct TORRENT_EXPORT blockchain_new_transaction_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_new_transaction_alert(aux::stack_allocator& alloc, libTAU::blockchain::transaction t);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_new_transaction_alert, 45, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // message found from peers.
        libTAU::blockchain::transaction tx;
    };

    // this alert is posted when get state from other peers.
    struct TORRENT_EXPORT blockchain_state_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_state_alert(aux::stack_allocator& alloc, aux::bytes id, libTAU::blockchain::account t);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_state_alert, 46, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        aux::bytes chain_id;

        // state from peers.
        libTAU::blockchain::account act;
    };

    // this alert is posted when syncing block.
    struct TORRENT_EXPORT blockchain_syncing_block_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_syncing_block_alert(aux::stack_allocator& alloc, dht::public_key p, blockchain::block blk);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_syncing_block_alert, 47, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // public key
        dht::public_key peer;

        // message found from peers.
        libTAU::blockchain::block blk;
    };

    // this alert is posted when syncing head block.
    struct TORRENT_EXPORT blockchain_syncing_head_block_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_syncing_head_block_alert(aux::stack_allocator& alloc, dht::public_key p, blockchain::block blk);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_syncing_head_block_alert, 48, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // public key
        dht::public_key peer;

        // message found from peers.
        libTAU::blockchain::block blk;
    };

    // this alert is posted when tx is confirmed.
    struct TORRENT_EXPORT blockchain_tx_confirmation_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_tx_confirmation_alert(aux::stack_allocator& alloc, aux::bytes id, dht::public_key p, sha1_hash h);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_tx_confirmation_alert, 49, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // chain id
        aux::bytes chain_id;

        // public key
        dht::public_key peer;

        // message found from peers.
        sha1_hash hash;
    };

	// this alert is posted when 'dht_non_referrable' is set into 'false' from 'true'
	// and NAT-PMP/UPNP is connected
	struct TORRENT_EXPORT referred_status_alert final : alert
	{
		// internal
		TORRENT_UNEXPORT referred_status_alert(aux::stack_allocator& alloc
			, address const& ip, int port);

		TORRENT_DEFINE_ALERT_PRIO(referred_status_alert, 50, alert_priority::critical)

		static inline constexpr alert_category_t static_category = alert_category::status;
		std::string message() const override;

		// the IP address that is believed to be our external IP
		aux::noexcept_movable<address> external_address;

		int external_port;
	};

    // this alert is posted when a message is arrived.
    struct TORRENT_EXPORT communication_message_arrived_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_message_arrived_alert(aux::stack_allocator& alloc, dht::public_key p, sha1_hash s, std::int64_t t);

        TORRENT_DEFINE_ALERT_PRIO(communication_message_arrived_alert, 51, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::communication;

        std::string message() const override;

        // public key
        dht::public_key peer;

        // message sent hash
        sha1_hash msg_arrived_hash;

        // syncing msg time
        std::int64_t time;
    };

    // this alert is posted when a tx is sent.
    struct TORRENT_EXPORT blockchain_tx_sent_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_tx_sent_alert(aux::stack_allocator& alloc, dht::public_key p, sha1_hash s, std::int64_t t);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_tx_sent_alert, 52, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // public key
        dht::public_key peer;

        // message sent hash
        sha1_hash tx_sent_hash;

        // syncing msg time
        std::int64_t time;
    };

    // this alert is posted when a tx is arrived.
    struct TORRENT_EXPORT blockchain_tx_arrived_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_tx_arrived_alert(aux::stack_allocator& alloc, aux::bytes id, sha1_hash s, std::int64_t t);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_tx_arrived_alert, 53, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // chain id
        aux::bytes chain_id;

        // message sent hash
        sha1_hash tx_arrived_hash;

        // syncing msg time
        std::int64_t time;
    };

    // this alert is posted when user info found in new mutable data.
    struct TORRENT_EXPORT communication_user_info_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_user_info_alert(aux::stack_allocator& alloc, dht::public_key p, aux::bytes k, aux::bytes v);

        TORRENT_DEFINE_ALERT_PRIO(communication_user_info_alert, 54, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::communication;

        std::string message() const override;

        // public key
        dht::public_key peer;

        aux::bytes key;

        // user info
        aux::bytes user_info;
    };

    // this alert is posted when user event found in new mutable data.
    struct TORRENT_EXPORT communication_user_event_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_user_event_alert(aux::stack_allocator& alloc, dht::public_key p, aux::bytes t);

        TORRENT_DEFINE_ALERT_PRIO(communication_user_event_alert, 55, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::communication;

        std::string message() const override;

        // public key
        dht::public_key peer;

        // user event
        aux::bytes user_event;
    };

    // this alert is posted when get state array from other peers.
    struct TORRENT_EXPORT blockchain_state_array_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_state_array_alert(aux::stack_allocator& alloc, aux::bytes id, std::vector<libTAU::blockchain::account> acts);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_state_array_alert, 56, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        aux::bytes chain_id;

        // state from peers.
        std::vector<libTAU::blockchain::account> accounts;
    };

    // this alert is posted when fail to get chain data from peers.
    struct TORRENT_EXPORT blockchain_fail_to_get_chain_data_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_fail_to_get_chain_data_alert(aux::stack_allocator& alloc, aux::bytes id);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_fail_to_get_chain_data_alert, 57, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        aux::bytes chain_id;
    };

    // this alert is posted when got signal.
    struct TORRENT_EXPORT blockchain_online_peer_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT blockchain_online_peer_alert(aux::stack_allocator& alloc, aux::bytes id, dht::public_key p, std::int64_t t);

        TORRENT_DEFINE_ALERT_PRIO(blockchain_online_peer_alert, 58, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::blockchain;

        std::string message() const override;

        // chain id
        aux::bytes chain_id;

        // public key
        dht::public_key peer;

        // syncing msg time
        std::int64_t time;
    };

    // this alert is posted when user event found in new mutable data.
    struct TORRENT_EXPORT communication_peer_attention_alert final : alert
    {
        // internal
        TORRENT_UNEXPORT communication_peer_attention_alert(aux::stack_allocator& alloc, dht::public_key p, std::int64_t t);

        TORRENT_DEFINE_ALERT_PRIO(communication_peer_attention_alert, 59, alert_priority::critical)

        static constexpr alert_category_t static_category = alert_category::communication;

        std::string message() const override;

        // public key
        dht::public_key peer;

        // time
        std::int64_t time;
    };

#undef TORRENT_DEFINE_ALERT_IMPL
#undef TORRENT_DEFINE_ALERT
#undef TORRENT_DEFINE_ALERT_PRIO
#undef PROGRESS_NOTIFICATION

} // namespace libTAU

#endif
