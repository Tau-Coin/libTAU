/*

Copyright (c) 2012, 2014-2017, 2019-2020, Arvid Norberg
Copyright (c) 2014, 2017-2018, Steven Siloti
Copyright (c) 2016, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef DHT_OBSERVER_HPP
#define DHT_OBSERVER_HPP

#include "libTAU/config.hpp"
#include "libTAU/address.hpp"
#include "libTAU/string_view.hpp"
#include "libTAU/kademlia/msg.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/aux_/common.h" // for transport
#include "libTAU/aux_/session_udp_sockets.hpp" // for transport

#include <sqlite3.h>

namespace libTAU {

struct entry;

namespace aux {
struct listen_socket_handle;
}

namespace dht {

	struct TORRENT_EXTRA_EXPORT dht_logger
	{
#ifndef TORRENT_DISABLE_LOGGING
		enum module_t
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

		enum message_direction_t
		{
			incoming_message,
			outgoing_message
		};

		virtual bool should_log(module_t m) const = 0;
		virtual bool should_log(module_t m, aux::LOG_LEVEL log_level) const = 0;
		virtual void log(module_t m, char const* fmt, ...) TORRENT_FORMAT(3,4) = 0;
		virtual void log_packet(message_direction_t dir, span<char const> pkt
			, udp::endpoint const& node) = 0;
#endif

	protected:
		~dht_logger() = default;
	};

	struct TORRENT_EXTRA_EXPORT dht_observer : dht_logger
	{
		virtual void set_external_address(aux::listen_socket_handle const& iface
			, address const& addr, address const& source) = 0;
		virtual int get_listen_port(aux::transport ssl, aux::listen_socket_handle const& s) = 0;
		virtual void get_peers(sha256_hash const& ih) = 0;
		virtual void outgoing_get_peers(sha256_hash const& target
			, sha256_hash const& sent_target, udp::endpoint const& ep) = 0;
		virtual void announce(sha256_hash const& ih, address const& addr, int port) = 0;
		virtual bool on_dht_request(string_view query
			, dht::msg const& request, entry& response) = 0;
		virtual void on_dht_item(dht::item& i) = 0;
		virtual std::int64_t get_time() = 0;
		virtual void on_dht_relay(public_key const& from, entry const& payload) = 0;
		virtual sqlite3* get_items_database() = 0;

	protected:
		~dht_observer() = default;
	};
}
}

#endif
