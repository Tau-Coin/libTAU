/*

Copyright (c) 2014-2020, Arvid Norberg
Copyright (c) 2016-2017, 2019-2021, Alden Torres
Copyright (c) 2017-2018, Steven Siloti
Copyright (c) 2020, Paul-Louis Ageneau
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_SESSION_INTERFACE_HPP_INCLUDED
#define TORRENT_SESSION_INTERFACE_HPP_INCLUDED

#include "libTAU/config.hpp"
#include "libTAU/fwd.hpp"
#include "libTAU/address.hpp"
#include "libTAU/io_context.hpp"
#include "libTAU/time.hpp"
#include "libTAU/disk_buffer_holder.hpp"
#include "libTAU/error_code.hpp"
#include "libTAU/socket.hpp" // for tcp::endpoint
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/vector.hpp"
#include "libTAU/aux_/listen_socket_handle.hpp"
#include "libTAU/aux_/session_udp_sockets.hpp" // for transport
#include "libTAU/session_types.hpp"
#include "libTAU/flags.hpp"
#include "libTAU/aux_/link.hpp" // for torrent_list_index_t
#include "libTAU/info_hash.hpp"
#include "libTAU/aux_/socket_type.hpp"
#include "libTAU/aux_/ssl.hpp"
#include "libTAU/kademlia/types.hpp"

#include <functional>
#include <memory>

#include <leveldb/db.h>
#include <sqlite3.h>

namespace libTAU {

	struct peer_class_pool;
	struct counters;

namespace aux {
	struct peer_class_set;
	struct tracker_request;
	struct request_callback;
	struct peer_connection;
	struct bandwidth_channel;
	struct bandwidth_manager;
	struct resolver_interface;
	struct alert_manager;
	struct torrent;
	struct external_ip;
}

	// hidden
	using queue_position_t = aux::strong_typedef<int, struct queue_position_tag>;

	constexpr queue_position_t no_pos{-1};
	constexpr queue_position_t last_pos{(std::numeric_limits<int>::max)()};

namespace dht {

		struct dht_tracker;
	}
}

namespace libTAU::aux {

	struct proxy_settings;
	struct session_settings;

	using ip_source_t = flags::bitfield_flag<std::uint8_t, struct ip_source_tag>;

#if !defined TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS
	// This is the basic logging and debug interface offered by the session.
	// a release build with logging disabled (which is the default) will
	// not have this class at all
	struct TORRENT_EXTRA_EXPORT session_logger
	{
#ifndef TORRENT_DISABLE_LOGGING
		virtual bool should_log() const = 0;
		virtual bool should_log(aux::LOG_LEVEL log_level) const = 0;
		virtual void session_log(char const* fmt, ...) const TORRENT_FORMAT(2,3) = 0;
#endif

#if TORRENT_USE_ASSERTS
		virtual bool is_single_thread() const = 0;
#endif
	protected:
		~session_logger() {}
	};
#endif // TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS

	// TODO: 2 make this interface a lot smaller. It could be split up into
	// several smaller interfaces. Each subsystem could then limit the size
	// of the mock object to test it.
	struct TORRENT_EXTRA_EXPORT session_interface
#if !defined TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS
		: session_logger
#endif
	{

		// TODO: 2 the IP voting mechanism should be factored out
		// to its own class, not part of the session
		// and these constants should move too

		// the logic in ip_voter relies on more reliable sources are represented
		// by more significant bits
		static inline constexpr ip_source_t source_dht = 1_bit;
		static inline constexpr ip_source_t source_peer = 2_bit;
		static inline constexpr ip_source_t source_tracker = 3_bit;
		static inline constexpr ip_source_t source_router = 4_bit;

		virtual void set_external_address(tcp::endpoint const& local_endpoint
			, address const& ip
			, ip_source_t source_type, address const& source) = 0;
		virtual aux::external_ip external_address() const = 0;

		virtual alert_manager& alerts() = 0;

		virtual io_context& get_context() = 0;
		virtual aux::resolver_interface& get_resolver() = 0;

		// port filter
		virtual port_filter const& get_port_filter() const = 0;
		virtual void ban_ip(address addr) = 0;

		virtual std::uint16_t session_time() const = 0;
		//virtual void crash_dump_initial() = 0;
		virtual time_point session_start_time() const = 0;

		virtual bool is_aborted() const = 0;
		virtual void trigger_optimistic_unchoke() noexcept = 0;
		virtual void trigger_unchoke() noexcept = 0;

		virtual int num_connections() const = 0;

		virtual int get_log_level() const = 0;

		virtual void for_each_listen_socket(std::function<void(aux::listen_socket_handle const&)> f) = 0;

		// ask for which interface and port to bind outgoing peer connections on
		virtual bool verify_bound_address(address const& addr, bool utp
			, error_code& ec) = 0;

		// TODO: it would be nice to not have this be part of session_interface
		virtual proxy_settings proxy() const = 0;

		virtual void apply_settings_pack(std::shared_ptr<settings_pack> pack) = 0;
		virtual session_settings const& settings() const = 0;

		// peer-classes
		virtual peer_class_pool const& peer_classes() const = 0;
		virtual peer_class_pool& peer_classes() = 0;

		virtual void sent_bytes(int bytes_payload, int bytes_protocol) = 0;
		virtual void received_bytes(int bytes_payload, int bytes_protocol) = 0;
		virtual void trancieve_ip_packet(int bytes, bool ipv6) = 0;
		virtual void sent_syn(bool ipv6) = 0;
		virtual void received_synack(bool ipv6) = 0;

		// this is the set of (subscribed) torrents that have changed
		// their states since the last time the user requested updates.
		static inline constexpr torrent_list_index_t torrent_state_updates{0};

			// all torrents that want to be ticked every second
		static inline constexpr torrent_list_index_t torrent_want_tick{1};

			// all torrents that want more peers and are still downloading
			// these typically have higher priority when connecting peers
		static inline constexpr torrent_list_index_t torrent_want_peers_download{2};

			// all torrents that want more peers and are finished downloading
		static inline constexpr torrent_list_index_t torrent_want_peers_finished{3};

			// torrents that want auto-scrape (only paused auto-managed ones)
		static inline constexpr torrent_list_index_t torrent_want_scrape{4};

			// auto-managed torrents by state. Only these torrents are considered
			// when recalculating auto-managed torrents. started auto managed
			// torrents that are inactive are not part of these lists, because they
			// are not considered for auto managing (they are left started
			// unconditionally)
		static inline constexpr torrent_list_index_t torrent_downloading_auto_managed{5};
		static inline constexpr torrent_list_index_t torrent_seeding_auto_managed{6};
		static inline constexpr torrent_list_index_t torrent_checking_auto_managed{7};

		static constexpr std::size_t num_torrent_lists = 8;

		virtual void inc_boost_connections() = 0;

		virtual bool announce_dht() const = 0;
		virtual bool has_dht() const = 0;
		virtual int external_udp_port(address const& local_address) const = 0;
		virtual udp::endpoint external_udp_endpoint() const = 0;
		virtual dht::dht_tracker* dht() = 0;

		virtual leveldb::DB* kvdb() = 0;
		virtual sqlite3* sqldb() = 0;

		virtual std::int64_t timer_coe() = 0;

		virtual dht::public_key* pubkey() = 0;
		virtual dht::secret_key* serkey() = 0;

		virtual counters& stats_counters() = 0;
		virtual void received_buffer(int size) = 0;
		virtual void sent_buffer(int size) = 0;

		virtual ~session_interface() {}
	};
}

#endif
