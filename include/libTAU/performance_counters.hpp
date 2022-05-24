/*

Copyright (c) 2014-2020, Arvid Norberg
Copyright (c) 2016-2017, Alden Torres
Copyright (c) 2019, Steven Siloti
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_PERFORMANCE_COUNTERS_HPP_INCLUDED
#define TORRENT_PERFORMANCE_COUNTERS_HPP_INCLUDED

#include "libTAU/config.hpp"
#include "libTAU/aux_/array.hpp"

#include <cstdint>
#include <atomic>
#include <mutex>

namespace libTAU {

	struct TORRENT_EXPORT counters
	{
		// internal
		enum stats_counter_t
		{
			// successful incoming connections (not rejected for any reason)
			incoming_connections,

			// counts events where the network
			// thread wakes up
			on_tick_counter,
			on_udp_counter,
			on_accept_counter,

			sent_payload_bytes,
			sent_bytes,
			sent_ip_overhead_bytes,
			sent_tracker_bytes,
			recv_payload_bytes,
			recv_bytes,
			recv_ip_overhead_bytes,
			recv_tracker_bytes,

			recv_failed_bytes,
			recv_redundant_bytes,

			dht_messages_in,
			dht_messages_in_dropped,
			dht_messages_out,
			dht_messages_out_dropped,
			dht_bytes_in,
			dht_bytes_out,

			dht_ping_in,
			dht_ping_out,
			dht_find_node_in,
			dht_find_node_out,
			dht_get_peers_in,
			dht_get_peers_out,
			dht_announce_peer_in,
			dht_announce_peer_out,
			dht_get_in,
			dht_get_out,
			dht_put_in,
			dht_put_out,
			dht_sample_infohashes_in,
			dht_sample_infohashes_out,
			dht_invoked_requests,

			dht_invalid_announce,
			dht_invalid_get_peers,
			dht_invalid_find_node,
			dht_invalid_put,
			dht_invalid_get,
			dht_invalid_sample_infohashes,

			// uTP counters.
			utp_packet_loss,
			utp_timeout,
			utp_packets_in,
			utp_packets_out,
			utp_fast_retransmit,
			utp_packet_resend,
			utp_samples_above_target,
			utp_samples_below_target,
			utp_payload_pkts_in,
			utp_payload_pkts_out,
			utp_invalid_pkts_in,
			utp_redundant_pkts_in,

			// the buffer sizes accepted by
			// socket send calls. The larger
			// the more efficient. The size is
			// 1 << n, where n is the number
			// at the end of the counter name

			// 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
			// 16384, 32768, 65536, 131072, 262144, 524288, 1048576
			socket_send_size3,

			// the buffer sizes returned by
			// socket recv calls. The larger
			// the more efficient. The size is
			// 1 << n, where n is the number
			// at the end of the counter name

			// 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
			// 16384, 32768, 65536, 131072, 262144, 524288, 1048576
			socket_recv_size3,

			num_stats_counters
		};

		// == ALL FOLLOWING ARE GAUGES ==

		// it is important that all gauges have a higher index than counters.
		// This assumption is relied upon in other parts of the code

		// internal
		enum stats_gauge_t
		{
			non_filter_torrents = num_stats_counters,

			dht_nodes,
			dht_node_cache,
			dht_torrents,
			dht_peers,
			dht_immutable_data,
			dht_mutable_data,
			dht_allocated_observers,

			has_incoming_connections,

			limiter_up_queue,
			limiter_down_queue,
			limiter_up_bytes,
			limiter_down_bytes,

			// the number of uTP connections in each respective state
			// these must be defined in the same order as the state_t enum
			// in utp_stream
			num_utp_idle,
			num_utp_syn_sent,
			num_utp_connected,
			num_utp_fin_sent,
			num_utp_close_wait,
			num_utp_deleted,

			num_outstanding_accept,

			num_queued_tracker_announces,

			num_counters,
			num_gauges_counters = num_counters - num_stats_counters
		};
#ifdef ATOMIC_LLONG_LOCK_FREE
#define TORRENT_COUNTER_NOEXCEPT noexcept
#else
#define TORRENT_COUNTER_NOEXCEPT
#endif

		counters() TORRENT_COUNTER_NOEXCEPT;

		counters(counters const&) TORRENT_COUNTER_NOEXCEPT;
		counters& operator=(counters const&) & TORRENT_COUNTER_NOEXCEPT;

		// returns the new value
		std::int64_t inc_stats_counter(int c, std::int64_t value = 1) TORRENT_COUNTER_NOEXCEPT;
		std::int64_t operator[](int i) const TORRENT_COUNTER_NOEXCEPT;

		void set_value(int c, std::int64_t value) TORRENT_COUNTER_NOEXCEPT;
		void blend_stats_counter(int c, std::int64_t value, int ratio) TORRENT_COUNTER_NOEXCEPT;

	private:

		// TODO: some space could be saved here by making gauges 32 bits
		// TODO: restore these to regular integers. Instead have one copy
		// of the counters per thread and collect them at convenient
		// synchronization points
#ifdef ATOMIC_LLONG_LOCK_FREE
		aux::array<std::atomic<std::int64_t>, num_counters> m_stats_counter;
#else
		// if the atomic type isn't lock-free, use a single lock instead, for
		// the whole array
		mutable std::mutex m_mutex;
		aux::array<std::int64_t, num_counters> m_stats_counter;
#endif
	};
}

#endif
