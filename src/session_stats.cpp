/*

Copyright (c) 2014-2021, Arvid Norberg
Copyright (c) 2016-2017, Alden Torres
Copyright (c) 2019, Steven Siloti
Copyright (c) 2020, FranciscoPombal
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/session_stats.hpp" // for stats_metric
#include "libTAU/aux_/vector.hpp"
#include "libTAU/performance_counters.hpp" // for counters

#include <cstring>
#include <algorithm>

namespace libTAU {

namespace {

	struct stats_metric_impl
	{
		char const* name;
		int value_index;
	};

#define METRIC(category, name) { #category "." #name, counters:: name },
	aux::array<stats_metric_impl, counters::num_counters> const metrics
	({{
		METRIC(peer, incoming_connections)

		// These counters count the number of times the
		// network thread wakes up for each respective
		// reason. If these counters are very large, it
		// may indicate a performance issue, causing the
		// network thread to wake up too ofte, wasting CPU.
		// mitigate it by increasing buffers and limits
		// for the specific trigger that wakes up the
		// thread.
		METRIC(net, on_tick_counter)
		METRIC(net, on_udp_counter)
		METRIC(net, on_accept_counter)

		// total number of bytes sent and received by the session
		METRIC(net, sent_payload_bytes)
		METRIC(net, sent_bytes)
		METRIC(net, sent_ip_overhead_bytes)
		METRIC(net, sent_tracker_bytes)
		METRIC(net, recv_payload_bytes)
		METRIC(net, recv_bytes)
		METRIC(net, recv_ip_overhead_bytes)
		METRIC(net, recv_tracker_bytes)

		// the number of sockets currently waiting for upload and download
		// bandwidth from the rate limiter.
		METRIC(net, limiter_up_queue)
		METRIC(net, limiter_down_queue)

		// the number of upload and download bytes waiting to be handed out from
		// the rate limiter.
		METRIC(net, limiter_up_bytes)
		METRIC(net, limiter_down_bytes)

		// the number of bytes downloaded that had to be discarded because they
		// failed the hash check
		METRIC(net, recv_failed_bytes)

		// the number of downloaded bytes that were discarded because they
		// were downloaded multiple times (from different peers)
		METRIC(net, recv_redundant_bytes)

		// is false by default and set to true when
		// the first incoming connection is established
		// this is used to know if the client is behind
		// NAT or not.
		METRIC(net, has_incoming_connections)

		// The number of nodes in the DHT routing table
		METRIC(dht, dht_nodes)

		// The number of replacement nodes in the DHT routing table
		METRIC(dht, dht_node_cache)

		// the number of torrents currently tracked by our DHT node
		METRIC(dht, dht_torrents)

		// the number of peers currently tracked by our DHT node
		METRIC(dht, dht_peers)

		// the number of immutable data items tracked by our DHT node
		METRIC(dht, dht_immutable_data)

		// the number of mutable data items tracked by our DHT node
		METRIC(dht, dht_mutable_data)

		// the number of RPC observers currently allocated
		METRIC(dht, dht_allocated_observers)

		// the total number of DHT messages sent and received
		METRIC(dht, dht_messages_in)
		METRIC(dht, dht_messages_out)

		// the number of incoming DHT requests that were dropped. There are a few
		// different reasons why incoming DHT packets may be dropped:
		//
		// 1. there wasn't enough send quota to respond to them.
		// 2. the Denial of service logic kicked in, blocking the peer
		// 3. ignore_dark_internet is enabled, and the packet came from a
		//    non-public IP address
		// 4. the bencoding of the message was invalid
		METRIC(dht, dht_messages_in_dropped)

		// the number of outgoing messages that failed to be
		// sent
		METRIC(dht, dht_messages_out_dropped)

		// the total number of bytes sent and received by the DHT
		METRIC(dht, dht_bytes_in)
		METRIC(dht, dht_bytes_out)

		// the number of DHT messages we've sent and received
		// by kind.
		METRIC(dht, dht_ping_in)
		METRIC(dht, dht_ping_out)
		METRIC(dht, dht_find_node_in)
		METRIC(dht, dht_find_node_out)
		METRIC(dht, dht_get_peers_in)
		METRIC(dht, dht_get_peers_out)
		METRIC(dht, dht_announce_peer_in)
		METRIC(dht, dht_announce_peer_out)
		METRIC(dht, dht_get_in)
		METRIC(dht, dht_get_out)
		METRIC(dht, dht_put_in)
		METRIC(dht, dht_put_out)
		METRIC(dht, dht_sample_infohashes_in)
		METRIC(dht, dht_sample_infohashes_out)
		METRIC(dht, dht_invoked_requests)

		// the number of failed incoming DHT requests by kind of request
		METRIC(dht, dht_invalid_announce)
		METRIC(dht, dht_invalid_get_peers)
		METRIC(dht, dht_invalid_find_node)
		METRIC(dht, dht_invalid_put)
		METRIC(dht, dht_invalid_get)
		METRIC(dht, dht_invalid_sample_infohashes)

		// the buffer sizes accepted by
		// socket send and receive calls respectively.
		// The larger the buffers are, the more efficient,
		// because it reqire fewer system calls per byte.
		// The size is 1 << n, where n is the number
		// at the end of the counter name. i.e.
		// 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
		// 16384, 32768, 65536, 131072, 262144, 524288, 1048576
		// bytes
		METRIC(sock_bufs, socket_send_size3)
		METRIC(sock_bufs, socket_recv_size3)

		// if the outstanding tracker announce limit is reached, tracker
		// announces are queued, to be issued when an announce slot opens up.
		// this measure the number of tracker announces currently in the
		// queue
		METRIC(tracker, num_queued_tracker_announces)
		// ... more
	}});
#undef METRIC
	} // anonymous namespace

	std::vector<stats_metric> session_stats_metrics()
	{
		aux::vector<stats_metric> stats;
		stats.resize(metrics.size());
		for (int i = 0; i < metrics.end_index(); ++i)
		{
			stats[i].name = metrics[i].name;
			stats[i].value_index = metrics[i].value_index;
			stats[i].type = metrics[i].value_index >= counters::num_stats_counters
				? metric_type_t::gauge : metric_type_t::counter;
		}
		return std::move(stats);
	}

	int find_metric_idx(string_view name)
	{
		auto const i = std::find_if(std::begin(metrics), std::end(metrics)
			, [name](stats_metric_impl const& metr)
			{ return metr.name == name; });

		if (i == std::end(metrics)) return -1;
		return i->value_index;
	}
}
