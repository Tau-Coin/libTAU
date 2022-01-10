/*

Copyright (c) 2006, 2008-2011, 2013-2020, Arvid Norberg
Copyright (c) 2016, Alden Torres
Copyright (c) 2017, Falcosc
Copyright (c) 2017, Falco
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_SESSION_STATUS_HPP_INCLUDED
#define TORRENT_SESSION_STATUS_HPP_INCLUDED

#include "libTAU/config.hpp"
#include "libTAU/aux_/export.hpp"
#include <vector>

// for dht_lookup and dht_routing_bucket
#include "libTAU/alert_types.hpp"

namespace libTAU {

	// contains session wide state and counters
	// deprecated in 1.1 in favor of session_stats counters, which is a more
	// flexible, extensible and performant mechanism for stats.
	struct session_status
	{
		// false as long as no incoming connections have been
		// established on the listening socket. Every time you change the listen port, this will
		// be reset to false.
		bool has_incoming_connections;

		// the total download and upload rates accumulated
		// from all torrents. This includes bittorrent protocol, DHT and an estimated TCP/IP
		// protocol overhead.
		// deprecated, use session_stats_metrics "net.recv_bytes" + "net.recv_ip_overhead_bytes"
		// they does include payload + protocol + ip overhead bytes
		int upload_rate;
		int download_rate;

		// the total number of bytes downloaded and
		// uploaded to and from all torrents. This also includes all the protocol overhead.
		// deprecated, use session_stats_metrics "net.recv_bytes" + "net.recv_ip_overhead_bytes"
		// they does include payload + protocol + ip overhead bytes
		std::int64_t total_download;
		std::int64_t total_upload;

		// the rate of the payload
		// down- and upload only.
		// deprecated, use session_stats_metrics "net.recv_payload_bytes"
		int payload_upload_rate;
		// deprecated, use session_stats_metrics "net.sent_payload_bytes"
		int payload_download_rate;

		// the total transfers of payload
		// only. The payload does not include the bittorrent protocol overhead, but only parts of the
		// actual files to be downloaded.
		// ``total_payload_download`` is deprecated, use session_stats_metrics
		// "net.recv_payload_bytes" ``total_payload_upload`` is deprecated, use
		// session_stats_metrics "net.sent_payload_bytes"
		std::int64_t total_payload_download;
		std::int64_t total_payload_upload;

		// the estimated TCP/IP overhead in each direction.
		int ip_overhead_upload_rate;
		int ip_overhead_download_rate;
		std::int64_t total_ip_overhead_download;
		std::int64_t total_ip_overhead_upload;

		// the upload and download rate used by DHT traffic. Also the total number
		// of bytes sent and received to and from the DHT.
		int dht_upload_rate;
		int dht_download_rate;
		std::int64_t total_dht_download;
		std::int64_t total_dht_upload;

		// the upload and download rate used by tracker traffic. Also the total number
		// of bytes sent and received to and from trackers.
		int tracker_upload_rate;
		int tracker_download_rate;
		std::int64_t total_tracker_download;
		std::int64_t total_tracker_upload;

		// the number of bytes that has been received more than once.
		// This can happen if a request from a peer times out and is requested from a different
		// peer, and then received again from the first one. To make this lower, increase the
		// ``request_timeout`` and the ``piece_timeout`` in the session settings.
		std::int64_t total_redundant_bytes;

		// the number of bytes that was downloaded which later failed
		// the hash-check.
		std::int64_t total_failed_bytes;

		// the number of peers that are
		// waiting for more bandwidth quota from the torrent rate limiter.
		int up_bandwidth_queue;
		int down_bandwidth_queue;

		// count the number of
		// bytes the connections are waiting for to be able to send and receive.
		int up_bandwidth_bytes_queue;
		int down_bandwidth_bytes_queue;

		// only available when
		// built with DHT support. They are all set to 0 if the DHT isn't running. When
		// the DHT is running, ``dht_nodes`` is set to the number of nodes in the routing
		// table. This number only includes *active* nodes, not cache nodes. The
		// ``dht_node_cache`` is set to the number of nodes in the node cache. These nodes
		// are used to replace the regular nodes in the routing table in case any of them
		// becomes unresponsive.
		// deprecated, use session_stats_metrics "dht.dht_nodes" and "dht.dht_nodes_cache"
		int dht_nodes;
		int dht_node_cache;

		// an estimation of the total number of nodes in the DHT
		// network.
		std::int64_t dht_global_nodes;

		// the number of nodes allocated dynamically for a
		// particular DHT lookup. This represents roughly the amount of memory used
		// by the DHT.
		int dht_total_allocations;
	};
}

#endif // TORRENT_SESSION_STATUS_HPP_INCLUDED
