/*

Copyright (c) 2017-2018, Steven Siloti
Copyright (c) 2017-2021, Arvid Norberg
Copyright (c) 2020, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.

*/

#ifndef TORRENT_FWD_HPP
#define TORRENT_FWD_HPP

#include "libtorrent/config.hpp"

namespace libtorrent {

// include/libtorrent/add_torrent_params.hpp
TORRENT_VERSION_NAMESPACE_3
struct add_torrent_params;
TORRENT_VERSION_NAMESPACE_3_END

// include/libtorrent/alert.hpp
struct alert;

// include/libtorrent/alert_types.hpp
struct dht_routing_bucket;
TORRENT_VERSION_NAMESPACE_3
struct torrent_alert;
struct peer_alert;
struct udp_error_alert;
struct external_ip_alert;
struct listen_failed_alert;
struct listen_succeeded_alert;
struct portmap_error_alert;
struct portmap_alert;
struct portmap_log_alert;
struct dht_announce_alert;
struct dht_get_peers_alert;
struct dht_bootstrap_alert;
struct torrent_error_alert;
struct incoming_connection_alert;
struct state_update_alert;
struct session_stats_alert;
struct dht_error_alert;
struct dht_immutable_item_alert;
struct dht_mutable_item_alert;
struct dht_put_alert;
struct dht_outgoing_get_peers_alert;
struct log_alert;
struct peer_log_alert;
struct dht_lookup;
struct dht_stats_alert;
struct dht_log_alert;
struct dht_pkt_alert;
struct dht_get_peers_reply_alert;
struct dht_direct_response_alert;
struct picker_log_alert;
struct session_error_alert;
struct dht_live_nodes_alert;
struct session_stats_header_alert;
struct dht_sample_infohashes_alert;
struct alerts_dropped_alert;
struct socks5_alert;
struct communication_new_device_id_alert;
struct communication_new_message_alert;
struct communication_confirmation_root_alert;
struct communication_syncing_message_alert;
TORRENT_VERSION_NAMESPACE_3_END

// include/libtorrent/announce_entry.hpp
TORRENT_VERSION_NAMESPACE_2
struct announce_infohash;
struct announce_endpoint;
struct announce_entry;
TORRENT_VERSION_NAMESPACE_2_END

// include/libtorrent/bdecode.hpp
struct bdecode_node;

// include/libtorrent/bitfield.hpp
struct bitfield;

// include/libtorrent/client_data.hpp
struct client_data_t;

// include/libtorrent/create_torrent.hpp
struct create_torrent;

// include/libtorrent/disk_buffer_holder.hpp
struct buffer_allocator_interface;
struct disk_buffer_holder;

// include/libtorrent/disk_interface.hpp
struct open_file_state;
struct disk_interface;
struct storage_holder;

// include/libtorrent/disk_observer.hpp
struct disk_observer;

// include/libtorrent/entry.hpp
struct entry;

// include/libtorrent/error_code.hpp
struct storage_error;

// include/libtorrent/extensions.hpp
TORRENT_VERSION_NAMESPACE_3
struct plugin;
TORRENT_VERSION_NAMESPACE_3_END
struct torrent_plugin;
struct peer_plugin;
struct crypto_plugin;

// include/libtorrent/file_storage.hpp
struct file_slice;
TORRENT_VERSION_NAMESPACE_4
class file_storage;
TORRENT_VERSION_NAMESPACE_4_END

// include/libtorrent/hasher.hpp
TORRENT_CRYPTO_NAMESPACE
class hasher;
class hasher256;
TORRENT_CRYPTO_NAMESPACE_END

// include/libtorrent/info_hash.hpp
struct info_hash_t;

// include/libtorrent/ip_filter.hpp
struct ip_filter;
class port_filter;

// include/libtorrent/kademlia/dht_state.hpp
namespace dht {
struct dht_state;
}

// include/libtorrent/kademlia/dht_storage.hpp
namespace dht {
struct dht_storage_counters;
}
namespace dht {
struct dht_storage_interface;
}

// include/libtorrent/peer_class.hpp
struct peer_class_info;

// include/libtorrent/peer_class_type_filter.hpp
struct peer_class_type_filter;

// include/libtorrent/peer_connection_handle.hpp
struct peer_connection_handle;
struct bt_peer_connection_handle;

// include/libtorrent/peer_info.hpp
TORRENT_VERSION_NAMESPACE_2
struct peer_info;
TORRENT_VERSION_NAMESPACE_2_END

// include/libtorrent/peer_request.hpp
struct peer_request;

// include/libtorrent/performance_counters.hpp
struct counters;

// include/libtorrent/piece_block.hpp
struct piece_block;

// include/libtorrent/session.hpp
struct session_proxy;
struct session;

// include/libtorrent/session_handle.hpp
struct session_handle;

// include/libtorrent/session_params.hpp
TORRENT_VERSION_NAMESPACE_3
struct session_params;
TORRENT_VERSION_NAMESPACE_3_END

// include/libtorrent/session_stats.hpp
struct stats_metric;

// include/libtorrent/settings_pack.hpp
struct settings_interface;
struct settings_pack;

// include/libtorrent/storage_defs.hpp
struct storage_params;

// include/libtorrent/torrent_handle.hpp
struct block_info;
struct partial_piece_info;
struct torrent_handle;

// include/libtorrent/torrent_info.hpp
struct web_seed_entry;
struct load_torrent_limits;
TORRENT_VERSION_NAMESPACE_3
class torrent_info;
TORRENT_VERSION_NAMESPACE_3_END

// include/libtorrent/torrent_status.hpp
TORRENT_VERSION_NAMESPACE_3
struct torrent_status;
TORRENT_VERSION_NAMESPACE_3_END

#if TORRENT_ABI_VERSION <= 2

// include/libtorrent/alert_types.hpp
TORRENT_VERSION_NAMESPACE_3
struct torrent_added_alert;
struct stats_alert;
struct anonymous_mode_alert;
struct mmap_cache_alert;
TORRENT_VERSION_NAMESPACE_3_END

// include/libtorrent/file_storage.hpp
struct file_entry;

// include/libtorrent/fingerprint.hpp
struct fingerprint;

// include/libtorrent/kademlia/dht_settings.hpp
namespace dht {
struct dht_settings;
}

// include/libtorrent/session_settings.hpp
struct pe_settings;

// include/libtorrent/session_status.hpp
struct utp_status;
struct session_status;

#endif // TORRENT_ABI_VERSION

}

namespace lt = libtorrent;

#endif // TORRENT_FWD_HPP
