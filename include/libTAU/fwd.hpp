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

#include "libTAU/config.hpp"

namespace libTAU {

// include/libTAU/add_torrent_params.hpp
TORRENT_VERSION_NAMESPACE_3
struct add_torrent_params;
TORRENT_VERSION_NAMESPACE_3_END

// include/libTAU/alert.hpp
struct alert;

// include/libTAU/alert_types.hpp
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
struct communication_friend_info_alert;
TORRENT_VERSION_NAMESPACE_3_END

// include/libTAU/announce_entry.hpp
TORRENT_VERSION_NAMESPACE_2
struct announce_infohash;
struct announce_endpoint;
struct announce_entry;
TORRENT_VERSION_NAMESPACE_2_END

// include/libTAU/bdecode.hpp
struct bdecode_node;

// include/libTAU/bitfield.hpp
struct bitfield;

// include/libTAU/client_data.hpp
struct client_data_t;

// include/libTAU/create_torrent.hpp
struct create_torrent;

// include/libTAU/disk_buffer_holder.hpp
struct buffer_allocator_interface;
struct disk_buffer_holder;

// include/libTAU/disk_interface.hpp
struct open_file_state;
struct disk_interface;
struct storage_holder;

// include/libTAU/disk_observer.hpp
struct disk_observer;

// include/libTAU/entry.hpp
struct entry;

// include/libTAU/error_code.hpp
struct storage_error;

// include/libTAU/extensions.hpp
TORRENT_VERSION_NAMESPACE_3
struct plugin;
TORRENT_VERSION_NAMESPACE_3_END
struct torrent_plugin;
struct peer_plugin;
struct crypto_plugin;

// include/libTAU/file_storage.hpp
struct file_slice;
TORRENT_VERSION_NAMESPACE_4
class file_storage;
TORRENT_VERSION_NAMESPACE_4_END

// include/libTAU/hasher.hpp
TORRENT_CRYPTO_NAMESPACE
class hasher;
class hasher256;
TORRENT_CRYPTO_NAMESPACE_END

// include/libTAU/info_hash.hpp
struct info_hash_t;

// include/libTAU/ip_filter.hpp
struct ip_filter;
class port_filter;

// include/libTAU/kademlia/dht_state.hpp
namespace dht {
struct dht_state;
}

// include/libTAU/kademlia/dht_storage.hpp
namespace dht {
struct dht_storage_counters;
}
namespace dht {
struct dht_storage_interface;
}

// include/libTAU/peer_class.hpp
struct peer_class_info;

// include/libTAU/peer_class_type_filter.hpp
struct peer_class_type_filter;

// include/libTAU/peer_connection_handle.hpp
struct peer_connection_handle;
struct bt_peer_connection_handle;

// include/libTAU/peer_info.hpp
TORRENT_VERSION_NAMESPACE_2
struct peer_info;
TORRENT_VERSION_NAMESPACE_2_END

// include/libTAU/peer_request.hpp
struct peer_request;

// include/libTAU/performance_counters.hpp
struct counters;

// include/libTAU/piece_block.hpp
struct piece_block;

// include/libTAU/session.hpp
struct session_proxy;
struct session;

// include/libTAU/session_handle.hpp
struct session_handle;

// include/libTAU/session_params.hpp
TORRENT_VERSION_NAMESPACE_3
struct session_params;
TORRENT_VERSION_NAMESPACE_3_END

// include/libTAU/session_stats.hpp
struct stats_metric;

// include/libTAU/settings_pack.hpp
struct settings_interface;
struct settings_pack;

// include/libTAU/storage_defs.hpp
struct storage_params;

// include/libTAU/torrent_handle.hpp
struct block_info;
struct partial_piece_info;
struct torrent_handle;

// include/libTAU/torrent_info.hpp
struct web_seed_entry;
struct load_torrent_limits;
TORRENT_VERSION_NAMESPACE_3
class torrent_info;
TORRENT_VERSION_NAMESPACE_3_END

// include/libTAU/torrent_status.hpp
TORRENT_VERSION_NAMESPACE_3
struct torrent_status;
TORRENT_VERSION_NAMESPACE_3_END

#if TORRENT_ABI_VERSION <= 2

// include/libTAU/alert_types.hpp
TORRENT_VERSION_NAMESPACE_3
struct torrent_added_alert;
struct stats_alert;
struct anonymous_mode_alert;
struct mmap_cache_alert;
TORRENT_VERSION_NAMESPACE_3_END

// include/libTAU/file_storage.hpp
struct file_entry;

// include/libTAU/fingerprint.hpp
struct fingerprint;

// include/libTAU/kademlia/dht_settings.hpp
namespace dht {
struct dht_settings;
}

// include/libTAU/session_settings.hpp
struct pe_settings;

// include/libTAU/session_status.hpp
struct utp_status;
struct session_status;

#endif // TORRENT_ABI_VERSION

}

namespace lt = libTAU;

#endif // TORRENT_FWD_HPP
