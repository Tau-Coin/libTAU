/*

Copyright (c) 2015-2020, Arvid Norberg
Copyright (c) 2015-2017, Alden Torres
Copyright (c) 2016, Steven Siloti
Copyright (c) 2019, Mike Tzou
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_DHT_STORAGE_HPP
#define TORRENT_DHT_STORAGE_HPP

#include <functional>

#include <libTAU/kademlia/node_id.hpp>
#include <libTAU/kademlia/types.hpp>
#include <libTAU/kademlia/node_entry.hpp>
#include <libTAU/kademlia/relay.hpp>

#include <libTAU/socket.hpp>
#include <libTAU/address.hpp>
#include <libTAU/span.hpp>
#include <libTAU/string_view.hpp>

namespace libTAU {
	struct entry;
	struct settings_interface;
}

namespace libTAU {
namespace dht {

	// This structure hold the relevant counters for the storage
	struct TORRENT_EXPORT dht_storage_counters
	{
		std::int32_t torrents = 0;
		std::int32_t peers = 0;
		std::int32_t immutable_data = 0;
		std::int32_t mutable_data = 0;

		// This member function set the counters to zero.
		void reset();
	};

	// The DHT storage interface is a pure virtual class that can
	// be implemented to customize how the data for the DHT is stored.
	//
	// The default storage implementation uses three maps in RAM to save
	// the peers, mutable and immutable items and it's designed to
	// provide a fast and fully compliant behavior of the BEPs.
	//
	// libTAU comes with one built-in storage implementation:
	// ``dht_default_storage`` (private non-accessible class). Its
	// constructor function is called dht_default_storage_constructor().
	// You should know that if this storage becomes full of DHT items,
	// the current implementation could degrade in performance.
	struct TORRENT_EXPORT dht_storage_interface
	{
		// This member function notifies the list of all node's ids
		// of each DHT running inside libTAU. It's advisable
		// that the concrete implementation keeps a copy of this list
		// for an eventual prioritization when deleting an element
		// to make room for a new one.
		virtual void update_node_ids(std::vector<node_id> const& ids) = 0;

		// This member function sets backend database for dht storage.
		//
		// Persistence of immutable or mutable items.
		virtual void set_backend(std::shared_ptr<dht_storage_interface> backend) = 0;

		// This function retrieves the immutable item given its target hash.
		//
		// For future implementers:
		// The value should be returned as an entry in the key item["v"].
		//
		// returns true if the item is found and the data is returned
		// inside the (entry) out parameter item.
		virtual bool get_immutable_item(sha256_hash const& target
			, entry& item) const = 0;

		// Store the item's data. This layer is only for storage.
		// The authentication of the item is performed by the upper layer.
		//
		// For implementers:
		// This data can be stored only if the target is not already
		// present. The implementation should consider the value of
		// settings_pack::dht_max_dht_items.
		//
		virtual void put_immutable_item(sha256_hash const& target
			, span<char const> buf
			, address const& addr) = 0;

		// This function retrieves the timestamp of a mutable item.
		//
		// returns true if the item is found and the data is returned
		// inside the out parameter ts.
		virtual bool get_mutable_item_timestamp(sha256_hash const& target
			, timestamp& ts) const = 0;

		// This function retrieves the mutable stored in the DHT.
		//
		// For implementers:
		// The item timestamp should be stored in the key item["ts"].
		// if force_fill is true or (0 <= ts and ts < item["ts"])
		// the following keys should be filled
		// item["v"] - with the value no encoded.
		// item["sig"] - with a string representation of the signature.
		// item["k"] - with a string representation of the public key.
		//
		// returns true if the item is found and the data is returned
		// inside the (entry) out parameter item.
		virtual bool get_mutable_item(sha256_hash const& target
			, timestamp ts, bool force_fill
			, entry& item) const = 0;

		// get item target by the prefix
		virtual bool get_mutable_item_target(sha256_hash const& prefix
			, sha256_hash& target) const = 0;

		// Store the item's data. This layer is only for storage.
		// The authentication of the item is performed by the upper layer.
		//
		// For implementers:
		// The timestamp should be checked if the item is already
		// present. The implementation should consider the value of
		// settings_pack::dht_max_dht_items.
		//
		virtual void put_mutable_item(sha256_hash const& target
			, span<char const> buf
			, signature const& sig
			, timestamp ts
			, public_key const& pk
			, span<char const> salt
			, address const& addr) = 0;

		virtual void remove_mutable_item(sha256_hash const& target) = 0;

		// Store relay endpoints.
		virtual void relay_referred(node_id const& peer
			, node_entry const& ne) = 0;

		// Find relay endpoints
		virtual void find_relays(node_id const& peer
			, std::vector<node_entry>& l
			, int count, udp protocol) = 0;

		// Store relay entry.
		virtual void put_relay_entry(sha256_hash const& sender
			, sha256_hash const& receiver
			, span<char const> payload
			, span<char const> aux_nodes
			, udp protocol
			, relay_hmac const& hmac) = 0;

		// Get relay entry by key.
		virtual bool get_relay_entry(sha256_hash const& key
			, entry& re) const = 0;

		// get random relay entry key by receiver
		virtual bool get_random_relay_entry(sha256_hash const& receiver
			, sha256_hash& key) const = 0;

		// Remove relay entry by key.
		virtual void remove_relay_entry(sha256_hash const& key) = 0;

		// This function is called periodically (non-constant frequency).
		//
		// For implementers:
		// Use this functions for expire peers or items or any other
		// storage cleanup.
		virtual void tick() = 0;

		// close storage
		virtual void close() = 0;

		// return stats counters for the store
		virtual dht_storage_counters counters() const = 0;

		// hidden
		virtual ~dht_storage_interface() {}
	};

	using dht_storage_constructor_type
		= std::function<std::unique_ptr<dht_storage_interface>(settings_interface const& settings)>;

	// constructor for the default DHT storage. The DHT storage is responsible
	// for maintaining peers and mutable and immutable items announced and
	// stored/put to the DHT node.
	TORRENT_EXPORT std::unique_ptr<dht_storage_interface> dht_default_storage_constructor(
		settings_interface const& settings);

} // namespace dht
} // namespace libTAU

#endif //TORRENT_DHT_STORAGE_HPP
