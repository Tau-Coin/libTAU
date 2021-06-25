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

#include <libtorrent/kademlia/node_id.hpp>
#include <libtorrent/kademlia/types.hpp>

#include <libtorrent/socket.hpp>
#include <libtorrent/address.hpp>
#include <libtorrent/span.hpp>
#include <libtorrent/string_view.hpp>

namespace libtorrent {
	struct entry;
	struct settings_interface;
}

namespace libtorrent {
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
	// libtorrent comes with one built-in storage implementation:
	// ``dht_default_storage`` (private non-accessible class). Its
	// constructor function is called dht_default_storage_constructor().
	// You should know that if this storage becomes full of DHT items,
	// the current implementation could degrade in performance.
	struct TORRENT_EXPORT dht_storage_interface
	{
		// This member function notifies the list of all node's ids
		// of each DHT running inside libtorrent. It's advisable
		// that the concrete implementation keeps a copy of this list
		// for an eventual prioritization when deleting an element
		// to make room for a new one.
		virtual void update_node_ids(std::vector<node_id> const& ids) = 0;

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

		// This function retrieves the sequence number of a mutable item.
		//
		// returns true if the item is found and the data is returned
		// inside the out parameter seq.
		virtual bool get_mutable_item_seq(sha256_hash const& target
			, sequence_number& seq) const = 0;

		// This function retrieves the mutable stored in the DHT.
		//
		// For implementers:
		// The item sequence should be stored in the key item["seq"].
		// if force_fill is true or (0 <= seq and seq < item["seq"])
		// the following keys should be filled
		// item["v"] - with the value no encoded.
		// item["sig"] - with a string representation of the signature.
		// item["k"] - with a string representation of the public key.
		//
		// returns true if the item is found and the data is returned
		// inside the (entry) out parameter item.
		virtual bool get_mutable_item(sha256_hash const& target
			, sequence_number seq, bool force_fill
			, entry& item) const = 0;

		// Store the item's data. This layer is only for storage.
		// The authentication of the item is performed by the upper layer.
		//
		// For implementers:
		// The sequence number should be checked if the item is already
		// present. The implementation should consider the value of
		// settings_pack::dht_max_dht_items.
		//
		virtual void put_mutable_item(sha256_hash const& target
			, span<char const> buf
			, signature const& sig
			, sequence_number seq
			, public_key const& pk
			, span<char const> salt
			, address const& addr) = 0;

		// This function is called periodically (non-constant frequency).
		//
		// For implementers:
		// Use this functions for expire peers or items or any other
		// storage cleanup.
		virtual void tick() = 0;

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
} // namespace libtorrent

#endif //TORRENT_DHT_STORAGE_HPP
