/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_STATE_LINKER_HPP
#define LIBTAU_STATE_LINKER_HPP


#include <utility>
#include <map>
#include "libTAU/kademlia/item.hpp"
#include "libTAU/blockchain/block.hpp"


namespace libTAU::blockchain {
    class TORRENT_EXPORT state_linker {

    public:

        state_linker() = default;

        // @param Construct with entry
        explicit state_linker(const entry& e);

        // @param Construct with bencode
        explicit state_linker(std::string encode): state_linker(bdecode(encode)) {}

        explicit state_linker(const sha256_hash &mBlockHash) : m_block_hash(mBlockHash) {}

        state_linker(const sha256_hash &mBlockHash,
                     std::map<dht::public_key, sha256_hash> mPreviousChangeBlockHashMap,
                     std::map<dht::public_key, sha256_hash> mLastChangeBlockHashMap) :
                     m_block_hash(mBlockHash), m_previous_change_block_hash_map(std::move(mPreviousChangeBlockHashMap)),
                     m_last_change_block_hash_map(std::move(mLastChangeBlockHashMap)) {}

        const std::map<dht::public_key, sha256_hash> &get_previous_change_block_hash_map() const { return m_previous_change_block_hash_map; }

        const std::map<dht::public_key, sha256_hash> &get_last_change_block_hash_map() const { return m_last_change_block_hash_map; }

        void set_last_change_block_hash_map(const std::map<dht::public_key, sha256_hash> &mLastChangeBlockHashMap) { m_last_change_block_hash_map = mLastChangeBlockHashMap; }

        void set_previous_change_block_hash_map(const std::map<dht::public_key, sha256_hash> &mPreviousChangeBlockHashMap) { m_previous_change_block_hash_map = mPreviousChangeBlockHashMap; }

        void update_previous_change_block_hash(dht::public_key pubKey, sha256_hash previous_change_block_hash) { m_previous_change_block_hash_map[pubKey] = previous_change_block_hash; }

        void update_last_change_block_hash(dht::public_key pubKey, sha256_hash last_change_block_hash) { m_last_change_block_hash_map[pubKey] = last_change_block_hash; }

        sha256_hash get_peer_previous_change_block_hash(const dht::public_key& pubKey) { return m_previous_change_block_hash_map[pubKey]; }

        sha256_hash get_peer_last_change_block_hash(const dht::public_key& pubKey) { return m_last_change_block_hash_map[pubKey]; }

        const sha256_hash &block_hash() const { return m_block_hash; }

        bool empty() { return m_block_hash.is_all_zeros(); }

        entry get_entry() const;

        std::string get_encode() const;

    private:

        // populate state linker data from entry
        void populate(const entry& e);

        // block hash
        sha256_hash m_block_hash;

        // previous change block hash map
        std::map<dht::public_key, sha256_hash> m_previous_change_block_hash_map;

        // last change block hash map
        std::map<dht::public_key, sha256_hash> m_last_change_block_hash_map;
    };
}

#endif //LIBTAU_STATE_LINKER_HPP
