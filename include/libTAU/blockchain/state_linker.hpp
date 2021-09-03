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

        state_linker(const sha256_hash &mBlockHash,
                     std::map<dht::public_key, sha256_hash> mLastChangeBlockHashMap) : m_block_hash(mBlockHash),
                     m_last_change_block_hash_map(std::move(mLastChangeBlockHashMap)) {}

        const std::map<dht::public_key, sha256_hash> &get_last_change_block_hash_map() const { return m_last_change_block_hash_map; }

        void set_last_change_block_hash_map(const std::map<dht::public_key, sha256_hash> &mLastChangeBlockHashMap) { m_last_change_block_hash_map = mLastChangeBlockHashMap; }

        void insert(dht::public_key pubKey, sha256_hash last_change_block_hash) { m_last_change_block_hash_map[pubKey] = last_change_block_hash; };

        const sha256_hash &block_hash() const { return m_block_hash; }

        bool empty() { return m_block_hash.is_all_zeros(); }

        entry get_entry() const;

        std::string get_encode() const;

    private:

        // populate state linker data from entry
        void populate(const entry& e);

        // block hash
        sha256_hash m_block_hash;

        // last change block hash map
        std::map<dht::public_key, sha256_hash> m_last_change_block_hash_map;
    };
}

#endif //LIBTAU_STATE_LINKER_HPP
