/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_INDEX_KEY_INFO_HPP
#define LIBTAU_INDEX_KEY_INFO_HPP


#include <set>
#include <utility>
#include <ostream>

#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"
#include "libTAU/sha1_hash.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/kademlia/types.hpp"

namespace libTAU::blockchain {
    class index_key_info {

    public:

        index_key_info() = default;

        // @param Construct with entry
        explicit index_key_info(const entry& e);

        // @param Construct with bencode
        explicit index_key_info(std::string encode): index_key_info(bdecode(encode)) {}

        explicit index_key_info(const sha256_hash &mMainChainBlockHash) : m_main_chain_block_hash(mMainChainBlockHash) {}

        index_key_info(const sha256_hash &mMainChainBlockHash, std::set<dht::public_key> mAssociatedPeers)
                : m_main_chain_block_hash(mMainChainBlockHash), m_associated_peers(std::move(mAssociatedPeers)) {}

        index_key_info(const sha256_hash &mMainChainBlockHash, std::set<sha256_hash> mNonMainChainBlockHashSet,
                       std::set<dht::public_key> mAssociatedPeers) :
                       m_main_chain_block_hash(mMainChainBlockHash),
                       m_non_main_chain_block_hash_set(std::move(mNonMainChainBlockHashSet)),
                       m_associated_peers(std::move(mAssociatedPeers)) {}

        const sha256_hash &main_chain_block_hash() const { return m_main_chain_block_hash; }

        void set_main_chain_block_hash(const sha256_hash &mMainChainBlockHash) { m_main_chain_block_hash = mMainChainBlockHash; }

        const std::set<sha256_hash> &non_main_chain_block_hash_set() const { return m_non_main_chain_block_hash_set; }

        void set_non_main_chain_block_hash_set(const std::set<sha256_hash> &mNonMainChainBlockHashSet) { m_non_main_chain_block_hash_set = mNonMainChainBlockHashSet; }

        const std::set<dht::public_key> &associated_peers() const { return m_associated_peers; }

        void set_associated_peers(const std::set<dht::public_key> &mAssociatedPeers) { m_associated_peers = mAssociatedPeers; }

        void clear_main_chain_block_hash() { m_main_chain_block_hash.clear(); }

        void clear_associated_peers() { m_associated_peers.clear(); }

        void add_non_main_chain_block_hash(sha256_hash hash) { m_non_main_chain_block_hash_set.insert(hash); }

        bool empty() const { return m_main_chain_block_hash.is_all_zeros() && m_non_main_chain_block_hash_set.empty(); }

        entry get_entry() const;

        std::string get_encode() const;

        // @returns a pretty-printed string representation of block structure
        std::string to_string() const;

        friend std::ostream &operator<<(std::ostream &os, const index_key_info &info);

    private:

        // populate index key info from entry
        void populate(const entry& e);

        // block hash on main chain
        sha256_hash m_main_chain_block_hash;

        // block hash no non-main chain
        std::set<sha256_hash> m_non_main_chain_block_hash_set;

        // associated peers
        std::set<dht::public_key> m_associated_peers;
    };
}


#endif //LIBTAU_INDEX_KEY_INFO_HPP
