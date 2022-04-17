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

    // 状态链接器：每个区块都会对应一个状态链接器，状态链接器通过previous change指针，可以完整回溯该账户的变化历史，
    // 同时，由于需要支持边同步边挖矿，新同步的区块涉及的账户的状态存在难以被其前一个链接器的previous change链接的情况，
    // 该账户指向区块的最新的状态连接器需要记录区块链尾部最新同步的状态，以便能让该账户状态在回滚时能正确地链接上
    class TORRENT_EXPORT state_linker {

    public:

        state_linker() = default;

        // @param Construct with entry
        explicit state_linker(const entry& e);

        // @param Construct with bencode
        explicit state_linker(std::string encode): state_linker(bdecode(encode)) {}

        explicit state_linker(const sha256_hash &mBlockHash) : m_block_hash(mBlockHash) {}

        state_linker(const sha256_hash &mBlockHash,
                     std::map<dht::public_key, sha256_hash> mNextChangeBlockHashMap,
                     std::map<dht::public_key, sha256_hash> mPreviousChangeBlockHashMap) :
                     m_block_hash(mBlockHash), m_next_change_block_hash_map(std::move(mNextChangeBlockHashMap)),
                     m_previous_change_block_hash_map(std::move(mPreviousChangeBlockHashMap)) {}

        const std::map<dht::public_key, sha256_hash> &get_next_change_block_hash_map() const { return m_next_change_block_hash_map; }

        const std::map<dht::public_key, sha256_hash> &get_previous_change_block_hash_map() const { return m_previous_change_block_hash_map; }

        void set_previous_change_block_hash_map(const std::map<dht::public_key, sha256_hash> &mPreviousChangeBlockHashMap) { m_previous_change_block_hash_map = mPreviousChangeBlockHashMap; }

        void update_next_change_block_hash(dht::public_key pubKey, sha256_hash next_change_block_hash) { m_next_change_block_hash_map[pubKey] = next_change_block_hash; }

        void update_previous_change_block_hash(dht::public_key pubKey, sha256_hash previous_change_block_hash) { m_previous_change_block_hash_map[pubKey] = previous_change_block_hash; }

        sha256_hash get_peer_next_change_block_hash(const dht::public_key& pubKey) { return m_next_change_block_hash_map[pubKey]; }

        sha256_hash get_peer_previous_change_block_hash(const dht::public_key& pubKey) { return m_previous_change_block_hash_map[pubKey]; }

        const sha256_hash &block_hash() const { return m_block_hash; }

        bool empty() { return m_block_hash.is_all_zeros(); }

        entry get_entry() const;

        std::string get_encode() const;

        // @returns a pretty-printed string representation of block structure
        std::string to_string() const;

        friend std::ostream &operator<<(std::ostream &os, const state_linker &stateLinker);

    private:

        // populate state linker data from entry
        void populate(const entry& e);

        // block hash
        sha256_hash m_block_hash;

        // next change block hash map
        std::map<dht::public_key, sha256_hash> m_next_change_block_hash_map;

        // previous change block hash map
        std::map<dht::public_key, sha256_hash> m_previous_change_block_hash_map;
    };
}

#endif //LIBTAU_STATE_LINKER_HPP
