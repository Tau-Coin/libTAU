/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BLOCKCHAIN_SIGNAL_HPP
#define LIBTAU_BLOCKCHAIN_SIGNAL_HPP


#include <set>
#include <map>
#include <utility>

#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/sha1_hash.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/kademlia/types.hpp"
#include "libTAU/communication/immutable_data_info.hpp"


namespace libTAU::blockchain {
    using immutable_data_info = communication::immutable_data_info;

    class blockchain_signal {
    public:
        // @param Construct with entry
        explicit blockchain_signal(const entry& e);

        // @param Construct with bencode
        explicit blockchain_signal(std::string encode): blockchain_signal(bdecode(encode)) {}

        blockchain_signal(const sha256_hash &mConsensusPointBlockHash, int64_t mConsensusPointBlockNumber,
                          immutable_data_info mBestBlock, immutable_data_info mImmutableBlock,
                          std::set<immutable_data_info> mBlockSet, std::set<immutable_data_info> mTxSet,
                          std::set<sha256_hash> mDemandBlockHashSet,
                          std::set<sha256_hash> mDemandTxHashSet, aux::bytes mTxHashPrefixArray)
                : m_consensus_point_block_hash(mConsensusPointBlockHash),
                  m_consensus_point_block_number(mConsensusPointBlockNumber), m_best_block(std::move(mBestBlock)),
                  m_immutable_block(std::move(mImmutableBlock)), m_block_set(std::move(mBlockSet)), m_tx_set(std::move(mTxSet)),
                  m_demand_block_hash_set(std::move(mDemandBlockHashSet)), m_demand_tx_hash_set(std::move(mDemandTxHashSet)),
                  m_tx_hash_prefix_array(std::move(mTxHashPrefixArray)) {}

        const sha256_hash &get_consensus_point_block_hash() const { return m_consensus_point_block_hash; }

        void set_consensus_point_block_hash(const sha256_hash &mConsensusPointBlockHash) { m_consensus_point_block_hash = mConsensusPointBlockHash; }

        int64_t get_consensus_point_block_number() const { return m_consensus_point_block_number; }

        void set_consensus_point_block_number(int64_t mConsensusPointBlockNumber) { m_consensus_point_block_number = mConsensusPointBlockNumber; }

        const immutable_data_info &get_best_block() const { return m_best_block; }

        void set_best_block(const immutable_data_info &mBestBlock) { m_best_block = mBestBlock; }

        const immutable_data_info &get_immutable_block() const { return m_immutable_block; }

        void set_immutable_block(const immutable_data_info &mImmutableBlock) { m_immutable_block = mImmutableBlock; }

        const std::set<immutable_data_info> &get_block_set() const { return m_block_set; }

        void set_block_set(const std::set<immutable_data_info> &mBlockSet) { m_block_set = mBlockSet; }

        const std::set<immutable_data_info> &get_tx_set() const { return m_tx_set; }

        void set_tx_set(const std::set<immutable_data_info> &mTxSet) { m_tx_set = mTxSet; }

        const std::set<sha256_hash> &get_demand_block_hash_set() const { return m_demand_block_hash_set; }

        void set_demand_block_hash_set(const std::set<sha256_hash> &mDemandBlockHashSet) { m_demand_block_hash_set = mDemandBlockHashSet; }

        const std::set<sha256_hash> &get_demand_tx_hash_set() const { return m_demand_tx_hash_set; }

        void set_demand_tx_hash_set(const std::set<sha256_hash> &mDemandTxHashSet) { m_demand_tx_hash_set = mDemandTxHashSet; }

        const aux::bytes &get_tx_hash_prefix_array() const { return m_tx_hash_prefix_array; }

        void set_tx_hash_prefix_array(const aux::bytes &mTxHashPrefixArray) { m_tx_hash_prefix_array = mTxHashPrefixArray; }

        entry get_entry() const;

        std::string get_encode() const;

    private:
        // populate block chain signal info from entry
        void populate(const entry& e);

        sha256_hash m_consensus_point_block_hash;

        std::int64_t m_consensus_point_block_number{};

        immutable_data_info m_best_block;

        immutable_data_info m_immutable_block;

        std::set<immutable_data_info> m_block_set;

        std::set<immutable_data_info> m_tx_set;

        std::set<sha256_hash> m_demand_block_hash_set;

        std::set<sha256_hash> m_demand_tx_hash_set;

        aux::bytes m_tx_hash_prefix_array;
    };
}


#endif //LIBTAU_BLOCKCHAIN_SIGNAL_HPP
