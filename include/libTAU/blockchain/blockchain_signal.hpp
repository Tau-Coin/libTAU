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
#include "libTAU/blockchain/vote.hpp"
#include "libTAU/communication/immutable_data_info.hpp"


namespace libTAU::blockchain {
    using immutable_data_info = communication::immutable_data_info;

    class blockchain_signal {
    public:
        blockchain_signal() = default;

        // @param Construct with entry
        explicit blockchain_signal(const entry& e);

        // @param Construct with bencode
        explicit blockchain_signal(std::string encode): blockchain_signal(bdecode(encode)) {}

        blockchain_signal(int64_t mTimestamp, const vote &mConsensusPointVote, immutable_data_info mBestTipBlock,
                          immutable_data_info mImmutableBlockInfo, std::set<immutable_data_info> mBlockSet,
                          std::set<immutable_data_info> mTxSet, std::set<sha256_hash> mDemandBlockHashSet,
                          aux::bytes mTxHashPrefixArray):
                  m_timestamp(mTimestamp), m_consensus_point_vote(mConsensusPointVote), m_best_tip_block_info(std::move(mBestTipBlock)),
                  m_consensus_point_block_info(std::move(mImmutableBlockInfo)), m_block_info_set(std::move(mBlockSet)),
                  m_tx_info_set(std::move(mTxSet)), m_demand_block_hash_set(std::move(mDemandBlockHashSet)),
                  m_tx_hash_prefix_array(std::move(mTxHashPrefixArray)) {}

//        blockchain_signal(const sha256_hash &mConsensusPointBlockHash, int64_t mConsensusPointBlockNumber,
//                          immutable_data_info mBestBlock, immutable_data_info mImmutableBlock,
//                          std::set<immutable_data_info> mBlockSet, std::set<immutable_data_info> mTxSet,
//                          std::set<sha256_hash> mDemandBlockHashSet,
//                          std::set<sha256_hash> mDemandTxHashSet, aux::bytes mTxHashPrefixArray)
//                : m_consensus_point_block_hash(mConsensusPointBlockHash),
//                  m_consensus_point_block_number(mConsensusPointBlockNumber), m_best_tip_block(std::move(mBestBlock)),
//                  m_immutable_block_info(std::move(mImmutableBlock)), m_block_set(std::move(mBlockSet)), m_tx_set(std::move(mTxSet)),
//                  m_demand_block_hash_set(std::move(mDemandBlockHashSet)), m_demand_tx_hash_set(std::move(mDemandTxHashSet)),
//                  m_tx_hash_prefix_array(std::move(mTxHashPrefixArray)) {}

//        const sha256_hash &get_consensus_point_block_hash() const { return m_consensus_point_block_hash; }
//
//        void set_consensus_point_block_hash(const sha256_hash &mConsensusPointBlockHash) { m_consensus_point_block_hash = mConsensusPointBlockHash; }
//
//        int64_t get_consensus_point_block_number() const { return m_consensus_point_block_number; }
//
//        void set_consensus_point_block_number(int64_t mConsensusPointBlockNumber) { m_consensus_point_block_number = mConsensusPointBlockNumber; }

        // @returns timestamp
        int64_t timestamp() const { return m_timestamp; }

        const vote &consensus_point_vote() const { return m_consensus_point_vote; }

        void set_consensus_point_vote(const vote &mConsensusPointVote) { m_consensus_point_vote = mConsensusPointVote; }

        const immutable_data_info &best_tip_block_info() const { return m_best_tip_block_info; }

        void set_best_tip_block_info(const immutable_data_info &mBestBlockInfo) { m_best_tip_block_info = mBestBlockInfo; }

        const immutable_data_info &consensus_point_block_info() const { return m_consensus_point_block_info; }

        void set_consensus_point_block_info(const immutable_data_info &mImmutableBlockInfo) { m_consensus_point_block_info = mImmutableBlockInfo; }

        const std::set<immutable_data_info> &block_info_set() const { return m_block_info_set; }

        void set_block_info_set(const std::set<immutable_data_info> &mBlockInfoSet) { m_block_info_set = mBlockInfoSet; }

        const std::set<immutable_data_info> &tx_info_set() const { return m_tx_info_set; }

        void set_tx_info_set(const std::set<immutable_data_info> &mTxInfoSet) { m_tx_info_set = mTxInfoSet; }

        const std::set<sha256_hash> &demand_block_hash_set() const { return m_demand_block_hash_set; }

        void set_demand_block_hash_set(const std::set<sha256_hash> &mDemandBlockHashSet) { m_demand_block_hash_set = mDemandBlockHashSet; }

//        const std::set<sha256_hash> &get_demand_tx_hash_set() const { return m_demand_tx_hash_set; }
//
//        void set_demand_tx_hash_set(const std::set<sha256_hash> &mDemandTxHashSet) { m_demand_tx_hash_set = mDemandTxHashSet; }

        const aux::bytes &tx_hash_prefix_array() const { return m_tx_hash_prefix_array; }

        void set_tx_hash_prefix_array(const aux::bytes &mTxHashPrefixArray) { m_tx_hash_prefix_array = mTxHashPrefixArray; }

        entry get_entry() const;

        std::string get_encode() const;

    private:
        // populate block chain signal info from entry
        void populate(const entry& e);

        // online signal timestamp
        std::int64_t m_timestamp;

        vote m_consensus_point_vote;

//        sha256_hash m_consensus_point_block_hash;
//
//        std::int64_t m_consensus_point_block_number{};

        immutable_data_info m_best_tip_block_info;

        immutable_data_info m_consensus_point_block_info;

        std::set<immutable_data_info> m_block_info_set;

        std::set<immutable_data_info> m_tx_info_set;

        std::set<sha256_hash> m_demand_block_hash_set;

//        std::set<sha256_hash> m_demand_tx_hash_set;

        aux::bytes m_tx_hash_prefix_array;
    };
}


#endif //LIBTAU_BLOCKCHAIN_SIGNAL_HPP
