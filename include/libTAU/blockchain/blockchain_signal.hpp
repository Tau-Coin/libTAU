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
#include <ostream>

#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/sha1_hash.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/kademlia/types.hpp"
#include "libTAU/blockchain/vote.hpp"
#include "libTAU/communication/immutable_data_info.hpp"


namespace libTAU::blockchain {
    using immutable_data_info = communication::immutable_data_info;

//    class blockchain_signal {
//    public:
//        // protocol id
//        static const std::int64_t protocol_id;
//
//    public:
//        blockchain_signal() = default;
//
//        // @param Construct with entry
//        explicit blockchain_signal(const entry& e);
//
//        // @param Construct with bencode
//        explicit blockchain_signal(std::string encode): blockchain_signal(bdecode(encode)) {}
//
//        blockchain_signal(aux::bytes mChainId, int64_t mTimestamp, const vote &mConsensusPointVote,
//                          immutable_data_info mHeadBlockInfo, immutable_data_info mImmutableBlockInfo,
//                          std::set<immutable_data_info> mBlockSet, std::set<immutable_data_info> mTxSet,
//                          std::set<sha256_hash> mDemandBlockHashSet,
//                          aux::bytes mLatestTxHashPrefixArray, const dht::public_key &mPeer):
//                m_chain_id(std::move(mChainId)), m_timestamp(mTimestamp), m_consensus_point_vote(mConsensusPointVote),
//                m_head_block_info(std::move(mHeadBlockInfo)), m_voting_point_block_info(std::move(mImmutableBlockInfo)),
//                m_block_info_set(std::move(mBlockSet)), m_tx_info_set(std::move(mTxSet)),
//                m_demand_block_hash_set(std::move(mDemandBlockHashSet)),
//                m_latest_tx_hash_prefix_array(std::move(mLatestTxHashPrefixArray)), m_gossip_peer(mPeer) {}
//
////        blockchain_signal(const sha256_hash &mConsensusPointBlockHash, int64_t mConsensusPointBlockNumber,
////                          immutable_data_info mBestBlock, immutable_data_info mImmutableBlock,
////                          std::set<immutable_data_info> mBlockSet, std::set<immutable_data_info> mTxSet,
////                          std::set<sha256_hash> mDemandBlockHashSet,
////                          std::set<sha256_hash> mDemandTxHashSet, aux::bytes mTxHashPrefixArray)
////                : m_consensus_point_block_hash(mConsensusPointBlockHash),
////                  m_consensus_point_block_number(mConsensusPointBlockNumber), m_best_tip_block(std::move(mBestBlock)),
////                  m_immutable_block_info(std::move(mImmutableBlock)), m_block_set(std::move(mBlockSet)), m_tx_set(std::move(mTxSet)),
////                  m_demand_block_hash_set(std::move(mDemandBlockHashSet)), m_demand_tx_hash_set(std::move(mDemandTxHashSet)),
////                  m_tx_hash_prefix_array(std::move(mTxHashPrefixArray)) {}
//
////        const sha256_hash &get_consensus_point_block_hash() const { return m_consensus_point_block_hash; }
////
////        void set_consensus_point_block_hash(const sha256_hash &mConsensusPointBlockHash) { m_consensus_point_block_hash = mConsensusPointBlockHash; }
////
////        int64_t get_consensus_point_block_number() const { return m_consensus_point_block_number; }
////
////        void set_consensus_point_block_number(int64_t mConsensusPointBlockNumber) { m_consensus_point_block_number = mConsensusPointBlockNumber; }
//
//        // chain id
//        const aux::bytes &chain_id() const { return m_chain_id; }
//
//        // @returns timestamp
//        int64_t timestamp() const { return m_timestamp; }
//
//        const vote &consensus_point_vote() const { return m_consensus_point_vote; }
//
//        void set_consensus_point_vote(const vote &mConsensusPointVote) { m_consensus_point_vote = mConsensusPointVote; }
//
//        const immutable_data_info &head_block_info() const { return m_head_block_info; }
//
//        void set_head_block_info(const immutable_data_info &mHeadBlockInfo) { m_head_block_info = mHeadBlockInfo; }
//
//        const immutable_data_info &voting_point_block_info() const { return m_voting_point_block_info; }
//
//        void set_voting_point_block_info(const immutable_data_info &mImmutableBlockInfo) { m_voting_point_block_info = mImmutableBlockInfo; }
//
//        const std::set<immutable_data_info> &block_info_set() const { return m_block_info_set; }
//
//        void set_block_info_set(const std::set<immutable_data_info> &mBlockInfoSet) { m_block_info_set = mBlockInfoSet; }
//
//        const std::set<immutable_data_info> &tx_info_set() const { return m_tx_info_set; }
//
//        void set_tx_info_set(const std::set<immutable_data_info> &mTxInfoSet) { m_tx_info_set = mTxInfoSet; }
//
//        const std::set<sha256_hash> &demand_block_hash_set() const { return m_demand_block_hash_set; }
//
//        void set_demand_block_hash_set(const std::set<sha256_hash> &mDemandBlockHashSet) { m_demand_block_hash_set = mDemandBlockHashSet; }
//
////        const std::set<sha256_hash> &get_demand_tx_hash_set() const { return m_demand_tx_hash_set; }
////
////        void set_demand_tx_hash_set(const std::set<sha256_hash> &mDemandTxHashSet) { m_demand_tx_hash_set = mDemandTxHashSet; }
//
////        const aux::bytes &tx_hash_prefix_array() const { return m_tx_hash_prefix_array; }
////
////        void set_tx_hash_prefix_array(const aux::bytes &mTxHashPrefixArray) { m_tx_hash_prefix_array = mTxHashPrefixArray; }
//
//        const aux::bytes &latest_tx_hash_prefix_array() const { return m_latest_tx_hash_prefix_array; }
//
//        const dht::public_key &gossip_peer() const { return m_gossip_peer; }
//
//        entry get_entry() const;
//
//        std::string get_encode() const;
//
//        bool empty() const { return m_chain_id.empty(); }
//
//        // @returns a pretty-printed string representation of signal structure
//        std::string to_string() const;
//
//        friend std::ostream &operator<<(std::ostream &os, const blockchain_signal &signal);
//
//    private:
//        // populate block chain signal info from entry
//        void populate(const entry& e);
//
//        // chain id
//        aux::bytes m_chain_id; // 32
//
//        // online signal timestamp
//        std::int64_t m_timestamp{}; // 10
//
//        // consensus point vote for block
//        vote m_consensus_point_vote; // 40
//
////        sha256_hash m_consensus_point_block_hash;
////
////        std::int64_t m_consensus_point_block_number{};
//
//        immutable_data_info m_head_block_info; // 1-70
//
//        immutable_data_info m_voting_point_block_info;
//
//        std::set<immutable_data_info> m_block_info_set;
//
//        std::set<immutable_data_info> m_tx_info_set;
//
//        std::set<sha256_hash> m_demand_block_hash_set; // 64
//
////        std::set<sha256_hash> m_demand_tx_hash_set;
//
//        // top ten tx
////        aux::bytes m_tx_hash_prefix_array;
//
//        // the latest tx hash array
//        aux::bytes m_latest_tx_hash_prefix_array;
//
//        // gossip peer
//        dht::public_key m_gossip_peer{}; // 32
//    };
}


#endif //LIBTAU_BLOCKCHAIN_SIGNAL_HPP
