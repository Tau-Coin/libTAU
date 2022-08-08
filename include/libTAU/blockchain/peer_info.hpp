/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_PEER_INFO_HPP
#define LIBTAU_PEER_INFO_HPP


#include <cstdint>

#include "libTAU/blockchain/block.hpp"
#include "libTAU/blockchain/state_array.hpp"
#include "libTAU/blockchain/state_hash_array.hpp"
#include "libTAU/blockchain/vote.hpp"
#include "libTAU/common/entry_type.hpp"
#include <libTAU/sha1_hash.hpp>
#include <ostream>
#include <utility>

namespace libTAU::blockchain {

//    enum STAGE {
//        HEAD_BLOCK,
//        NORMAL,
//    };

    struct peer_info {
        peer_info() = default;

        explicit peer_info(int64_t mLastSeen) : m_last_seen(mLastSeen) {}

//        peer_info(transaction mLatestTx, int64_t mLastSeen) : m_latest_tx(std::move(mLatestTx)), m_last_seen(mLastSeen) {}

//        peer_info(STAGE mStage, block mHeadBlock) : m_stage(mStage), m_head_block(std::move(mHeadBlock)) {}
//
//        peer_info(STAGE mStage, block mHeadBlock, int64_t mLastSeen) : m_stage(mStage), m_head_block(std::move(mHeadBlock)),
//                                                                              m_last_seen(mLastSeen) {}

//        void setStage(STAGE mStage) {
//            m_stage = mStage;
//        }

        std::string to_string() const;

        friend std::ostream &operator<<(std::ostream &os, const peer_info &info);

//        int m_score = 40;

//        STAGE m_stage = HEAD_BLOCK;

//        int m_last_request_time = 0;

//        std::map<std::unique_ptr<common::blockchain_entry_base>, std::int64_t, common::less_blockchain_entry_base> m_requests_time;

//        std::map<std::unique_ptr<common::blockchain_entry_base>, std::int64_t, common::less_blockchain_entry_base> m_peer_requests_time;

        block m_head_block;

        block m_genesis_block;

        state_hash_array m_state_hash_array;

        std::map<sha1_hash, state_array> m_state_arrays;

//        transaction m_latest_tx;

        // last seen time(s)
        std::int64_t m_last_seen = 0;

//        std::int64_t m_last_ping_time = 0;

//        bool m_fee_tx_pool_sync_done = false;
//        bool m_time_tx_pool_sync_done = false;

//        bool m_sync_done = false;

//        bool m_gossip_done = false;

//        vote m_vote;

//        aux::bytes m_pool_levenshtein_array;
    };

    struct ban_info {

        ban_info() = default;

        explicit ban_info(int64_t mFreeTime) : m_free_time(mFreeTime) {}

//        ban_info(int mBanTimes, int64_t mFreeTime) : m_ban_times(mBanTimes), m_free_time(mFreeTime) {}
//
//        void increase_ban_times() {
//            m_ban_times++;
//        }

        void set_free_time(int64_t mFreeTime) {
            m_free_time = mFreeTime;
        }

        std::string to_string() const;

        friend std::ostream &operator<<(std::ostream &os, const ban_info &info);

//        int m_ban_times = 1;

        std::int64_t m_free_time = 0;
    };
}


#endif //LIBTAU_PEER_INFO_HPP
