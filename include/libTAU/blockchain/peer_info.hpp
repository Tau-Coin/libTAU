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
#include "libTAU/blockchain/vote.hpp"
#include "libTAU/common/entry_type.hpp"
#include <libTAU/sha1_hash.hpp>

namespace libTAU::blockchain {

    enum STAGE {
        HEAD_BLOCK,
        NORMAL,
    };

    struct peer_info {
        peer_info() = default;

        peer_info(int mScore) : m_score(mScore) {}

        void setStage(STAGE mStage) {
            m_stage = mStage;
        }

        int m_score = 30;

        STAGE m_stage = HEAD_BLOCK;

        int m_last_seen = 0;

        int m_last_request_time = 0;

        std::map<std::int64_t, int> m_requests_time;

        block m_head_block;

        vote m_vote;

        aux::bytes m_pool_levenshtein_array;
    };

    struct ban_info {

        ban_info() = default;

        ban_info(int mBanTimes, int64_t mFreeTime) : m_ban_times(mBanTimes), m_free_time(mFreeTime) {}

        void increase_ban_times() {
            m_ban_times++;
        }

        void set_free_time(int64_t mFreeTime) {
            m_free_time = mFreeTime;
        }

        int m_ban_times = 0;

        std::int64_t m_free_time = 0;
    };
}


#endif //LIBTAU_PEER_INFO_HPP
