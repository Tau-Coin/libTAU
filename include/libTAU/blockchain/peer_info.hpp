/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_PEER_INFO_HPP
#define LIBTAU_PEER_INFO_HPP


#include <cstdint>

namespace libTAU::blockchain {

    struct peer_info {
        peer_info(int mScore) : m_score(mScore) {}

        int m_score = 30;

        int m_stage = 0;
    };

    struct ban_info {

        ban_info(int mBanTimes, int64_t mFreeTime) : m_ban_times(mBanTimes), m_free_time(mFreeTime) {}

        void increase_ban_times() {
            m_ban_times++;
        }

        void set_free_time(int64_t mFreeTime) {
            m_free_time = mFreeTime;
        }

        int m_ban_times;

        std::int64_t m_free_time;
    };
}


#endif //LIBTAU_PEER_INFO_HPP
