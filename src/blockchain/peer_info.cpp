/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/peer_info.hpp"


namespace libTAU::blockchain {

    std::string peer_info::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const peer_info &info) {
        os << info.m_head_block.block_number();
//        os << " m_requests_time: ";
//        for (auto const &item: info.m_requests_time) {
//            os << "key: " << *item.first << " value: " << item.second;
//        }
        return os;
    }

    std::string ban_info::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const ban_info &info) {
        os << "m_free_time: " << info.m_free_time;
        return os;
    }
}