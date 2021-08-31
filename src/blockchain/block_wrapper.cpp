/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/block_wrapper.hpp"

namespace libTAU::blockchain {
    block_wrapper::block_wrapper(entry e) {
        populate(e);
    }

    entry block_wrapper::get_entry() const {
        entry e(entry::dictionary_t);

        // block
        e["b"] = m_block.get_entry();
        // miner last change block number
        e["m"] = entry(m_miner_last_change_block_number);
        // sender last change block number
        e["s"] = entry(m_sender_last_change_block_number);
        // receiver last change block number
        e["r"] = entry(m_receiver_last_change_block_number);

        return e;
    }

    std::string block_wrapper::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    void block_wrapper::populate(const entry &e) {
        // block
        if (auto* i = const_cast<entry *>(e.find_key("b")))
        {
            m_block = block(*i);
        }
        // miner last change block number
        if (auto* i = const_cast<entry *>(e.find_key("m")))
        {
            m_miner_last_change_block_number = i->integer();
        }
        // sender last change block number
        if (auto* i = const_cast<entry *>(e.find_key("s")))
        {
            m_sender_last_change_block_number = i->integer();
        }
        // receiver last change block number
        if (auto* i = const_cast<entry *>(e.find_key("r")))
        {
            m_receiver_last_change_block_number = i->integer();
        }
    }

}
