/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/state_linker.hpp"

namespace libTAU::blockchain {
    state_linker::state_linker(const entry& e) {
        populate(e);
    }

    entry state_linker::get_entry() const {
        entry e(entry::dictionary_t);

        // block hash
        e["h"] = entry(m_block_hash.to_string());
        // miner last change block hash
        e["m"] = entry(m_miner_last_change_block_hash.to_string());
        // sender last change block hash
        e["s"] = entry(m_sender_last_change_block_hash.to_string());
        // receiver last change block hash
        e["r"] = entry(m_receiver_last_change_block_hash.to_string());

        return e;
    }

    std::string state_linker::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    void state_linker::populate(const entry &e) {
        // block hash
        if (auto* i = const_cast<entry *>(e.find_key("h")))
        {
            m_block_hash = sha256_hash(i->string().data());
        }
        // miner last change block hash
        if (auto* i = const_cast<entry *>(e.find_key("m")))
        {
            m_miner_last_change_block_hash = sha256_hash(i->string().data());
        }
        // sender last change block hash
        if (auto* i = const_cast<entry *>(e.find_key("s")))
        {
            m_sender_last_change_block_hash = sha256_hash(i->string().data());
        }
        // receiver last change block hash
        if (auto* i = const_cast<entry *>(e.find_key("r")))
        {
            m_receiver_last_change_block_hash = sha256_hash(i->string().data());
        }
    }

}
