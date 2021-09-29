/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/state_pointer.hpp"

namespace libTAU::blockchain {
    state_pointer::state_pointer(const entry &e) {
        populate(e);
    }

    entry state_pointer::get_entry() const {
        entry e(entry::dictionary_t);

        // first block hash
        e["f"] = entry(m_first_block_hash.to_string());
        // last block hash
        e["l"] = entry(m_last_block_hash.to_string());

        return e;
    }

    std::string state_pointer::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    void state_pointer::populate(const entry &e) {
        // first block hash
        if (auto* i = const_cast<entry *>(e.find_key("f")))
        {
            auto first_block_hash = i->string();
            m_first_block_hash = sha256_hash(first_block_hash.data());
        }
        // last block hash
        if (auto* i = const_cast<entry *>(e.find_key("l")))
        {
            auto last_block_hash = i->string();
            m_last_block_hash = sha256_hash(last_block_hash.data());
        }
    }
}
