/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/vote.hpp"

namespace libTAU::blockchain {
    vote::vote(const entry &e) {
        populate(e);
    }

    entry vote::get_entry() const {
        entry e(entry::dictionary_t);

        // consensus point block hash
        e["h"] = entry(m_block_hash.to_string());

        // consensus point block number
        e["n"] = entry(m_block_number);

        return e;
    }

    std::string vote::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    void vote::populate(const entry &e) {
        // consensus point block hash
        if (auto* i = const_cast<entry *>(e.find_key("h")))
        {
            m_block_hash = sha256_hash(i->string().data());
        }
        // consensus point block number
        if (auto* i = const_cast<entry *>(e.find_key("n")))
        {
            m_block_number = i->integer();
        }
    }
}