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

        // last change map
        entry m(entry::dictionary_t);
        for (auto const& item: m_last_change_block_hash_map) {
            std::string key(item.first.bytes.begin(), item.first.bytes.end());
            m[key] = entry(item.second.to_string());
        }
        e["m"] = m;

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
        // last change map
        if (auto* i = const_cast<entry *>(e.find_key("m")))
        {
            auto & dic = i->dict();
            for (auto const& item: dic) {
                m_last_change_block_hash_map[dht::public_key(item.first.data())] = sha256_hash(item.second.string().data());
            }
        }
    }

}
