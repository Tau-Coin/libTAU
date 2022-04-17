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

        // next change map
        entry n(entry::dictionary_t);
        for (auto const& item: m_next_change_block_hash_map) {
            std::string key(item.first.bytes.begin(), item.first.bytes.end());
            n[key] = entry(item.second.to_string());
        }
        e["n"] = n;

        // previous change map
        entry p(entry::dictionary_t);
        for (auto const& item: m_previous_change_block_hash_map) {
            std::string key(item.first.bytes.begin(), item.first.bytes.end());
            p[key] = entry(item.second.to_string());
        }
        e["p"] = p;

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
        // next change block hash map
        if (auto* i = const_cast<entry *>(e.find_key("n")))
        {
            auto & dic = i->dict();
            for (auto const& item: dic) {
                m_next_change_block_hash_map[dht::public_key(item.first.data())] = sha256_hash(item.second.string().data());
            }
        }
        // previous change block hash map
        if (auto* i = const_cast<entry *>(e.find_key("p")))
        {
            auto & dic = i->dict();
            for (auto const& item: dic) {
                m_previous_change_block_hash_map[dht::public_key(item.first.data())] = sha256_hash(item.second.string().data());
            }
        }
    }

    std::string state_linker::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const state_linker &stateLinker) {
        os << "m_block_hash: " << aux::toHex(stateLinker.m_block_hash) << " m_next_change_block_hash_map: ";
        for (auto const& item: stateLinker.m_next_change_block_hash_map) {
            os << " peer:" << aux::toHex(item.first.bytes) << " next change block hash:" << aux::toHex(item.second.to_string());
        }
        os << " m_previous_change_block_hash_map: ";
        for (auto const& item: stateLinker.m_previous_change_block_hash_map) {
            os << " peer:" << aux::toHex(item.first.bytes) << " previous change block hash:" << aux::toHex(item.second.to_string());
        }

        return os;
    }

}
