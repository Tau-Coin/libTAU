/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/account_block_pointer.hpp"

namespace libTAU::blockchain {
    account_block_pointer::account_block_pointer(const entry &e) {
        populate(e);
    }

    entry account_block_pointer::get_entry() const {
        entry e(entry::dictionary_t);

        // the latest block hash
        e["l"] = entry(m_latest_block_hash.to_string());
        // the oldest block hash
        e["o"] = entry(m_oldest_block_hash.to_string());

        return e;
    }

    std::string account_block_pointer::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    void account_block_pointer::populate(const entry &e) {
        // the latest block hash
        if (auto* i = const_cast<entry *>(e.find_key("l")))
        {
            auto latest_block_hash = i->string();
            m_latest_block_hash = sha256_hash(latest_block_hash.data());
        }
        // the oldest block hash
        if (auto* i = const_cast<entry *>(e.find_key("o")))
        {
            auto oldest_block_hash = i->string();
            m_oldest_block_hash = sha256_hash(oldest_block_hash.data());
        }
    }

    std::string account_block_pointer::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const account_block_pointer &pointer) {
        os << "m_latest_block_hash: " << aux::toHex(pointer.m_latest_block_hash) << " m_oldest_block_hash: "
           << aux::toHex(pointer.m_oldest_block_hash);
        return os;
    }
}
