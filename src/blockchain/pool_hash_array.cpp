/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/pool_hash_array.hpp"

namespace libTAU::blockchain {

    pool_hash_array::pool_hash_array(const entry& e) {
        populate(e);

        std::string encode;
        bencode(std::back_inserter(encode), e);
        m_hash = hasher(encode).final();
    }

    entry pool_hash_array::get_entry() const {
        // hash array
        entry::list_type e;
        for (auto const& hash: m_hash_array) {
            e.push_back(hash.to_string());
        }

        return e;
    }

    std::string pool_hash_array::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    void pool_hash_array::populate(const entry &e) {
        auto & lst = e.list();
        for (auto const& hash: lst) {
            m_hash_array.emplace_back(hash.string().data());
        }
    }

    std::string pool_hash_array::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const pool_hash_array &hashArray) {
        os << "m_hash_array: ";
        for (auto const& hash: hashArray.m_hash_array) {
            os << " hash:" << aux::toHex(hash.to_string());
        }

        os << " m_hash: " << aux::toHex(hashArray.m_hash.to_string());

        return os;
    }

}
