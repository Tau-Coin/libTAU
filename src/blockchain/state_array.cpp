/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/state_array.hpp"

namespace libTAU::blockchain {
    state_array::state_array(const entry &e) {
        populate(e);

        std::string encode;
        bencode(std::back_inserter(encode), e);
        m_hash = hasher(encode).final();
    }

    entry state_array::get_entry() const {
        // hash array
        entry::list_type e;
        for (auto const& act: m_state_array) {
            e.push_back(act.get_entry());
        }

        return e;
    }

    void state_array::populate(const entry &e) {
        auto & lst = e.list();
        for (auto const& act: lst) {
            m_state_array.emplace_back(act);
        }
    }

    std::string state_array::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    std::string state_array::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const state_array &stateArray) {
        os << "m_state_array: ";
        for (auto const& act: stateArray.m_state_array) {
            os << " account:" << act.to_string();
        }

        os << " m_hash: " << aux::toHex(stateArray.m_hash.to_string());

        return os;
    }
}
