/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/account.hpp"

namespace libTAU::blockchain {

    account::account(const entry& e) {
        populate(e);
    }

    entry account::get_entry() const {
        entry e(entry::dictionary_t);

        // balance
        if (m_balance != 0) {
            e["b"] = entry(m_balance);
        }
        // nonce
        if (m_nonce != 0) {
            e["n"] = entry(m_nonce);
        }
        // note timestamp
        e["t"] = entry(m_note_timestamp);
        // effective power
        if (m_effective_power != 0) {
            e["p"] = entry(m_effective_power);
        }
        // block number
        if (m_block_number != 0) {
            e["r"] = entry(m_block_number);
        }

        return e;
    }

    void account::populate(const entry &e) {
        // balance
        if (auto* i = const_cast<entry *>(e.find_key("b")))
        {
            m_balance = i->integer();
        }
        // nonce
        if (auto* i = const_cast<entry *>(e.find_key("n")))
        {
            m_nonce = i->integer();
        }
        // note timestamp
        if (auto* i = const_cast<entry *>(e.find_key("t")))
        {
            m_note_timestamp = i->integer();
        }
        // effective power
        if (auto* i = const_cast<entry *>(e.find_key("p")))
        {
            m_effective_power = i->integer();
        }
        // block number
        if (auto* i = const_cast<entry *>(e.find_key("r")))
        {
            m_block_number = i->integer();
        }
    }
}
