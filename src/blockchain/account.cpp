/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/account.hpp"
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"

namespace libTAU::blockchain {

    account::account(const entry& e) {
        populate(e);
    }

    entry account::get_entry() const {
        entry e(entry::dictionary_t);

        // peer
        e["p"] = entry(std::string(m_peer.bytes.begin(), m_peer.bytes.end()));
        // balance
        if (m_balance != 0) {
            e["b"] = entry(m_balance);
        }
        // nonce
        if (m_nonce != 0) {
            e["n"] = entry(m_nonce);
        }
//        // effective power
//        if (m_effective_power != 0) {
//            e["p"] = entry(m_effective_power);
//        }
//        // block number
//        if (m_block_number != 0) {
//            e["r"] = entry(m_block_number);
//        }

        return e;
    }

    void account::populate(const entry &e) {
        // peer
        if (auto* i = const_cast<entry *>(e.find_key("p")))
        {
            auto peer = i->string();
            m_peer = dht::public_key(peer.data());
        }
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
//        // effective power
//        if (auto* i = const_cast<entry *>(e.find_key("p")))
//        {
//            m_effective_power = i->integer();
//        }
//        // block number
//        if (auto* i = const_cast<entry *>(e.find_key("r")))
//        {
//            m_block_number = i->integer();
//        }
    }

    std::string account::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const account &account) {
        os << "m_peer: " << aux::toHex(account.m_peer.bytes) << " m_balance: " << account.m_balance << " m_nonce: " << account.m_nonce;
        return os;
    }
}
