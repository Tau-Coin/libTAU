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
        entry::list_type lst;

        // peer
        auto peer = std::string(m_peer.bytes.begin(), m_peer.bytes.end());
        lst.push_back(peer);
        // balance
        auto balance = aux::int64ToLittleEndianString(m_balance);
        lst.push_back(balance);
        // nonce
        auto nonce = aux::int64ToLittleEndianString(m_nonce);
        lst.push_back(nonce);
        // power
        auto power = aux::int64ToLittleEndianString(m_power);
        lst.push_back(power);

        return lst;
    }

    void account::populate(const entry &e) {
        auto const& lst = e.list();

        if (lst.size() != 4)
            return;

        // peer
        m_peer = dht::public_key(lst[0].string().data());

        // balance
        m_balance = aux::int64FromLittleEndianString(lst[1].string());
        // nonce
        m_nonce = aux::int64FromLittleEndianString(lst[2].string());
        // power
        m_power = aux::int64FromLittleEndianString(lst[3].string());
    }

    std::string account::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const account &account) {
        os << "m_peer: " << aux::toHex(account.m_peer.bytes) << " m_balance: " << account.m_balance
           << " m_nonce: " << account.m_nonce << " m_power: " << account.m_power;
        return os;
    }
}
