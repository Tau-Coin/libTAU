/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/transaction_wrapper.hpp"

namespace libTAU::blockchain {

    transaction_wrapper::transaction_wrapper(const entry &e) {
        populate(e);
    }

    entry transaction_wrapper::get_entry() const {
        entry::list_type lst;

        // previous hash
        lst.push_back(m_previous_hash.to_string());
        // tx
        lst.push_back(m_tx.get_entry());

        return lst;
    }

    void transaction_wrapper::populate(const entry &e) {
        auto const& lst = e.list();

        if (lst.size() != 2)
            return;

        // previous hash
        m_previous_hash = sha1_hash(lst[0].string().data());

        // tx
        m_tx = transaction(lst[1]);
        m_hash = m_tx.sha1();
    }

    std::string transaction_wrapper::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    std::string transaction_wrapper::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const transaction_wrapper &wrapper) {
        os << "m_previous_hash: " << aux::toHex(wrapper.m_previous_hash) << " m_tx: " << wrapper.m_tx.to_string()
           << " m_hash: " << aux::toHex(wrapper.m_hash);
        return os;
    }

}
