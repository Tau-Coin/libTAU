/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/transaction.hpp"

namespace libTAU::blockchain {
    transaction::transaction(entry e) {
        populate(e);
    }

    void transaction::populate(const entry &e) {
        // version
        if (auto* i = const_cast<entry *>(e.find_key("v")))
        {
            m_version = static_cast<tx_version>(i->integer());
        }
        // timestamp
        if (auto* i = const_cast<entry *>(e.find_key("t")))
        {
            m_timestamp = i->integer();
        }
        // sender
        if (auto* i = const_cast<entry *>(e.find_key("s")))
        {
            auto sender = i->string();
            m_sender = aux::bytes(sender.begin(), sender.end());
        }
        // receiver
        if (auto* i = const_cast<entry *>(e.find_key("r")))
        {
            auto receiver = i->string();
            m_receiver = aux::bytes(receiver.begin(), receiver.end());
        }
        // amount
        if (auto* i = const_cast<entry *>(e.find_key("a")))
        {
            m_amount = i->integer();
        }
        // fee
        if (auto* i = const_cast<entry *>(e.find_key("f")))
        {
            m_fee = i->integer();
        }
        // payload
        if (auto* i = const_cast<entry *>(e.find_key("p")))
        {
            auto payload = i->string();
            m_payload = aux::bytes(payload.begin(), payload.end());
        }
        // signature
        if (auto* i = const_cast<entry *>(e.find_key("sig")))
        {
            auto signature = i->string();
            m_signature = aux::bytes(signature.begin(), signature.end());
        }
    }
}