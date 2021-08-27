/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/transaction.hpp"

#include <utility>

namespace libTAU::blockchain {
    transaction::transaction(entry e) {
        populate(e);
    }

    transaction::transaction(tx_version mVersion, int64_t mTimestamp, aux::bytes mSender,
                             aux::bytes mReceiver, int64_t mNonce, int64_t mAmount, int64_t mFee,
                             aux::bytes mPayload, aux::bytes mSignature) : m_version(mVersion),
                             m_timestamp(mTimestamp), m_sender(std::move(mSender)), m_receiver(std::move(mReceiver)),
                             m_nonce(mNonce), m_amount(mAmount), m_fee(mFee), m_payload(std::move(mPayload)),
                             m_signature(std::move(mSignature)) {

    }

    entry transaction::get_entry() const {
        entry e(entry::dictionary_t);

        // version
        e["v"] = entry(m_version);
        // timestamp
        e["t"] = entry(m_timestamp);
        // sender
        e["s"] = entry(std::string(m_sender.begin(), m_sender.end()));
        // receiver
        e["r"] = entry(std::string(m_receiver.begin(), m_receiver.end()));
        // nonce
        e["n"] = entry(m_nonce);
        // amount
        e["a"] = entry(m_amount);
        // fee
        e["f"] = entry(m_fee);
        // payload
        e["p"] = entry(std::string(m_payload.begin(), m_payload.end()));
        // signature
        e["sig"] = entry(std::string(m_signature.begin(), m_signature.end()));

        return e;
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
        // nonce
        if (auto* i = const_cast<entry *>(e.find_key("n")))
        {
            m_nonce = i->integer();
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