/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_TRANSACTION_HPP
#define LIBTAU_TRANSACTION_HPP


#include <utility>

#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"
#include "libTAU/entry.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"

namespace libTAU::blockchain {
    enum tx_version {
        tx_version1,
        tx_unknown_version,
    };

    class transaction {
    public:
        transaction() = default;

        // @param Construct with entry
        explicit transaction(entry e);

        // @param Construct with bencode
        explicit transaction(std::string encode): transaction(bdecode(encode)) {}

        transaction(tx_version mVersion, int64_t mTimestamp, aux::bytes mSender, aux::bytes mReceiver,
                    int64_t mAmount, int64_t mFee, aux::bytes mPayload, aux::bytes mSignature) :
                    m_version(mVersion), m_timestamp(mTimestamp), m_sender(std::move(mSender)),
                    m_receiver(std::move(mReceiver)), m_amount(mAmount), m_fee(mFee), m_payload(std::move(mPayload)),
                    m_signature(std::move(mSignature)) {}

        tx_version version() const { return m_version; }

        int64_t timestamp() const { return m_timestamp; }

        const aux::bytes &sender() const { return m_sender; }

        const aux::bytes &receiver() const { return m_receiver; }

        int64_t amount() const { return m_amount; }

        int64_t fee() const { return m_fee; }

        const aux::bytes &payload() const { return m_payload; }

        const aux::bytes &signature() const { return m_signature; }

    private:

        // populate transaction data from entry
        void populate(const entry& e);

        // version
        tx_version m_version;

        // timestamp
        std::int64_t m_timestamp;

        // sender
        aux::bytes m_sender;

        // receiver
        aux::bytes m_receiver;

        // amount
        std::int64_t m_amount;

        // fee
        std::int64_t m_fee;

        // payload
        aux::bytes m_payload;

        // signature
        aux::bytes m_signature;
    };
}


#endif //LIBTAU_TRANSACTION_HPP
