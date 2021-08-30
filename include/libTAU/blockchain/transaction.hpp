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
#include "libTAU/kademlia/types.hpp"

namespace libTAU::blockchain {
    enum tx_version {
        tx_version1,
        tx_unknown_version,
    };

    class TORRENT_EXPORT transaction {
    public:
        transaction() = default;

        // @param Construct with entry
        explicit transaction(const entry& e);

        // @param Construct with bencode
        explicit transaction(std::string encode): transaction(bdecode(encode)) {}

        transaction(tx_version mVersion, int64_t mTimestamp, const dht::public_key &mSender,
                    const dht::public_key &mReceiver, int64_t mNonce, int64_t mAmount, int64_t mFee,
                    aux::bytes mPayload) : m_version(mVersion), m_timestamp(mTimestamp), m_sender(mSender),
                    m_receiver(mReceiver), m_nonce(mNonce), m_amount(mAmount),
                    m_fee(mFee), m_payload(std::move(mPayload)) {}

        tx_version version() const { return m_version; }

        int64_t timestamp() const { return m_timestamp; }

        const dht::public_key &sender() const { return m_sender; }

        const dht::public_key &receiver() const { return m_receiver; }

        int64_t nonce() const { return m_nonce; }

        int64_t amount() const { return m_amount; }

        int64_t fee() const { return m_fee; }

        const aux::bytes &payload() const { return m_payload; }

        const dht::signature &signature() const { return m_signature; }

        entry get_entry() const;

        std::string get_encode() const;

        // @returns the SHA256 hash of this message
        const sha256_hash &sha256();

        void sign(dht::public_key const& pk, dht::secret_key const& sk);

        bool verify_signature() const;

    private:

        std::string get_encode_without_signature() const;

        entry get_entry_without_signature() const;

        // populate transaction data from entry
        void populate(const entry& e);

        // version
        tx_version m_version = tx_version1;

        // timestamp
        std::int64_t m_timestamp{};

        // sender
        dht::public_key m_sender{};

        // receiver
        dht::public_key m_receiver{};

        // nonce
        std::int64_t m_nonce{};

        // amount
        std::int64_t m_amount{};

        // fee
        std::int64_t m_fee{};

        // payload
        aux::bytes m_payload;

        // signature
        dht::signature m_signature{};

        // sha256 hash
        sha256_hash m_hash;
    };
}


#endif //LIBTAU_TRANSACTION_HPP
