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
#include <libTAU/sha1_hash.hpp>
#include <ostream>

namespace libTAU {
namespace blockchain {
    enum tx_version {
        tx_version1,
        tx_unknown_version,
    };

    enum tx_type {
        type_transfer,
        type_note,
        type_unknown,
    };

    class TORRENT_EXPORT transaction {
    public:
        transaction() = default;

        // @param Construct with entry
        explicit transaction(const entry& e);

        // @param Construct with bencode
        explicit transaction(std::string encode): transaction(bdecode(encode)) {}

        static transaction create_transfer_transaction(aux::bytes& mChainId, tx_version mVersion, int64_t mTimestamp,
                                                       const dht::public_key &mSender, const dht::public_key &mReceiver,
                                                       int64_t mNonce, int64_t mAmount, int64_t mFee, aux::bytes& mPayload) {
            return transaction(mChainId, mVersion, mTimestamp, mSender, mReceiver, mNonce, mAmount, mFee, mPayload);
        }

        static transaction create_note_transaction(aux::bytes& mChainId, tx_version mVersion, int64_t mTimestamp,
                                                       const dht::public_key &mSender,  aux::bytes& mPayload) {
            return transaction(mChainId, mVersion, mTimestamp, mSender, mPayload);
        }

        transaction(aux::bytes mChainId, tx_version mVersion, int64_t mTimestamp,
                    const dht::public_key &mSender, aux::bytes mPayload) :
                    m_chain_id(std::move(mChainId)), m_version(mVersion), m_timestamp(mTimestamp),
                    m_sender(mSender), m_payload(std::move(mPayload)) {
            m_type = tx_type::type_note;
        }

        transaction(aux::bytes mChainId, tx_version mVersion, int64_t mTimestamp, const dht::public_key &mSender,
                    const dht::public_key &mReceiver, int64_t mNonce, int64_t mAmount, int64_t mFee,
                    aux::bytes mPayload) : m_chain_id(std::move(mChainId)), m_version(mVersion),
                    m_timestamp(mTimestamp), m_sender(mSender), m_receiver(mReceiver),
                    m_nonce(mNonce), m_amount(mAmount), m_fee(mFee), m_payload(std::move(mPayload)) {
            m_type = tx_type::type_transfer;
        }

        const aux::bytes &chain_id() const { return m_chain_id; }

        tx_version version() const { return m_version; }

        tx_type type() const { return m_type; }

        int64_t timestamp() const { return m_timestamp; }

        const dht::public_key &sender() const { return m_sender; }

        const dht::public_key &receiver() const { return m_receiver; }

        int64_t nonce() const { return m_nonce; }

        int64_t amount() const { return m_amount; }

        int64_t fee() const { return m_fee; }

        int64_t cost() const { return m_amount + m_fee; }

        const aux::bytes &payload() const { return m_payload; }

        const dht::signature &signature() const { return m_signature; }

        bool empty() const { return m_hash.is_all_zeros(); }

        entry get_entry() const;

        std::string get_encode() const;

        size_t get_encode_size() const;

        // @returns the SHA1 hash of this message
        const sha1_hash &sha1() const { return m_hash; }

        void sign(dht::public_key const& pk, dht::secret_key const& sk);

        bool verify_signature() const;

        bool operator==(const transaction &rhs) const {
            return m_hash == rhs.m_hash;
        }

        bool operator!=(const transaction &rhs) const {
            return !(rhs == *this);
        }

        bool operator<(const transaction &rhs) const {
            return m_hash < rhs.m_hash;
        }

        // @returns a pretty-printed string representation of tx structure
        std::string to_string() const;

        friend std::ostream &operator<<(std::ostream &os, const transaction &transaction);

    private:

        std::string get_encode_without_signature() const;

        entry get_entry_without_signature() const;

        // populate transaction data from entry
        void populate(const entry& e);

        // chain id
        aux::bytes m_chain_id;

        // version
        tx_version m_version = tx_version1;

        // version
        tx_type m_type = type_transfer;

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
        sha1_hash m_hash;
    };
}
}


#endif //LIBTAU_TRANSACTION_HPP
