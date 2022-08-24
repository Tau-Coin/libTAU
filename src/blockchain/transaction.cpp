/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/transaction.hpp"
#include "libTAU/hasher.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/kademlia/ed25519.hpp"
#include <utility>

namespace libTAU::blockchain {
    transaction::transaction(const entry& e) {
        populate(e);

        std::string encode;
        bencode(std::back_inserter(encode), e);
        m_hash = hasher(encode).final();
    }

    entry transaction::get_entry_without_signature() const {
        entry::list_type lst;

        // chain id
        lst.push_back(std::string(m_chain_id.begin(), m_chain_id.end()));
        // version
        auto version = aux::intToLittleEndianString((int)m_version);
        lst.push_back(version);
        // type
        auto type = aux::intToLittleEndianString((int)m_type);
        lst.push_back(type);
        // timestamp
        auto timestamp = aux::int64ToLittleEndianString(m_timestamp);
        lst.push_back(timestamp);
        // sender
        lst.push_back(std::string(m_sender.bytes.begin(), m_sender.bytes.end()));
        if (m_type == tx_type::type_transfer) {
            // receiver
            lst.push_back(std::string(m_receiver.bytes.begin(), m_receiver.bytes.end()));
            // nonce
            auto nonce = aux::int64ToLittleEndianString(m_nonce);
            lst.push_back(nonce);
            // fee
            auto fee = aux::int64ToLittleEndianString(m_fee);
            lst.push_back(fee);
            // amount
            auto amount = aux::int64ToLittleEndianString(m_amount);
            lst.push_back(amount);
        }
        // payload
        lst.push_back(std::string(m_payload.begin(), m_payload.end()));

        return lst;
    }

    entry transaction::get_entry() const {
        entry e = get_entry_without_signature();
        // signature
        e.list().push_back(std::string(m_signature.bytes.begin(), m_signature.bytes.end()));

        return e;
    }

    std::string transaction::get_encode_without_signature() const {
        std::string encode;
        auto e = get_entry_without_signature();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    std::string transaction::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    size_t transaction::get_encode_size() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode.size();
    }

//    const sha256_hash &transaction::sha256() {
//        if (m_hash.is_all_zeros()) {
//            auto encode = get_encode();
//            m_hash = dht::item_target_id(encode);
//        }
//
//        return m_hash;
//    }

    void transaction::sign(const dht::public_key &pk, const dht::secret_key &sk) {
        m_signature = ed25519_sign(get_encode_without_signature(), pk, sk);

        auto encode = get_encode();
        m_hash = hasher(encode).final();
    }

    bool transaction::verify_signature() const {
        return ed25519_verify(m_signature, get_encode_without_signature(), m_sender);
    }

    void transaction::populate(const entry &e) {
        auto const& lst = e.list();

        if (lst.size() == 7) {
            // type
            int type = aux::intFromLittleEndianString(lst[2].string());
            m_type = static_cast<tx_type>(type);
            if (m_type != tx_type::type_note)
                return;

            // chain id
            auto chain_id = lst[0].string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
            // version
            int version = aux::intFromLittleEndianString(lst[1].string());
            m_version = static_cast<tx_version>(version);
            // balance
            m_timestamp = aux::int64FromLittleEndianString(lst[3].string());
            // sender
            m_sender = dht::public_key(lst[4].string().data());
            // payload
            auto payload = lst[5].string();
            m_payload = aux::bytes(payload.begin(), payload.end());
            // signature
            m_signature = dht::signature(lst[6].string().data());
        }

        if (lst.size() == 11) {
            int type = aux::intFromLittleEndianString(lst[2].string());
            m_type = static_cast<tx_type>(type);
            if (m_type != tx_type::type_transfer)
                return;

            // chain id
            auto chain_id = lst[0].string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
            // version
            int version = aux::intFromLittleEndianString(lst[1].string());
            m_version = static_cast<tx_version>(version);
            // balance
            m_timestamp = aux::int64FromLittleEndianString(lst[3].string());
            // sender
            m_sender = dht::public_key(lst[4].string().data());
            // receiver
            m_receiver = dht::public_key(lst[5].string().data());
            // nonce
            m_nonce = aux::int64FromLittleEndianString(lst[6].string());
            // fee
            m_fee = aux::int64FromLittleEndianString(lst[7].string());
            // amount
            m_amount = aux::int64FromLittleEndianString(lst[8].string());
            // payload
            auto payload = lst[9].string();
            m_payload = aux::bytes(payload.begin(), payload.end());
            // signature
            m_signature = dht::signature(lst[10].string().data());
        }
    }

    std::string transaction::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const transaction &transaction) {
        os << "m_chain_id: " << aux::toHex(transaction.m_chain_id) << " m_version: " << transaction.m_version
           << " m_type: " << transaction.m_type << " m_timestamp: " << transaction.m_timestamp << " m_sender: "
           << aux::toHex(transaction.m_sender.bytes) << " m_receiver: " << aux::toHex(transaction.m_receiver.bytes)
           << " m_nonce: " << transaction.m_nonce << " m_amount: " << transaction.m_amount
           << " m_fee: " << transaction.m_fee << " m_hash: " << aux::toHex(transaction.m_hash.to_string());
        return os;
    }
}