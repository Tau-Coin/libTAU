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
        entry e(entry::dictionary_t);

        // chain id
        e["i"] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // version
        e["v"] = entry(m_version);
        // type
        e["e"] = entry(m_type);
        // timestamp
        e["t"] = entry(m_timestamp);
        // sender
        e["s"] = entry(std::string(m_sender.bytes.begin(), m_sender.bytes.end()));
        if (m_type == tx_type::type_transfer) {
            // receiver
            e["r"] = entry(std::string(m_receiver.bytes.begin(), m_receiver.bytes.end()));
            // nonce
            e["n"] = entry(m_nonce);
            // fee
            e["f"] = entry(m_fee);
            // amount
            e["a"] = entry(m_amount);
        }
        // payload
        e["p"] = entry(std::string(m_payload.begin(), m_payload.end()));

        return e;
    }

    entry transaction::get_entry() const {
        entry e = get_entry_without_signature();
        // signature
        e["sig"] = entry(std::string(m_signature.bytes.begin(), m_signature.bytes.end()));

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
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key("i")))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
        // version
        if (auto* i = const_cast<entry *>(e.find_key("v")))
        {
            m_version = static_cast<tx_version>(i->integer());
        }
        // type
        if (auto* i = const_cast<entry *>(e.find_key("e")))
        {
            m_type = static_cast<tx_type>(i->integer());
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
            m_sender = dht::public_key(sender.data());
        }
        // receiver
        if (auto* i = const_cast<entry *>(e.find_key("r")))
        {
            auto receiver = i->string();
            m_receiver = dht::public_key(receiver.data());
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
            m_signature = dht::signature(signature.data());
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