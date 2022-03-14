/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/kademlia/item.hpp"
#include "libTAU/kademlia/ed25519.hpp"
#include "libTAU/blockchain/block.hpp"

namespace libTAU::blockchain {
    block::block(const entry& e) {
        populate(e);

        std::string encode;
        bencode(std::back_inserter(encode), e);
        m_hash = dht::item_target_id(encode);
    }

    entry block::get_entry() const {
        auto e = get_entry_without_signature();
        // signature
        e["sig"] = entry(std::string(m_signature.bytes.begin(), m_signature.bytes.end()));

        return e;
    }

    std::string block::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

//    const sha256_hash &block::sha256() {
//        if (m_hash.is_all_zeros()) {
//            auto encode = get_encode();
//            m_hash = dht::item_target_id(encode);
//        }
//
//        return m_hash;
//    }

    void block::sign(const dht::public_key &pk, const dht::secret_key &sk) {
        m_signature = ed25519_sign(get_encode_without_signature(), pk, sk);

        auto encode = get_encode();
        m_hash = dht::item_target_id(encode);
    }

    bool block::verify_signature() const {
        return ed25519_verify(m_signature, get_encode_without_signature(), m_miner);
    }

    std::string block::get_encode_without_signature() const {
        std::string encode;
        auto e = get_entry_without_signature();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    entry block::get_entry_without_signature() const {
        entry e(entry::dictionary_t);

        // chain id
        e["i"] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // version
        e["v"] = entry(m_version);
        // timestamp
        e["t"] = entry(m_timestamp);
        // block number
        e["n"] = entry(m_block_number);
        // previous block hash
        e["h"] = entry(m_previous_block_hash.to_string());
        // base target
        e["b"] = entry(static_cast<std::int64_t>(m_base_target));
        // cumulative difficulty
        e["d"] = entry(static_cast<std::int64_t>(m_cumulative_difficulty));
        // generation signature
        e["g"] = entry(m_generation_signature.to_string());
        // miner
        e["m"] = entry(std::string(m_miner.bytes.begin(), m_miner.bytes.end()));
        // miner balance
        e["mb"] = entry(m_miner_balance);
        // miner nonce
        e["mn"] = entry(m_miner_nonce);
        // miner note timestamp
        e["mt"] = entry(m_miner_note_timestamp);
        if (!m_tx.empty()) {
            // tx
            e["tx"] = m_tx.get_entry();
            // sender balance
            e["sb"] = entry(m_sender_balance);
            // sender nonce
            e["sn"] = entry(m_sender_nonce);
            // sender note timestamp
            e["st"] = entry(m_sender_note_timestamp);
            // receiver balance
            e["rb"] = entry(m_receiver_balance);
            // receiver nonce
            e["rn"] = entry(m_receiver_nonce);
            // receiver note timestamp
            e["rt"] = entry(m_receiver_note_timestamp);
        }

        if (m_endpoint.port() != 0) {
            entry ne(entry::dictionary_t);

            // address
            if (m_endpoint.address().is_v4()) {
                // ipv4
                address_v4::bytes_type b = m_endpoint.address().to_v4().to_bytes();
                ne["4"] = entry(std::string(b.begin(), b.end()));
            } else {
                // ipv6
                address_v6::bytes_type b = m_endpoint.address().to_v6().to_bytes();
                ne["6"] = entry(std::string(b.begin(), b.end()));
            }

            // port
            ne["p"] = entry(m_endpoint.port());

            e["ep"] = ne;
        }

        return e;
    }


    void block::populate(const entry &e) {
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key("i")))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
        // version
        if (auto* i = const_cast<entry *>(e.find_key("v")))
        {
            m_version = static_cast<block_version>(i->integer());
        }
        // timestamp
        if (auto* i = const_cast<entry *>(e.find_key("t")))
        {
            m_timestamp = i->integer();
        }
        // block number
        if (auto* i = const_cast<entry *>(e.find_key("n")))
        {
            m_block_number = i->integer();
        }
        // previous block hash
        if (auto* i = const_cast<entry *>(e.find_key("h")))
        {
            auto previous_block_hash = i->string();
            m_previous_block_hash = sha256_hash(previous_block_hash.data());
        }
        // base target
        if (auto* i = const_cast<entry *>(e.find_key("b")))
        {
            m_base_target = static_cast<std::uint64_t>(i->integer());
        }
        // cumulative difficulty
        if (auto* i = const_cast<entry *>(e.find_key("d")))
        {
            m_cumulative_difficulty = static_cast<std::uint64_t>(i->integer());
        }
        // generation signature
        if (auto* i = const_cast<entry *>(e.find_key("g")))
        {
            auto generation_signature = i->string();
            m_generation_signature = sha256_hash(generation_signature.data());
        }
        // transaction
        if (auto* i = const_cast<entry *>(e.find_key("tx")))
        {
            m_tx = transaction(*i);
        }
        // miner
        if (auto* i = const_cast<entry *>(e.find_key("m")))
        {
            auto miner = i->string();
            m_miner = dht::public_key(miner.data());
        }
        // miner balance
        if (auto* i = const_cast<entry *>(e.find_key("mb")))
        {
            m_miner_balance = i->integer();
        }
        // miner nonce
        if (auto* i = const_cast<entry *>(e.find_key("mn")))
        {
            m_miner_nonce = i->integer();
        }
        // miner note timestamp
        if (auto* i = const_cast<entry *>(e.find_key("mt")))
        {
            m_miner_note_timestamp = i->integer();
        }
        // sender balance
        if (auto* i = const_cast<entry *>(e.find_key("sb")))
        {
            m_sender_balance = i->integer();
        }
        // sender nonce
        if (auto* i = const_cast<entry *>(e.find_key("sn")))
        {
            m_sender_nonce = i->integer();
        }
        // sender note timestamp
        if (auto* i = const_cast<entry *>(e.find_key("st")))
        {
            m_sender_note_timestamp = i->integer();
        }
        // receiver balance
        if (auto* i = const_cast<entry *>(e.find_key("rb")))
        {
            m_receiver_balance = i->integer();
        }
        // receiver nonce
        if (auto* i = const_cast<entry *>(e.find_key("rn")))
        {
            m_receiver_nonce = i->integer();
        }
        // receiver note timestamp
        if (auto* i = const_cast<entry *>(e.find_key("rt")))
        {
            m_receiver_note_timestamp = i->integer();
        }
        // signature
        if (auto* i = const_cast<entry *>(e.find_key("sig")))
        {
            auto signature = i->string();
            m_signature = dht::signature(signature.data());
        }
        // endpoint
        if (auto* i = const_cast<entry *>(e.find_key("ep")))
        {
            entry ne = entry(*i);

            // ip
            if (auto* ipv4_ptr = const_cast<entry *>(ne.find_key("4"))) {
                // make ipv4
                std::string ipv4 = ipv4_ptr->string();
                address_v4::bytes_type b;
                memcpy(&b[0], ipv4.c_str(), b.size());
                address addr = make_address_v4(b);

                // port
                if (auto* p = const_cast<entry *>(ne.find_key("p")))
                {
                    u_int16_t port = p->integer();
                    if (port != 0) {
                        m_endpoint = udp::endpoint(addr, port);
                    }
                }
            } else if (auto* ipv6_ptr = const_cast<entry *>(ne.find_key("6"))) {
                // make ipv6
                std::string ipv6 = ipv6_ptr->string();
                address_v6::bytes_type b;
                memcpy(&b[0], ipv6.c_str(), b.size());
                address addr = make_address_v6(b);

                // port
                if (auto* p = const_cast<entry *>(ne.find_key("p")))
                {
                    u_int16_t port = p->integer();
                    if (port != 0) {
                        m_endpoint = udp::endpoint(addr, port);
                    }
                }
            }
        }
    }

    std::set<dht::public_key> block::get_block_peers() const {
        std::set<dht::public_key> peers;
        peers.insert(m_miner);
//        auto tx = m_tx;
        if (!m_tx.empty()) {
            peers.insert(m_tx.sender());
            peers.insert(m_tx.receiver());
        }

        return peers;
    }

    std::string block::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const block &block) {
        os << "m_chain_id: " << aux::toHex(block.m_chain_id) << " m_version: " << block.m_version << " m_timestamp: "
           << block.m_timestamp << " m_block_number: " << block.m_block_number << " m_previous_block_hash: "
           << aux::toHex(block.m_previous_block_hash.to_string()) << " m_base_target: " << block.m_base_target << " m_cumulative_difficulty: "
           << block.m_cumulative_difficulty << " m_generation_signature: " << aux::toHex(block.m_generation_signature.to_string()) << " m_tx: "
           << block.m_tx << " m_miner: " << aux::toHex(block.m_miner.bytes) << " m_miner_balance: " << block.m_miner_balance
           << " m_miner_nonce: " << block.m_miner_nonce << " m_miner_note_timestamp: " << block.m_miner_note_timestamp
           << " m_sender_balance: " << block.m_sender_balance << " m_sender_nonce: " << block.m_sender_nonce
           << " m_sender_note_timestamp: " << block.m_sender_note_timestamp << " m_receiver_balance: " << block.m_receiver_balance
           << " m_receiver_nonce: " << block.m_receiver_nonce << " m_receiver_note_timestamp: " << block.m_receiver_note_timestamp
           << " m_end_point ip: " << block.m_endpoint.address().to_string() << " port: " << block.m_endpoint.port()
           << " m_hash: " << aux::toHex(block.m_hash.to_string());
        return os;
    }
}