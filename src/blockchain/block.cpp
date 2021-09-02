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

    const sha256_hash &block::sha256() {
        if (m_hash.is_all_zeros()) {
            auto encode = get_encode();
            m_hash = dht::item_target_id(encode);
        }

        return m_hash;
    }

    void block::sign(const dht::public_key &pk, const dht::secret_key &sk) {
        m_signature = ed25519_sign(get_encode_without_signature(), pk, sk);
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

        // version
        e["v"] = entry(m_version);
        // chain id
        e["i"] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // timestamp
        e["t"] = entry(m_timestamp);
        // block number
        e["n"] = entry(m_block_number);
        // previous block root
        e["h"] = entry(std::string(m_previous_block_root.begin(), m_previous_block_root.end()));
        // base target
        e["b"] = entry(m_base_target);
        // cumulative difficulty
        e["d"] = entry(m_cumulative_difficulty);
        // tx
        e["tx"] = m_tx.get_entry();
        // miner
        e["m"] = entry(std::string(m_miner.bytes.begin(), m_miner.bytes.end()));
        // miner balance
        e["mb"] = entry(m_miner_balance);
        // miner nonce
        e["mn"] = entry(m_miner_nonce);
        // sender balance
        e["sb"] = entry(m_sender_balance);
        // sender nonce
        e["sn"] = entry(m_sender_nonce);
        // receiver balance
        e["rb"] = entry(m_receiver_balance);
        // receiver nonce
        e["rn"] = entry(m_receiver_nonce);

        return e;
    }


    void block::populate(const entry &e) {
        // version
        if (auto* i = const_cast<entry *>(e.find_key("v")))
        {
            m_version = static_cast<block_version>(i->integer());
        }
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key("i")))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
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
        // previous block root
        if (auto* i = const_cast<entry *>(e.find_key("h")))
        {
            auto previous_block_root = i->string();
            m_previous_block_root = aux::bytes(previous_block_root.begin(), previous_block_root.end());
        }
        // base target
        if (auto* i = const_cast<entry *>(e.find_key("b")))
        {
            m_base_target = i->integer();
        }
        // cumulative difficulty
        if (auto* i = const_cast<entry *>(e.find_key("d")))
        {
            m_cumulative_difficulty = i->integer();
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
        // signature
        if (auto* i = const_cast<entry *>(e.find_key("sig")))
        {
            auto signature = i->string();
            m_signature = dht::signature(signature.data());
        }
    }
}