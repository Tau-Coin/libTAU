/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/block.hpp"

namespace libTAU::blockchain {
    block::block(entry e) {
        populate(e);
    }

    void block::populate(const entry &e) {
        // version
        if (auto* i = const_cast<entry *>(e.find_key("v")))
        {
            m_version = static_cast<block_version>(i->integer());
        }
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key("c")))
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
            m_miner = aux::bytes(miner.begin(), miner.end());
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
            m_signature = aux::bytes(signature.begin(), signature.end());
        }
    }
}