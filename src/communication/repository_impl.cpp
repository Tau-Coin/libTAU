/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/block_wrapper.hpp"
#include "libTAU/blockchain/repository_impl.hpp"

namespace libTAU::blockchain {

    bool repository_impl::init() {
        return false;
    }

    // check block number
    account repository_impl::get_account(aux::bytes chain_id, dht::public_key pubKey) {
        std::string sKey;
        sKey.insert(sKey.end(), chain_id.begin(), chain_id.end());
        sKey.insert(sKey.end(), pubKey.bytes.begin(), pubKey.bytes.end());

        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), sKey, &value);

        if (status.ok() && !value.empty()) {
            std::string block_encode;
            status = m_leveldb->Get(leveldb::ReadOptions(), value, &block_encode);

            if (status.ok() && !block_encode.empty()) {
                block b(block_encode);
                if (pubKey == b.miner()) {
                    return account(b.miner_balance(), b.miner_nonce());
                } else if (pubKey == b.tx().sender()) {
                    return account(b.sender_balance(), b.sender_nonce());
                } else if (pubKey == b.tx().receiver()) {
                    return account(b.receiver_balance(), b.receiver_nonce());
                }
            }
        }

        return account(0, 0);
    }

    account repository_impl::get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) {
        return account(0, 0);
    }

    bool repository_impl::is_block_exist(aux::bytes chain_id, sha256_hash hash) {
        return false;
    }

    bool repository_impl::save_block(block b, bool main_chain) {
        std::int64_t m_miner_last_change_block_number = -1;
        std::int64_t m_sender_last_change_block_number = -1;
        std::int64_t m_receiver_last_change_block_number = -1;

        auto& chain_id = b.chain_id();
        auto& miner = b.miner();

        std::string minerBlockKey;
        minerBlockKey.insert(minerBlockKey.end(), chain_id.begin(), chain_id.end());
        minerBlockKey.insert(minerBlockKey.end(), miner.bytes.begin(), miner.bytes.end());
        std::string block_encode;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), minerBlockKey, &block_encode);
        if (status.ok() && !block_encode.empty()) {

        }

        block_wrapper blockWrapper();
        return false;
    }

    block repository_impl::get_block_by_hash(aux::bytes chain_id, sha256_hash hash) {
        return block();
    }
}
