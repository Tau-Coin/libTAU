/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/state_linker.hpp"
#include "libTAU/blockchain/repository_impl.hpp"

namespace libTAU::blockchain {

    const std::string key_state_linker_suffix = "linker";

    bool repository_impl::init() {
        return false;
    }

    bool repository_impl::is_account_exist(aux::bytes chain_id, dht::public_key pubKey) {
        std::string sKey;
        sKey.insert(sKey.end(), chain_id.begin(), chain_id.end());
        sKey.insert(sKey.end(), pubKey.bytes.begin(), pubKey.bytes.end());
        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), sKey, &value);

        return status.ok();
    }

    // check block number
    account repository_impl::get_account(aux::bytes chain_id, dht::public_key pubKey) {
        sha256_hash block_hash = get_account_block_hash(chain_id, pubKey);

        if (!block_hash.is_all_zeros()) {
            block b = get_block_by_hash(block_hash);
            if (!b.empty()) {
                return find_state_from_block(pubKey, b);
            }
        }

        return account(0, 0);
    }

    account repository_impl::get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) {
        return account(0, 0);
    }

    sha256_hash repository_impl::get_account_block_hash(aux::bytes chain_id, dht::public_key pubKey) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());

        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);

        return sha256_hash(value.data());
    }

    bool repository_impl::save_account_block_hash(aux::bytes chain_id, dht::public_key pubKey, sha256_hash hash) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, hash.to_string());

        return status.ok();
    }

    bool repository_impl::is_block_exist(sha256_hash hash) {
        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), hash.to_string(), &value);

        return status.ok();
    }

    block repository_impl::get_block_by_hash(sha256_hash hash) {
        std::string value;
        m_leveldb->Get(leveldb::ReadOptions(), hash.to_string(), &value);

        if (value.empty()) {
            return block(value);
        }

        return block();
    }

    account repository_impl::find_state_from_block(dht::public_key pubKey, block b) {
        if (pubKey == b.miner()) {
            return account(b.miner_balance(), b.miner_nonce());
        } else if (pubKey == b.tx().sender()) {
            return account(b.sender_balance(), b.sender_nonce());
        } else if (pubKey == b.tx().receiver()) {
            return account(b.receiver_balance(), b.receiver_nonce());
        }

        return account(0, 0);
    }

    state_linker repository_impl::get_state_linker(sha256_hash block_hash) {
        std::string key;
        key.insert(key.end(), block_hash.begin(), block_hash.end());
        key.insert(key.end(), key_state_linker_suffix.begin(), key_state_linker_suffix.end());
        std::string value;
        m_leveldb->Get(leveldb::ReadOptions(), key, &value);

        if (value.empty()) {
            return state_linker(value);
        }

        return state_linker();
    }

    bool repository_impl::save_state_linker(state_linker stateLinker) {
        std::string key;
        auto& block_hash = stateLinker.block_hash();
        key.insert(key.end(), block_hash.begin(), block_hash.end());
        key.insert(key.end(), key_state_linker_suffix.begin(), key_state_linker_suffix.end());

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, stateLinker.get_encode());
        return status.ok();
    }

    bool repository_impl::save_block(block b) {
        if (b.empty())
            return false;

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(),
                                                b.sha256().to_string(), b.get_encode());
        return status.ok();
    }

    bool repository_impl::save_block(block b, bool main_chain) {
        if (!save_block(b))
            return false;

        if (main_chain) {
        } else {
            populate_state_from_block(b);
        }

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

        state_linker blockWrapper();
        return false;
    }

    bool repository_impl::rollback_block(block b) {
        return false;
    }

    bool repository_impl::populate_state_from_block(block b) {
        return false;
    }

    bool repository_impl::delete_block(sha256_hash hash) {
        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), hash.to_string());
        return status.ok();
    }
}
