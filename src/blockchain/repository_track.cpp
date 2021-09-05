/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/repository_track.hpp"

namespace libTAU::blockchain {

    bool repository_track::init() {
        return false;
    }

    bool repository_track::create_user_state_db(aux::bytes chain_id) {
        return m_repository->create_user_state_db(chain_id);
    }

    bool repository_track::delete_user_state_db(aux::bytes chain_id) {
        return m_repository->delete_user_state_db(chain_id);
    }

    std::set<dht::public_key> repository_track::get_all_peers(aux::bytes chain_id) {
        return m_repository->get_all_peers(chain_id);
    }

    bool repository_track::is_account_exist(aux::bytes chain_id, dht::public_key pubKey) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());

        if (m_cache.find(key) != m_cache.end()) {
            return true;
        }

        return m_repository->is_account_exist(chain_id, pubKey);
    }

    account repository_track::get_account(aux::bytes chain_id, dht::public_key pubKey) {
        sha256_hash block_hash = get_account_block_hash(chain_id, pubKey);

        if (!block_hash.is_all_zeros()) {
            block b = get_block_by_hash(block_hash);
            if (!b.empty()) {
                return find_state_from_block(pubKey, b);
            }
        }

        return account(0, 0, 0);
    }

    account repository_track::get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) {
        auto s = get_account(chain_id, pubKey);

        if (s.empty()) {
            return get_account_from_user_db(chain_id, pubKey);
        }

        return s;
    }

    bool repository_track::is_block_exist(sha256_hash hash) {
        if (m_cache.find(hash.to_string()) != m_cache.end()) {
            return true;
        }

        return m_repository->is_block_exist(hash);
    }

    block repository_track::get_block_by_hash(sha256_hash hash) {
        auto it = m_cache.find(hash.to_string());
        if (it != m_cache.end()) {
            std::string value = it->second;
            return block(value);
        } else {
            return m_repository->get_block_by_hash(hash);
        }
    }

    bool repository_track::save_block(block b, bool main_chain) {
        if (!save_block(b))
            return false;

        if (main_chain) {
            auto& chain_id = b.chain_id();
            std::map<dht::public_key, sha256_hash> last_change_block_hash_map;

            auto& miner = b.miner();
            sha256_hash miner_block_hash = get_account_block_hash(chain_id, miner);
            block miner_block = get_block_by_hash(miner_block_hash);
            if (b.block_number() > miner_block.block_number()) {
                // connect
                last_change_block_hash_map[miner] = miner_block.sha256();

                if (!save_account_block_hash(chain_id, miner, b.sha256()))
                    return false;
            } else if (b.block_number() < miner_block.block_number()) {
                // sync
                auto linker = get_state_linker(miner_block_hash);
                linker.insert(miner, b.sha256());

                if (!save_state_linker(linker))
                    return false;
            }

            auto tx = b.tx();
            if (!tx.empty()) {
                auto &sender = tx.sender();
                sha256_hash sender_block_hash = get_account_block_hash(chain_id, sender);
                block sender_block = get_block_by_hash(sender_block_hash);
                if (b.block_number() > sender_block.block_number()) {
                    // connect
                    last_change_block_hash_map[sender] = sender_block.sha256();

                    if (!save_account_block_hash(chain_id, sender, b.sha256()))
                        return false;
                } else if (b.block_number() < sender_block.block_number()) {
                    // sync
                    auto linker = get_state_linker(sender_block_hash);
                    linker.insert(sender, b.sha256());
                    if (!save_state_linker(linker))
                        return false;
                }

                auto &receiver = tx.sender();
                sha256_hash receiver_block_hash = get_account_block_hash(chain_id, receiver);
                block receiver_block = get_block_by_hash(receiver_block_hash);
                if (b.block_number() > receiver_block.block_number()) {
                    // connect
                    last_change_block_hash_map[receiver] = receiver_block.sha256();

                    if (!save_account_block_hash(chain_id, receiver, b.sha256()))
                        return false;
                } else if (b.block_number() < receiver_block.block_number()) {
                    // sync
                    auto linker = get_state_linker(receiver_block_hash);
                    linker.insert(receiver, b.sha256());

                    if (!save_state_linker(linker))
                        return false;
                }
            }

            state_linker stateLinker(b.sha256(), last_change_block_hash_map);
            if (!save_state_linker(stateLinker))
                return false;
        } else {
            update_user_state_db(b);
        }

        return true;
    }

    bool repository_track::rollback_block(block b) {
        if (b.empty())
            return false;

        auto& chain_id = b.chain_id();
        auto stateLinker = get_state_linker(b.sha256());
        for (auto const& item: stateLinker.get_last_change_block_hash_map()) {
            save_account_block_hash(chain_id, item.first, item.second);
        }

        return true;
    }

    bool repository_track::delete_block(sha256_hash hash) {
        return m_repository->delete_block(hash);
    }

    sha256_hash repository_track::get_best_tip_block_hash(aux::bytes chain_id) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tip_block_hash.begin(), key_suffix_best_tip_block_hash.end());

        auto it = m_cache.find(key);
        if (it != m_cache.end()) {
            std::string value = it->second;
            return sha256_hash (value.data());
        } else {
            return m_repository->get_best_tip_block_hash(chain_id);
        }
    }

    bool repository_track::set_best_tip_block_hash(aux::bytes chain_id, sha256_hash hash) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tip_block_hash.begin(), key_suffix_best_tip_block_hash.end());
        m_cache[key] = hash.to_string();

        return true;
    }

    bool repository_track::delete_best_tip_block_hash(aux::bytes chain_id) {
        return m_repository->delete_best_tip_block_hash(chain_id);
    }

    sha256_hash repository_track::get_best_tail_block_hash(aux::bytes chain_id) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tail_block_hash.begin(), key_suffix_best_tail_block_hash.end());

        auto it = m_cache.find(key);
        if (it != m_cache.end()) {
            std::string value = it->second;
            return sha256_hash (value.data());
        } else {
            return m_repository->get_best_tail_block_hash(chain_id);
        }
    }

    bool repository_track::set_best_tail_block_hash(aux::bytes chain_id, sha256_hash hash) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tail_block_hash.begin(), key_suffix_best_tail_block_hash.end());
        m_cache[key] = hash.to_string();

        return true;
    }

    bool repository_track::delete_best_tail_block_hash(aux::bytes chain_id) {
        return m_repository->delete_best_tip_block_hash(chain_id);
    }

    repository *repository_track::start_tracking() {
        return new repository_track(this);
    }

    void repository_track::update_batch(std::map<std::string, std::string> cache) {
        m_cache.insert(cache.begin(), cache.end());
    }

    // unsupported
    void repository_track::flush() {

    }

    void repository_track::commit() {

    }

    void repository_track::rollback() {
        m_cache.clear();
    }

    account repository_track::get_account_from_user_db(aux::bytes chain_id, dht::public_key pubKey) {
        return m_repository->get_account_from_user_db(chain_id, pubKey);
    }

    bool repository_track::update_user_state_db(block b) {
        return m_repository->update_user_state_db(b);
    }

    bool repository_track::update_user_state_db(aux::bytes chain_id, dht::public_key pubKey, std::int64_t balance,
                                                std::int64_t nonce, std::int64_t height) {
        return m_repository->update_user_state_db(chain_id, pubKey, balance, nonce, height);
    }

    sha256_hash repository_track::get_account_block_hash(aux::bytes chain_id, dht::public_key pubKey) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());

        auto it = m_cache.find(key);
        if (it != m_cache.end()) {
            std::string value = it->second;
            return sha256_hash(value.data());
        } else {
            return m_repository->get_account_block_hash(chain_id, pubKey);
        }
    }

    bool repository_track::save_account_block_hash(aux::bytes chain_id, dht::public_key pubKey, sha256_hash hash) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());

        m_cache[key] = hash.to_string();

        return true;
    }

    account repository_track::find_state_from_block(dht::public_key pubKey, block b) {
        if (pubKey == b.miner()) {
            return account(b.miner_balance(), b.miner_nonce(), b.block_number());
        } else if (pubKey == b.tx().sender()) {
            return account(b.sender_balance(), b.sender_nonce(), b.block_number());
        } else if (pubKey == b.tx().receiver()) {
            return account(b.receiver_balance(), b.receiver_nonce(), b.block_number());
        }

        return account(0, 0, 0);
    }

    state_linker repository_track::get_state_linker(sha256_hash block_hash) {
        std::string key;
        key.insert(key.end(), block_hash.begin(), block_hash.end());
        key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());

        auto it = m_cache.find(key);
        if (it != m_cache.end()) {
            std::string value = it->second;
            return state_linker(value);
        } else {
            return m_repository->get_state_linker(block_hash);
        }
    }

    bool repository_track::save_state_linker(state_linker stateLinker) {
        std::string key;
        auto& block_hash = stateLinker.block_hash();
        key.insert(key.end(), block_hash.begin(), block_hash.end());
        key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());

        m_cache[key] = stateLinker.get_encode();
        return true;
    }

    bool repository_track::save_block(block b) {
        if (b.empty())
            return false;

        m_cache[b.sha256().to_string()] = b.get_encode();
        return true;
    }
}
