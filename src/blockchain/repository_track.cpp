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
        return false;
    }

    bool repository_track::delete_user_state_db(aux::bytes chain_id) {
        return false;
    }

    std::set<dht::public_key> repository_track::get_all_peers(aux::bytes chain_id) {
        return m_repository->get_all_peers(chain_id);
    }

    bool repository_track::delete_peer(aux::bytes chain_id, dht::public_key pubKey) {
        return false;
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

//    account repository_track::get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) {
//        auto s = get_account(chain_id, pubKey);
//
//        if (s.empty()) {
//            return get_account_from_user_db(chain_id, pubKey);
//        }
//
//        return s;
//    }

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

//    bool repository_track::save_block(block b, bool main_chain) {
//        return true;
//    }

    bool repository_track::forward_update_last_change_block_hash(aux::bytes chain_id, const dht::public_key &pubKey,
                                                                 state_linker &stateLinker, sha256_hash current_block_hash) {
        sha256_hash block_hash = get_account_block_hash(chain_id, pubKey);
        if (!block_hash.is_all_zeros()) {
            auto linker = get_state_linker(block_hash);
            if (linker.empty()) {
                return false;
            }

            stateLinker.update_previous_change_block_hash(pubKey, block_hash);
            stateLinker.update_last_change_block_hash(pubKey, linker.get_peer_last_change_block_hash(pubKey));
        } else {
            stateLinker.update_last_change_block_hash(pubKey, current_block_hash);
        }

        return true;
    }

    bool repository_track::backward_update_last_change_block_hash(aux::bytes chain_id, const dht::public_key &pubKey,
                                                                  state_linker& stateLinker, sha256_hash current_block_hash) {
        sha256_hash block_hash = get_account_block_hash(chain_id, pubKey);
        if (!block_hash.is_all_zeros()) {
            auto linker = get_state_linker(block_hash);
            if (linker.empty()) {
                return false;
            }

            sha256_hash current_last_change_hash = linker.get_peer_last_change_block_hash(pubKey);
            if (current_last_change_hash == block_hash) {
                linker.update_previous_change_block_hash(pubKey, current_block_hash);
            } else {
                auto current_last_change_hash_linker = get_state_linker(current_last_change_hash);
                if (current_last_change_hash_linker.empty())
                    return false;
                current_last_change_hash_linker.update_previous_change_block_hash(pubKey, current_block_hash);
                if (!save_state_linker(current_last_change_hash_linker))
                    return false;
            }

            linker.update_last_change_block_hash(pubKey, current_block_hash);
            if (!save_state_linker(linker))
                return false;
        } else {
            // save in db first time
            stateLinker.update_last_change_block_hash(pubKey, current_block_hash);

            if (!save_account_block_hash(chain_id, pubKey, current_block_hash))
                return false;
        }

        return true;
    }

    bool repository_track::connect_tip_block(block b) {
        m_main_chain_blocks.push_back(b);

        // save block
        if (!save_block(b))
            return false;

        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
        indexKeyInfo.set_main_chain_block_hash(b.sha256());
        indexKeyInfo.add_associated_peer(b.miner());

        state_linker stateLinker(b.sha256());
        auto& chain_id = b.chain_id();

        if (!forward_update_last_change_block_hash(chain_id, b.miner(), stateLinker, b.sha256()))
            return false;
        // save miner state
        if (!save_account_block_hash(chain_id, b.miner(), b.sha256()))
            return false;

        auto tx = b.tx();
        if (!tx.empty()) {
            if (!forward_update_last_change_block_hash(chain_id, tx.sender(), stateLinker, b.sha256()))
                return false;
            // save state
            if (!save_account_block_hash(chain_id, tx.sender(), b.sha256()))
                return false;

            if (!forward_update_last_change_block_hash(chain_id, tx.receiver(), stateLinker, b.sha256()))
                return false;
            // save state
            if (!save_account_block_hash(chain_id, tx.receiver(), b.sha256()))
                return false;

            indexKeyInfo.add_associated_peer(tx.sender());
            indexKeyInfo.add_associated_peer(tx.receiver());
        }

        if (!save_state_linker(stateLinker))
            return false;

        if (!save_index_info(b.chain_id(), b.block_number(), indexKeyInfo))
            return false;

        return true;
    }

    bool repository_track::connect_tail_block(block b) {
        m_main_chain_blocks.push_back(b);

        // save block
        if (!save_block(b))
            return false;

        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
        indexKeyInfo.set_main_chain_block_hash(b.sha256());
        indexKeyInfo.add_associated_peer(b.miner());

        state_linker stateLinker(b.sha256());
        auto& chain_id = b.chain_id();
        if (!backward_update_last_change_block_hash(chain_id, b.miner(), stateLinker, b.sha256()))
            return false;
        auto tx = b.tx();
        if (!tx.empty()) {
            if (!backward_update_last_change_block_hash(chain_id, tx.sender(), stateLinker, b.sha256()))
                return false;
            if (!backward_update_last_change_block_hash(chain_id, tx.receiver(), stateLinker, b.sha256()))
                return false;

            indexKeyInfo.add_associated_peer(tx.sender());
            indexKeyInfo.add_associated_peer(tx.receiver());
        }

        if (!save_state_linker(stateLinker))
            return false;

        if (!save_index_info(b.chain_id(), b.block_number(), indexKeyInfo))
            return false;

        return true;
    }

    bool repository_track::rollback_block(block b) {
        if (b.empty())
            return false;

        auto& chain_id = b.chain_id();
        auto stateLinker = get_state_linker(b.sha256());
        for (auto const& item: stateLinker.get_previous_change_block_hash_map()) {
            auto& pubKey = item.first;
            auto& block_hash = item.second;
            save_account_block_hash(chain_id, pubKey, block_hash);

            // record last change block hash
            auto linker = get_state_linker(block_hash);
            if (linker.empty())
                return false;
            linker.update_last_change_block_hash(pubKey, stateLinker.get_peer_last_change_block_hash(pubKey));
            if (!save_state_linker(linker))
                return false;
        }

        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
        indexKeyInfo.add_non_main_chain_block_hash(b.sha256());
        indexKeyInfo.clear_main_chain_block_hash();
        indexKeyInfo.clear_associated_peers();
        if (!save_index_info(b.chain_id(), b.block_number(), indexKeyInfo))
            return false;

        return true;
    }

    bool repository_track::delete_block(sha256_hash hash) {
        m_cache[hash.to_string()] = std::string ();
        return true;
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
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tip_block_hash.begin(), key_suffix_best_tip_block_hash.end());
        m_cache[key] = std::string ();

        return true;
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
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tail_block_hash.begin(), key_suffix_best_tail_block_hash.end());
        m_cache[key] = std::string ();

        return true;
    }

    repository *repository_track::start_tracking() {
        return new repository_track(this);
    }

    void repository_track::update_batch(std::map<std::string, std::string> cache, std::vector<block> main_chain_blocks) {
        m_cache.insert(cache.begin(), cache.end());
        m_main_chain_blocks.insert(m_main_chain_blocks.end(), main_chain_blocks.begin(), main_chain_blocks.end());
    }

    // unsupported
    bool repository_track::flush() {
        return false;
    }

    bool repository_track::commit() {
        m_repository->update_batch(m_cache, m_main_chain_blocks);
        m_cache.clear();
        m_main_chain_blocks.clear();

        return true;
    }

    void repository_track::rollback() {
        m_cache.clear();
    }

//    account repository_track::get_account_from_user_db(aux::bytes chain_id, dht::public_key pubKey) {
//        return m_repository->get_account_from_user_db(chain_id, pubKey);
//    }

    bool repository_track::update_user_state_db(block b) {
        update_user_state_db(b.chain_id(), b.miner());

        auto tx = b.tx();
        if (!tx.empty()) {
            update_user_state_db(b.chain_id(), tx.sender());
            update_user_state_db(b.chain_id(), tx.receiver());
        }

        return true;
    }

    bool repository_track::update_user_state_db(aux::bytes chain_id, dht::public_key pubKey) {
        return m_repository->update_user_state_db(chain_id, pubKey);
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

    bool repository_track::delete_account_block_hash(aux::bytes chain_id, dht::public_key pubKey) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());

        m_cache[key] = std::string ();
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

    bool repository_track::delete_state_linker(sha256_hash block_hash) {
        std::string key;
        key.insert(key.end(), block_hash.begin(), block_hash.end());
        key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());

        m_cache[key] = std::string ();
        return true;
    }

    bool repository_track::save_block(block b) {
        if (b.empty())
            return false;

        m_cache[b.sha256().to_string()] = b.get_encode();
        return true;
    }

    bool repository_track::save_non_main_chain_block(block b) {
        // save block
        if (!save_block(b))
            return false;

        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
        indexKeyInfo.add_non_main_chain_block_hash(b.sha256());
        if (!save_index_info(b.chain_id(), b.block_number(), indexKeyInfo))
            return false;

        return true;
    }

    bool repository_track::delete_index_info(aux::bytes chain_id, std::int64_t block_number) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_separator.begin(), key_separator.end());
        std::string str_num = std::to_string(block_number);
        key.insert(key.end(), str_num.begin(), str_num.end());

        m_cache[key] = std::string ();

        return true;
    }

    index_key_info repository_track::get_index_info(aux::bytes chain_id, std::int64_t block_number) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_separator.begin(), key_separator.end());
        std::string str_num = std::to_string(block_number);
        key.insert(key.end(), str_num.begin(), str_num.end());

        auto it = m_cache.find(key);
        if (it != m_cache.end()) {
            std::string value = it->second;
            return index_key_info(value);
        } else {
            return m_repository->get_index_info(chain_id, block_number);
        }
    }

    bool repository_track::save_index_info(aux::bytes chain_id, std::int64_t block_number, index_key_info indexKeyInfo) {
        if (indexKeyInfo.empty())
            return false;

        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_separator.begin(), key_separator.end());
        std::string str_num = std::to_string(block_number);
        key.insert(key.end(), str_num.begin(), str_num.end());

        m_cache[key] = indexKeyInfo.get_encode();

        return true;
    }

    bool repository_track::delete_outdated_data_by_height(aux::bytes chain_id, std::int64_t block_number) {
        index_key_info indexKeyInfo = get_index_info(chain_id, block_number);
        auto& main_chain_block_hash = indexKeyInfo.main_chain_block_hash();
        if (!main_chain_block_hash.is_all_zeros()) {
            if (!delete_block(main_chain_block_hash))
                return false;
            if (!delete_state_linker(main_chain_block_hash))
                return false;
        }

        auto& non_main_chain_block_hash_set = indexKeyInfo.non_main_chain_block_hash_set();
        for (auto const& hash: non_main_chain_block_hash_set) {
            if (!delete_block(hash))
                return false;
            if (!delete_state_linker(hash))
                return false;
        }

        auto& associated_peers = indexKeyInfo.associated_peers();
        for (auto const& peer: associated_peers) {
            auto s = get_account(chain_id, peer);
            if (!s.empty() && s.block_number() <= block_number) {
                if (!delete_account_block_hash(chain_id, peer))
                    return false;
            }
        }

        if (!delete_index_info(chain_id, block_number))
            return false;

        return true;
    }

}
