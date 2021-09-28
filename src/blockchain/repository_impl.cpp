/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/state_linker.hpp"
#include "libTAU/blockchain/repository_impl.hpp"

namespace libTAU::blockchain {

    bool repository_impl::init() {
        return true;
    }


    bool repository_impl::create_user_state_db(const aux::bytes &chain_id) {
        std::string sql = "CREATE TABLE IF NOT EXISTS ";
        sql.append(std::string(chain_id.begin(), chain_id.end()));
        sql.append("(PUBKEY VARCHAR(32) PRIMARY KEY NOT NULL);");

        char *zErrMsg = nullptr;
        int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
        if (ok != SQLITE_OK) {
            sqlite3_free(zErrMsg);
            return false;
        }

        return true;
    }

    bool repository_impl::delete_user_state_db(const aux::bytes &chain_id) {
        std::string sql = "DROP TABLE ";
        sql.append(std::string(chain_id.begin(), chain_id.end()));

        char *zErrMsg = nullptr;
        int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
        if (ok != SQLITE_OK) {
            sqlite3_free(zErrMsg);
            return false;
        }

        return true;
    }

//    account repository_impl::get_account_from_user_db(aux::bytes chain_id, dht::public_key pubKey) {
//        std::int64_t balance;
//        std::int64_t nonce;
//        std::int64_t height;
//
//        sqlite3_stmt * stmt;
//        std::string sql = "SELECT BALANCE,NONCE,HEIGHT FROM ";
//        sql.append(std::string(chain_id.begin(), chain_id.end()));
//        sql.append(" WHERE PUBKEY=");
//        sql.append(std::string(pubKey.bytes.begin(), pubKey.bytes.end()));
//
//        int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
//        if (ok == SQLITE_OK) {
//            for (;sqlite3_step(stmt) == SQLITE_ROW;) {
//                balance = sqlite3_column_int64(stmt, 0);
//                nonce = sqlite3_column_int64(stmt, 1);
//                height = sqlite3_column_int64(stmt, 2);
//            }
//        }
//
//        sqlite3_finalize(stmt);
//
//        return account(balance, nonce, height);
//    }

    std::set<dht::public_key> repository_impl::get_all_peers(const aux::bytes &chain_id) {
        std::set<dht::public_key> peers;

        sqlite3_stmt * stmt;
        std::string sql = "SELECT PUBKEY FROM ";
        sql.append(std::string(chain_id.begin(), chain_id.end()));

        int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
        if (ok == SQLITE_OK) {
            for (;sqlite3_step(stmt) == SQLITE_ROW;) {
                const unsigned char *pK = sqlite3_column_text(stmt,0);
                auto length = sqlite3_column_bytes(stmt, 0);
                std::string value(pK, pK + length);
                auto public_key = dht::public_key(value.data());
                peers.insert(public_key);
            }
        }

        sqlite3_finalize(stmt);

        return peers;
    }

    bool repository_impl::delete_peer(const aux::bytes &chain_id, const dht::public_key &pubKey) {
        std::string sql = "DELETE FROM ";
        sql.append(std::string(chain_id.begin(), chain_id.end()));
        sql.append(" WHERE PUBKEY=");
        sql.append(std::string(pubKey.bytes.begin(), pubKey.bytes.end()));

        char *zErrMsg = nullptr;
        int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
        if (ok != SQLITE_OK) {
            sqlite3_free(zErrMsg);
            return false;
        }

        return true;
    }

    bool repository_impl::update_user_state_db(const block &b) {
        update_user_state_db(b.chain_id(), b.miner());

        auto tx = b.tx();
        if (!tx.empty()) {
            update_user_state_db(b.chain_id(), tx.sender());
            update_user_state_db(b.chain_id(), tx.receiver());
        }

        return true;
    }

    bool repository_impl::update_user_state_db(const aux::bytes &chain_id, const dht::public_key &pubKey) {
        sqlite3_stmt * stmt;
        std::string sql = "INSERT INTO ";
        sql.append(std::string(chain_id.begin(), chain_id.end()));
        sql.append(" VALUES(?)");
        int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
        if (ok != SQLITE_OK) {
            return false;
        }
        std::string value(pubKey.bytes.begin(), pubKey.bytes.end());
        sqlite3_bind_text(stmt, 1, value.c_str(), value.size(), nullptr);
//        sqlite3_bind_int64(stmt, 2, balance);
//        sqlite3_bind_int64(stmt, 3, nonce);
//        sqlite3_bind_int64(stmt, 4, height);
        ok = sqlite3_step(stmt);
        if (ok != SQLITE_DONE) {
            return false;
        }
        sqlite3_finalize(stmt);

        return true;
    }

    bool repository_impl::is_account_exist(const aux::bytes &chain_id, const dht::public_key &pubKey) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());
        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);

        return status.ok();
    }

    // check block number
    account repository_impl::get_account(const aux::bytes &chain_id, const dht::public_key &pubKey) {
        sha256_hash block_hash = get_account_block_hash(chain_id, pubKey);

        if (!block_hash.is_all_zeros()) {
            block b = get_block_by_hash(block_hash);
            if (!b.empty()) {
                return find_state_from_block(pubKey, b);
            }
        }

        return account(0, 0, 0);
    }

//    account repository_impl::get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) {
//        auto s = get_account(chain_id, pubKey);
//
//        if (s.empty()) {
//            return get_account_from_user_db(chain_id, pubKey);
//        }
//
//        return s;
//    }

    sha256_hash repository_impl::get_account_block_hash(const aux::bytes &chain_id, const dht::public_key &pubKey) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());

        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);

        return sha256_hash(value.data());
    }

    bool repository_impl::save_account_block_hash(const aux::bytes &chain_id, const dht::public_key &pubKey, const sha256_hash &hash) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, hash.to_string());

        return status.ok();
    }

    bool repository_impl::delete_account_block_hash(const aux::bytes &chain_id, const dht::public_key &pubKey) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());

        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
        return status.ok();
    }

    bool repository_impl::is_block_exist(const sha256_hash &hash) {
        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), hash.to_string(), &value);

        return status.ok();
    }

    block repository_impl::get_block_by_hash(const sha256_hash &hash) {
        std::string value;
        m_leveldb->Get(leveldb::ReadOptions(), hash.to_string(), &value);

        if (value.empty()) {
            return block(value);
        }

        return block();
    }

    account repository_impl::find_state_from_block(const dht::public_key &pubKey, const block &b) {
        if (pubKey == b.miner()) {
            return account(b.miner_balance(), b.miner_nonce(), b.block_number());
        } else if (pubKey == b.tx().sender()) {
            return account(b.sender_balance(), b.sender_nonce(), b.block_number());
        } else if (pubKey == b.tx().receiver()) {
            return account(b.receiver_balance(), b.receiver_nonce(), b.block_number());
        }

        return account(0, 0, 0);
    }

    state_linker repository_impl::get_state_linker(const sha256_hash &block_hash) {
        std::string key;
        key.insert(key.end(), block_hash.begin(), block_hash.end());
        key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());

        std::string value;
        m_leveldb->Get(leveldb::ReadOptions(), key, &value);

        if (value.empty()) {
            return state_linker(value);
        }

        return state_linker();
    }

    bool repository_impl::save_state_linker(const state_linker &stateLinker) {
        std::string key;
        auto& block_hash = stateLinker.block_hash();
        key.insert(key.end(), block_hash.begin(), block_hash.end());
        key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, stateLinker.get_encode());
        return status.ok();
    }

    bool repository_impl::delete_state_linker(const sha256_hash &block_hash) {
        std::string key;
        key.insert(key.end(), block_hash.begin(), block_hash.end());
        key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());

        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
        return status.ok();
    }

    bool repository_impl::save_block(const block &b) {
        if (b.empty())
            return false;

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(),
                                                b.sha256().to_string(), b.get_encode());
        return status.ok();
    }

//    bool repository_impl::save_block(block b, bool main_chain) {
//        return true;
//    }

    bool repository_impl::save_non_main_chain_block(const block &b) {
        // save block
        if (!save_block(b))
            return false;

        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
        indexKeyInfo.add_non_main_chain_block_hash(b.sha256());
        if (!save_index_info(b.chain_id(), b.block_number(), indexKeyInfo))
            return false;

        return true;
    }

    bool repository_impl::delete_index_info(const aux::bytes &chain_id, std::int64_t block_number) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_separator.begin(), key_separator.end());
        std::string str_num = std::to_string(block_number);
        key.insert(key.end(), str_num.begin(), str_num.end());

        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
        return status.ok();
    }

    index_key_info repository_impl::get_index_info(const aux::bytes &chain_id, std::int64_t block_number) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_separator.begin(), key_separator.end());
        std::string str_num = std::to_string(block_number);
        key.insert(key.end(), str_num.begin(), str_num.end());

        std::string value;
        m_leveldb->Get(leveldb::ReadOptions(), key, &value);

        if (value.empty()) {
            return index_key_info(value);
        }

        return index_key_info();
    }

    bool repository_impl::save_index_info(const aux::bytes &chain_id, std::int64_t block_number, const index_key_info &indexKeyInfo) {
        if (indexKeyInfo.empty())
            return false;

        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_separator.begin(), key_separator.end());
        std::string str_num = std::to_string(block_number);
        key.insert(key.end(), str_num.begin(), str_num.end());

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, indexKeyInfo.get_encode());
        return status.ok();
    }

    bool repository_impl::forward_update_last_change_block_hash(const aux::bytes &chain_id, const dht::public_key &pubKey,
                                                                state_linker &stateLinker, const sha256_hash &current_block_hash) {
        sha256_hash block_hash = get_account_block_hash(chain_id, pubKey);
        if (!block_hash.is_all_zeros()) {
            auto linker = get_state_linker(block_hash);
            if (linker.empty()) {
                return false;
            }

            stateLinker.update_previous_change_block_hash(pubKey, block_hash);
            stateLinker.update_last_change_block_hash(pubKey, linker.get_peer_last_change_block_hash(pubKey));
        } else {
            // save in db first time
            stateLinker.update_last_change_block_hash(pubKey, current_block_hash);
        }

        return true;
    }

    bool repository_impl::backward_update_last_change_block_hash(const aux::bytes &chain_id, const dht::public_key &pubKey,
                                                                 state_linker& stateLinker, const sha256_hash &current_block_hash) {
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

    bool repository_impl::connect_tip_block(const block &b) {
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

    bool repository_impl::connect_tail_block(const block &b) {
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

    // validate peer
    bool repository_impl::rollback_block(const block &b) {
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

    bool repository_impl::delete_block(const sha256_hash &hash) {
        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), hash.to_string());
        return status.ok();
    }

    bool repository_impl::delete_outdated_data_by_height(const aux::bytes &chain_id, std::int64_t block_number) {
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

    sha256_hash repository_impl::get_best_tip_block_hash(const aux::bytes &chain_id) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tip_block_hash.begin(), key_suffix_best_tip_block_hash.end());

        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);

        return sha256_hash(value.data());
    }

    bool repository_impl::set_best_tip_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tip_block_hash.begin(), key_suffix_best_tip_block_hash.end());

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, hash.to_string());
        return status.ok();
    }

    bool repository_impl::delete_best_tip_block_hash(const aux::bytes &chain_id) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tip_block_hash.begin(), key_suffix_best_tip_block_hash.end());

        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
        return status.ok();
    }

    sha256_hash repository_impl::get_best_tail_block_hash(const aux::bytes &chain_id) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tail_block_hash.begin(), key_suffix_best_tail_block_hash.end());

        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);

        return sha256_hash(value.data());
    }

    bool repository_impl::set_best_tail_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tail_block_hash.begin(), key_suffix_best_tail_block_hash.end());

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, hash.to_string());
        return status.ok();
    }

    bool repository_impl::delete_best_tail_block_hash(const aux::bytes &chain_id) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tail_block_hash.begin(), key_suffix_best_tail_block_hash.end());

        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
        return status.ok();
    }

    repository *repository_impl::start_tracking() {
        return new repository_track(this);
    }

    void repository_impl::update_batch(const std::map<std::string, std::string> &cache, const std::vector<block> &main_chain_blocks) {
        for (auto const& item: cache) {
            if (item.second.empty()) {
                m_write_batch.Delete(item.first);
            } else {
                m_write_batch.Put(item.first, item.second);
            }
        }

        m_main_chain_blocks.insert(m_main_chain_blocks.end(), main_chain_blocks.begin(), main_chain_blocks.end());
    }

    bool repository_impl::flush() {
        for (auto const& b: m_main_chain_blocks) {
            update_user_state_db(b);
        }
        leveldb::Status status = m_leveldb->Write(leveldb::WriteOptions(), &m_write_batch);
        if (!status.ok()) {
            return false;
        }

        m_write_batch.Clear();
        m_main_chain_blocks.clear();

        return true;
    }

    // unsupported
    bool repository_impl::commit() {
        return false;
    }

    // unsupported
    void repository_impl::rollback() {

    }
}
