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


    bool repository_impl::create_user_state_db(aux::bytes chain_id) {
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

    bool repository_impl::delete_user_state_db(aux::bytes chain_id) {
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

    std::set<dht::public_key> repository_impl::get_all_peers(aux::bytes chain_id) {
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

    bool repository_impl::delete_peer(aux::bytes chain_id, dht::public_key pubKey) {
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

    bool repository_impl::update_user_state_db(block b) {
        update_user_state_db(b.chain_id(), b.miner());

        auto tx = b.tx();
        if (!tx.empty()) {
            update_user_state_db(b.chain_id(), tx.sender());
            update_user_state_db(b.chain_id(), tx.receiver());
        }

        return true;
    }

    bool repository_impl::update_user_state_db(aux::bytes chain_id, dht::public_key pubKey) {
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

    bool repository_impl::is_account_exist(aux::bytes chain_id, dht::public_key pubKey) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());
        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);

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
            return account(b.miner_balance(), b.miner_nonce(), b.block_number());
        } else if (pubKey == b.tx().sender()) {
            return account(b.sender_balance(), b.sender_nonce(), b.block_number());
        } else if (pubKey == b.tx().receiver()) {
            return account(b.receiver_balance(), b.receiver_nonce(), b.block_number());
        }

        return account(0, 0, 0);
    }

    state_linker repository_impl::get_state_linker(sha256_hash block_hash) {
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

    bool repository_impl::save_state_linker(state_linker stateLinker) {
        std::string key;
        auto& block_hash = stateLinker.block_hash();
        key.insert(key.end(), block_hash.begin(), block_hash.end());
        key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());

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

            update_user_state_db(b);
        }

        return true;
    }

    bool repository_impl::rollback_block(block b) {
        if (b.empty())
            return false;

        auto& chain_id = b.chain_id();
        auto stateLinker = get_state_linker(b.sha256());
        for (auto const& item: stateLinker.get_last_change_block_hash_map()) {
            save_account_block_hash(chain_id, item.first, item.second);
        }

        return true;
    }

    bool repository_impl::delete_block(sha256_hash hash) {
        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), hash.to_string());
        return status.ok();
    }

    sha256_hash repository_impl::get_best_tip_block_hash(aux::bytes chain_id) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tip_block_hash.begin(), key_suffix_best_tip_block_hash.end());

        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);

        return sha256_hash(value.data());
    }

    bool repository_impl::set_best_tip_block_hash(aux::bytes chain_id, sha256_hash hash) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tip_block_hash.begin(), key_suffix_best_tip_block_hash.end());

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, hash.to_string());
        return status.ok();
    }

    bool repository_impl::delete_best_tip_block_hash(aux::bytes chain_id) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tip_block_hash.begin(), key_suffix_best_tip_block_hash.end());

        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
        return status.ok();
    }

    sha256_hash repository_impl::get_best_tail_block_hash(aux::bytes chain_id) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tail_block_hash.begin(), key_suffix_best_tail_block_hash.end());

        std::string value;
        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);

        return sha256_hash(value.data());
    }

    bool repository_impl::set_best_tail_block_hash(aux::bytes chain_id, sha256_hash hash) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tail_block_hash.begin(), key_suffix_best_tail_block_hash.end());

        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, hash.to_string());
        return status.ok();
    }

    bool repository_impl::delete_best_tail_block_hash(aux::bytes chain_id) {
        std::string key;
        key.insert(key.end(), chain_id.begin(), chain_id.end());
        key.insert(key.end(), key_suffix_best_tail_block_hash.begin(), key_suffix_best_tail_block_hash.end());

        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
        return status.ok();
    }

    repository *repository_impl::start_tracking() {
        return new repository_track(this);
    }

    void repository_impl::update_batch(std::map<std::string, std::string> cache, std::vector<block> main_chain_blocks) {
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
