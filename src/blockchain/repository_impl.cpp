/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/hasher.hpp"
#include "libTAU/blockchain/state_linker.hpp"
#include "libTAU/blockchain/repository_impl.hpp"

namespace libTAU::blockchain {

    namespace {
        std::string chain_id_to_short_hash(const aux::bytes &chain_id) {
            // prevent SQL injection
            sha1_hash hash = hasher(chain_id).final();
            // 't' + hex(sha1(chain id))
            return "t" + aux::toHex(hash);
        }
    }

    bool repository_impl::init() {
        return true;
    }

    std::shared_ptr<repository> repository_impl::start_tracking() {
        return std::shared_ptr<repository>();
    }

    bool repository_impl::flush(const aux::bytes &chain_id) {
        return false;
    }

    bool repository_impl::commit(const aux::bytes &chain_id) {
        return false;
    }

    void repository_impl::rollback(const aux::bytes &chain_id) {

    }

    std::set<aux::bytes> repository_impl::get_all_chains() {
        return std::set<aux::bytes>();
    }

    bool repository_impl::add_new_chain(const aux::bytes &chain_id) {
        return false;
    }

    bool repository_impl::delete_chain(const aux::bytes &chain_id) {
        return false;
    }

//    bool repository_impl::set_head_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) {
//        return false;
//    }
//
//    bool repository_impl::delete_head_block_hash(const aux::bytes &chain_id) {
//        return false;
//    }

    bool repository_impl::create_state_array_db(const aux::bytes &chain_id) {
        return false;
    }

    bool repository_impl::delete_state_array_db(const aux::bytes &chain_id) {
        return false;
    }

    state_array repository_impl::get_state_array_by_hash(const aux::bytes &chain_id, const sha1_hash &hash) {
        return state_array(libTAU::entry());
    }

    std::vector<state_array> repository_impl::get_all_state_arrays(const aux::bytes &chain_id) {
        return std::vector<state_array>();
    }

    bool repository_impl::is_state_array_in_db(const aux::bytes &chain_id, const sha1_hash &hash) {
        return false;
    }

    bool repository_impl::save_state_array(const aux::bytes &chain_id, const state_array &stateArray) {
        return false;
    }

    bool repository_impl::delete_state_array_by_hash(const aux::bytes &chain_id, const sha1_hash &hash) {
        return false;
    }

    bool repository_impl::create_state_db(const aux::bytes &chain_id) {
        return false;
    }

    bool repository_impl::delete_state_db(const aux::bytes &chain_id) {
        return false;
    }

    bool repository_impl::clear_state_db(const aux::bytes &chain_id) {
        return false;
    }

    account repository_impl::get_account(const aux::bytes &chain_id, const dht::public_key &pubKey) {
        return account();
    }

    bool repository_impl::save_account(const aux::bytes &chain_id, const account &act) {
        return false;
    }

    bool repository_impl::delete_account(const aux::bytes &chain_id, const dht::public_key &pubKey) {
        return false;
    }

    std::vector<account> repository_impl::get_all_effective_state(const aux::bytes &chain_id) {
        return std::vector<account>();
    }

    dht::public_key repository_impl::get_peer_from_state_db_randomly(const aux::bytes &chain_id) {
        return dht::public_key();
    }

    bool repository_impl::create_block_db(const aux::bytes &chain_id) {
        return false;
    }

    bool repository_impl::delete_block_db(const aux::bytes &chain_id) {
        return false;
    }

    block repository_impl::get_head_block(const aux::bytes &chain_id) {
        return block();
    }

    block repository_impl::get_block_by_hash(const aux::bytes &chain_id, const sha1_hash &hash) {
        return block();
    }

    block repository_impl::get_block_by_number(const aux::bytes &chain_id, int64_t block_number) {
        return block();
    }

    bool repository_impl::save_block(const block &blk, bool is_main_chain) {
        return false;
    }

    bool repository_impl::delete_block_by_hash(const aux::bytes &chain_id, const sha1_hash &hash) {
        return false;
    }

    block repository_impl::get_main_chain_block_by_number(const aux::bytes &chain_id, std::int64_t block_number) {
        return block();
    }

    bool repository_impl::delete_blocks_by_number(const aux::bytes &chain_id, std::int64_t block_number) {
        return false;
    }

    bool repository_impl::create_peer_db(const aux::bytes &chain_id) {
        return false;
    }

    bool repository_impl::delete_peer_db(const aux::bytes &chain_id) {
        return false;
    }

    dht::public_key repository_impl::get_peer_from_peer_db_randomly(const aux::bytes &chain_id) {
        return dht::public_key();
    }

    bool repository_impl::delete_peer_in_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) {
        return false;
    }

    bool repository_impl::add_peer_in_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) {
        return false;
    }

//    bool repository_impl::create_peer_db(const aux::bytes &chain_id) {
//        std::string sql = "CREATE TABLE IF NOT EXISTS ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append("(PUBKEY VARCHAR(32) PRIMARY KEY NOT NULL);");
//
//        char *zErrMsg = nullptr;
//        int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
//        if (ok != SQLITE_OK) {
//            sqlite3_free(zErrMsg);
//            return false;
//        }
//
//        return true;
//    }
//
//    bool repository_impl::delete_peer_db(const aux::bytes &chain_id) {
//        std::string sql = "DROP TABLE ";
//        sql.append(chain_id_to_short_hash(chain_id));
//
//        char *zErrMsg = nullptr;
//        int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
//        if (ok != SQLITE_OK) {
//            sqlite3_free(zErrMsg);
//            return false;
//        }
//
//        return true;
//    }

//    account repository_impl::get_account_from_user_db(aux::bytes chain_id, dht::public_key pubKey) {
//        std::int64_t balance;
//        std::int64_t nonce;
//        std::int64_t height;
//
//        sqlite3_stmt * stmt;
//        std::string sql = "SELECT BALANCE,NONCE,HEIGHT FROM ";
//        sql.append(chain_id_to_short_hash(chain_id));
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

//    std::set<dht::public_key> repository_impl::get_all_peers(const aux::bytes &chain_id) {
//        std::set<dht::public_key> peers;
//
//        sqlite3_stmt * stmt;
//        std::string sql = "SELECT PUBKEY FROM ";
//        sql.append(chain_id_to_short_hash(chain_id));
//
//        int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
//        if (ok == SQLITE_OK) {
//            for (;sqlite3_step(stmt) == SQLITE_ROW;) {
//                const unsigned char *pK = sqlite3_column_text(stmt,0);
//                auto length = sqlite3_column_bytes(stmt, 0);
//                std::string value(pK, pK + length);
//                auto public_key = dht::public_key(value.data());
//                peers.insert(public_key);
//            }
//        }
//
//        sqlite3_finalize(stmt);
//
//        return peers;
//    }
//
//    dht::public_key repository_impl::get_peer_randomly(const aux::bytes &chain_id) {
//        dht::public_key peer{};
//
//        sqlite3_stmt * stmt;
//        std::string sql = "SELECT PUBKEY FROM ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append(" ORDER BY RANDOM() limit 1");
//
//        int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
//        if (ok == SQLITE_OK) {
//            for (;sqlite3_step(stmt) == SQLITE_ROW;) {
//                const unsigned char *pK = sqlite3_column_text(stmt,0);
//                auto length = sqlite3_column_bytes(stmt, 0);
//                std::string value(pK, pK + length);
//                peer = dht::public_key(value.data());
//                break;
//            }
//        }
//
//        sqlite3_finalize(stmt);
//
//        return peer;
//    }

//    bool repository_impl::delete_peer_in_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        std::string sql = "DELETE FROM ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append(" WHERE PUBKEY=");
//        sql.append(std::string(pubKey.bytes.begin(), pubKey.bytes.end()));
//
//        char *zErrMsg = nullptr;
//        int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
//        if (ok != SQLITE_OK) {
//            sqlite3_free(zErrMsg);
//            return false;
//        }
//
//        return true;
//    }

//    bool repository_impl::update_user_state_db(const block &b) {
//        update_user_state_db(b.chain_id(), b.miner());
//
//        auto tx = b.tx();
//        if (!tx.empty()) {
//            update_user_state_db(b.chain_id(), tx.sender());
//            update_user_state_db(b.chain_id(), tx.receiver());
//        }
//
//        return true;
//    }

//    bool repository_impl::add_peer_in_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        sqlite3_stmt * stmt;
//        std::string sql = "INSERT INTO ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append(" VALUES(?)");
//        int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
//        if (ok != SQLITE_OK) {
//            return false;
//        }
//        std::string value(pubKey.bytes.begin(), pubKey.bytes.end());
//        sqlite3_bind_text(stmt, 1, value.c_str(), value.size(), nullptr);
////        sqlite3_bind_int64(stmt, 2, balance);
////        sqlite3_bind_int64(stmt, 3, nonce);
////        sqlite3_bind_int64(stmt, 4, height);
//        ok = sqlite3_step(stmt);
//        if (ok != SQLITE_DONE) {
//            return false;
//        }
//        sqlite3_finalize(stmt);
//
//        return true;
//    }

//    bool repository_impl::create_gossip_peer_db(const aux::bytes &chain_id) {
//        std::string sql = "CREATE TABLE IF NOT EXISTS ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append("GOSSIP(PUBKEY VARCHAR(32) PRIMARY KEY NOT NULL);");
//
//        char *zErrMsg = nullptr;
//        int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
//        if (ok != SQLITE_OK) {
//            sqlite3_free(zErrMsg);
//            return false;
//        }
//
//        return true;
//    }
//
//    bool repository_impl::delete_gossip_peer_db(const aux::bytes &chain_id) {
//        std::string sql = "DROP TABLE ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append("GOSSIP");
//
//        char *zErrMsg = nullptr;
//        int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
//        if (ok != SQLITE_OK) {
//            sqlite3_free(zErrMsg);
//            return false;
//        }
//
//        return true;
//    }

//    std::set<dht::public_key> repository_impl::get_all_gossip_peers(const aux::bytes &chain_id) {
//        std::set<dht::public_key> peers;
//
//        sqlite3_stmt * stmt;
//        std::string sql = "SELECT PUBKEY FROM ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append("GOSSIP");
//
//        int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
//        if (ok == SQLITE_OK) {
//            for (;sqlite3_step(stmt) == SQLITE_ROW;) {
//                const unsigned char *pK = sqlite3_column_text(stmt,0);
//                auto length = sqlite3_column_bytes(stmt, 0);
//                std::string value(pK, pK + length);
//                auto public_key = dht::public_key(value.data());
//                peers.insert(public_key);
//            }
//        }
//
//        sqlite3_finalize(stmt);
//
//        return peers;
//    }

//    dht::public_key repository_impl::get_gossip_peer_randomly(const aux::bytes &chain_id) {
//        dht::public_key peer{};
//
//        sqlite3_stmt * stmt;
//        std::string sql = "SELECT PUBKEY FROM ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append("GOSSIP ORDER BY RANDOM() limit 1");
//
//        int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
//        if (ok == SQLITE_OK) {
//            for (;sqlite3_step(stmt) == SQLITE_ROW;) {
//                const unsigned char *pK = sqlite3_column_text(stmt,0);
//                auto length = sqlite3_column_bytes(stmt, 0);
//                std::string value(pK, pK + length);
//                peer = dht::public_key(value.data());
//                break;
//            }
//        }
//
//        sqlite3_finalize(stmt);
//
//        return peer;
//    }

//    bool repository_impl::delete_peer_in_gossip_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        std::string sql = "DELETE FROM ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append("GOSSIP");
//        sql.append(" WHERE PUBKEY=");
//        sql.append(std::string(pubKey.bytes.begin(), pubKey.bytes.end()));
//
//        char *zErrMsg = nullptr;
//        int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
//        if (ok != SQLITE_OK) {
//            sqlite3_free(zErrMsg);
//            return false;
//        }
//
//        return true;
//    }

//    bool repository_impl::delete_all_peers_in_gossip_peer_db(const aux::bytes &chain_id) {
//        std::string sql = "DELETE FROM ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append("GOSSIP");
//
//        char *zErrMsg = nullptr;
//        int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
//        if (ok != SQLITE_OK) {
//            sqlite3_free(zErrMsg);
//            return false;
//        }
//
//        return true;
//    }

//    bool repository_impl::add_peer_in_gossip_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        sqlite3_stmt * stmt;
//        std::string sql = "INSERT INTO ";
//        sql.append(chain_id_to_short_hash(chain_id));
//        sql.append("GOSSIP");
//        sql.append(" VALUES(?)");
//        int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
//        if (ok != SQLITE_OK) {
//            return false;
//        }
//        std::string value(pubKey.bytes.begin(), pubKey.bytes.end());
//        sqlite3_bind_text(stmt, 1, value.c_str(), value.size(), nullptr);
////        sqlite3_bind_int64(stmt, 2, balance);
////        sqlite3_bind_int64(stmt, 3, nonce);
////        sqlite3_bind_int64(stmt, 4, height);
//        ok = sqlite3_step(stmt);
//        if (ok != SQLITE_DONE) {
//            return false;
//        }
//        sqlite3_finalize(stmt);
//
//        return true;
//    }

//    bool repository_impl::is_account_exist(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());
//        std::string value;
//        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);
//
//        return status.ok();
//    }

//    std::int64_t repository_impl::get_effective_power(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        account_block_pointer accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
//
//        if (!accountBlockPointer.empty()) {
//            if (accountBlockPointer.latest_block_hash() == accountBlockPointer.oldest_block_hash()) {
//                return 1;
//            } else {
//                block latest_block = get_block_by_hash(accountBlockPointer.latest_block_hash());
//                block oldest_block = get_block_by_hash(accountBlockPointer.oldest_block_hash());
//                if (!latest_block.empty() && !oldest_block.empty()) {
//                    account account1 = find_state_from_block(pubKey, latest_block);
//                    account account2 = find_state_from_block(pubKey, oldest_block);
//
//                    return account1.nonce() - account2.nonce() + 1;
//                }
//            }
//        }
//
//        return 0;
//    }

    // check block number
//    account repository_impl::get_account(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        account_block_pointer accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
//
//        if (!accountBlockPointer.empty() && !accountBlockPointer.latest_block_hash().is_all_zeros()) {
//            block b = get_block_by_hash(accountBlockPointer.latest_block_hash());
//            if (!b.empty()) {
//                return find_state_from_block(pubKey, b);
//            }
//        }
//
//        return account(0, 0, 0);
//    }

//    account repository_impl::get_account_with_effective_power(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        account acct(0, 0, 0, 0);
//        account_block_pointer accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
//
//        if (!accountBlockPointer.empty() && !accountBlockPointer.latest_block_hash().is_all_zeros()) {
//            block latest_block = get_block_by_hash(accountBlockPointer.latest_block_hash());
//            if (!latest_block.empty()) {
//                acct = find_state_from_block(pubKey, latest_block);
//
//                if (accountBlockPointer.latest_block_hash() == accountBlockPointer.oldest_block_hash()) {
//                    acct.set_effective_power(1);
//                } else {
//                    block oldest_block = get_block_by_hash(accountBlockPointer.oldest_block_hash());
//                    if (!oldest_block.empty()) {
//                        account account2 = find_state_from_block(pubKey, oldest_block);
//                        acct.set_effective_power(acct.nonce() - account2.nonce() + 1);
//                    }
//                }
//            }
//        }
//
//        return acct;
//    }

//    account repository_impl::get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) {
//        auto s = get_account(chain_id, pubKey);
//
//        if (s.empty()) {
//            return get_account_from_user_db(chain_id, pubKey);
//        }
//
//        return s;
//    }

//    account_block_pointer repository_impl::get_account_block_pointer(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());
//
//        std::string value;
//        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);
//
//        if (!value.empty()) {
//            return account_block_pointer(value);
//        }
//
//        return account_block_pointer();
//    }
//
//    bool repository_impl::save_account_block_pointer(const aux::bytes &chain_id, const dht::public_key &pubKey, const account_block_pointer &accountBlockPointer) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());
//
//        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, accountBlockPointer.get_encode());
//
//        return status.ok();
//    }
//
//    bool repository_impl::delete_account_block_pointer(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), pubKey.bytes.begin(), pubKey.bytes.end());
//
//        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
//        return status.ok();
//    }

//    bool repository_impl::is_block_exist(const sha256_hash &hash) {
//        std::string value;
//        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), hash.to_string(), &value);
//
//        return status.ok();
//    }
//
//    block repository_impl::get_block_by_hash(const sha256_hash &hash) {
//        std::string value;
//        m_leveldb->Get(leveldb::ReadOptions(), hash.to_string(), &value);
//
//        if (!value.empty()) {
//            return block(value);
//        }
//
//        return block();
//    }

//    block repository_impl::get_main_chain_block_by_number(const aux::bytes &chain_id, std::int64_t block_number) {
//        auto index_info = get_index_info(chain_id, block_number);
//        if (!index_info.empty() && !index_info.main_chain_block_hash().is_all_zeros()) {
//            return get_block_by_hash(index_info.main_chain_block_hash());
//        }
//
//        return block();
//    }
//
//    sha256_hash
//    repository_impl::get_main_chain_block_hash_by_number(const aux::bytes &chain_id, std::int64_t block_number) {
//        auto index_info = get_index_info(chain_id, block_number);
//        if (!index_info.empty() && !index_info.main_chain_block_hash().is_all_zeros()) {
//            return index_info.main_chain_block_hash();
//        }
//
//        return libTAU::sha256_hash();
//    }

//    account repository_impl::find_state_from_block(const dht::public_key &pubKey, const block &b) {
//        if (pubKey == b.miner()) {
//            return account(b.miner_balance(), b.miner_nonce(), b.block_number());
//        } else if (pubKey == b.tx().sender()) {
//            return account(b.sender_balance(), b.sender_nonce(), b.block_number());
//        } else if (pubKey == b.tx().receiver()) {
//            return account(b.receiver_balance(), b.receiver_nonce(), b.block_number());
//        }
//
//        return account(0, 0, 0);
//    }

//    state_linker repository_impl::get_state_linker(const sha256_hash &block_hash) {
//        std::string key;
//        key.insert(key.end(), block_hash.begin(), block_hash.end());
//        key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());
//
//        std::string value;
//        m_leveldb->Get(leveldb::ReadOptions(), key, &value);
//
//        if (!value.empty()) {
//            return state_linker(value);
//        }
//
//        return state_linker();
//    }
//
//    bool repository_impl::save_state_linker(const state_linker &stateLinker) {
//        std::string key;
//        auto& block_hash = stateLinker.block_hash();
//        key.insert(key.end(), block_hash.begin(), block_hash.end());
//        key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());
//
//        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, stateLinker.get_encode());
//        return status.ok();
//    }
//
//    bool repository_impl::delete_state_linker(const sha256_hash &block_hash) {
//        std::string key;
//        key.insert(key.end(), block_hash.begin(), block_hash.end());
//        key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());
//
//        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
//        return status.ok();
//    }

//    bool repository_impl::save_block(const block &b) {
//        if (b.empty())
//            return false;
//
//        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(),
//                                                b.sha256().to_string(), b.get_encode());
//        return status.ok();
//    }

//    bool repository_impl::save_block(block b, bool main_chain) {
//        return true;
//    }

//    bool repository_impl::save_non_main_chain_block(block &b) {
//        // save block
//        if (!save_block(b))
//            return false;
//
//        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
//        indexKeyInfo.add_non_main_chain_block_hash(b.sha256());
//        if (!save_index_info(b.chain_id(), b.block_number(), indexKeyInfo))
//            return false;
//
//        return true;
//    }

//    bool repository_impl::delete_index_info(const aux::bytes &chain_id, std::int64_t block_number) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_separator.begin(), key_separator.end());
//        std::string str_num = std::to_string(block_number);
//        key.insert(key.end(), str_num.begin(), str_num.end());
//
//        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
//        return status.ok();
//    }
//
//    index_key_info repository_impl::get_index_info(const aux::bytes &chain_id, std::int64_t block_number) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_separator.begin(), key_separator.end());
//        std::string str_num = std::to_string(block_number);
//        key.insert(key.end(), str_num.begin(), str_num.end());
//
//        std::string value;
//        m_leveldb->Get(leveldb::ReadOptions(), key, &value);
//
//        if (!value.empty()) {
//            return index_key_info(value);
//        }
//
//        return index_key_info();
//    }
//
//    bool repository_impl::save_index_info(const aux::bytes &chain_id, std::int64_t block_number, const index_key_info &indexKeyInfo) {
//        if (indexKeyInfo.empty())
//            return false;
//
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_separator.begin(), key_separator.end());
//        std::string str_num = std::to_string(block_number);
//        key.insert(key.end(), str_num.begin(), str_num.end());
//
//        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, indexKeyInfo.get_encode());
//        return status.ok();
//    }

//    bool repository_impl::forward_update_state_linker(const aux::bytes &chain_id, const dht::public_key &pubKey,
//                                                      state_linker &stateLinker, const sha256_hash &current_block_hash) {
//        account_block_pointer accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
//        if (!accountBlockPointer.empty()) {
//            auto linker = get_state_linker(accountBlockPointer.latest_block_hash());
//            linker.update_next_change_block_hash(pubKey, current_block_hash);
//            stateLinker.update_previous_change_block_hash(pubKey, accountBlockPointer.latest_block_hash());
//            if (!save_state_linker(linker))
//                return false;
//        }
//
//        return true;
//    }
//
//    bool repository_impl::backward_update_state_linker(const aux::bytes &chain_id, const dht::public_key &pubKey,
//                                                       state_linker& stateLinker, const sha256_hash &current_block_hash) {
//        account_block_pointer accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
//        if (!accountBlockPointer.empty()) {
//            auto linker = get_state_linker(accountBlockPointer.oldest_block_hash());
//            linker.update_previous_change_block_hash(pubKey, current_block_hash);
//            stateLinker.update_next_change_block_hash(pubKey, accountBlockPointer.oldest_block_hash());
//            if (!save_state_linker(linker))
//                return false;
//        }
//
//        return true;
//    }

//    bool repository_impl::connect_head_block(const block &b) {
//        m_connected_blocks.push_back(b);
//
//        // save block
//        if (!save_block(b))
//            return false;
//
//        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
//        indexKeyInfo.set_main_chain_block_hash(b.sha256());
//
//        if (b.miner_balance() != 0 || b.miner_nonce() != 0 || b.sender_balance() != 0 || b.sender_nonce() != 0 || b.receiver_balance() != 0 || b.receiver_nonce() != 0) {
//            state_linker stateLinker(b.sha256());
//            auto &chain_id = b.chain_id();
//
//            std::set<dht::public_key> peers = b.get_block_peers();
//            if (!peers.empty()) {
//                indexKeyInfo.set_associated_peers(peers);
//                for (auto const &peer: peers) {
//                    // update state linker
//                    if (!forward_update_state_linker(chain_id, peer, stateLinker, b.sha256()))
//                        return false;
//                    // update state pointer
//                    auto accountBlockPointer = get_account_block_pointer(chain_id, peer);
//                    if (accountBlockPointer.empty()) {
//                        accountBlockPointer.set_initial_block_hash(b.sha256());
//                    } else {
//                        accountBlockPointer.set_latest_block_hash(b.sha256());
//                    }
//                    if (!save_account_block_pointer(chain_id, peer, accountBlockPointer))
//                        return false;
//                }
//            }
//
//            if (!save_state_linker(stateLinker))
//                return false;
//        }
//
//        return save_index_info(b.chain_id(), b.block_number(), indexKeyInfo);
//    }

//    bool repository_impl::connect_tail_block(const block &b) {
//        m_connected_blocks.push_back(b);
//
//        // save block
//        if (!save_block(b))
//            return false;
//
//        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
//        indexKeyInfo.set_main_chain_block_hash(b.sha256());
//
//        if (b.miner_balance() != 0 || b.miner_nonce() != 0 || b.sender_balance() != 0 || b.sender_nonce() != 0 || b.receiver_balance() != 0 || b.receiver_nonce() != 0) {
//            state_linker stateLinker(b.sha256());
//            auto &chain_id = b.chain_id();
//
//            std::set<dht::public_key> peers = b.get_block_peers();
//            if (!peers.empty()) {
//                indexKeyInfo.set_associated_peers(peers);
//
//                for (auto const &peer: peers) {
//                    // update state linker
//                    if (!backward_update_state_linker(chain_id, peer, stateLinker, b.sha256()))
//                        return false;
//                    // update state pointer
//                    auto accountBlockPointer = get_account_block_pointer(chain_id, peer);
//                    if (accountBlockPointer.empty()) {
//                        accountBlockPointer.set_initial_block_hash(b.sha256());
//                    } else {
//                        accountBlockPointer.set_oldest_block_hash(b.sha256());
//                    }
//                    if (!save_account_block_pointer(chain_id, peer, accountBlockPointer))
//                        return false;
//                }
//            }
//
//            if (!save_state_linker(stateLinker))
//                return false;
//        }
//
//        return save_index_info(b.chain_id(), b.block_number(), indexKeyInfo);
//    }

    // validate peer
//    bool repository_impl::rollback_block(const block &b) {
//        if (b.empty())
//            return false;
//
//        m_discarded_blocks.push_back(b);
//
//        if (b.miner_balance() != 0 || b.miner_nonce() != 0 || b.sender_balance() != 0 || b.sender_nonce() != 0 || b.receiver_balance() != 0 || b.receiver_nonce() != 0) {
//            auto &chain_id = b.chain_id();
//            auto stateLinker = get_state_linker(b.sha256());
//            auto &block_hash_map = stateLinker.get_previous_change_block_hash_map();
//            auto peers = b.get_block_peers();
//
//            for (auto const &peer: peers) {
//                sha256_hash previous_change_block_hash;
//                auto it = block_hash_map.find(peer);
//                if (it != block_hash_map.end()) {
//                    previous_change_block_hash = it->second;
//                }
//
//                if (previous_change_block_hash.is_all_zeros()) {
//                    if (!delete_account_block_pointer(chain_id, peer))
//                        return false;
//                } else {
//                    auto accountBlockPointer = get_account_block_pointer(chain_id, peer);
//                    // if oldest block pointer point to current block, this account was taken on chain on this block, delete it
//                    if (accountBlockPointer.oldest_block_hash() == b.sha256()) {
//                        if (!delete_account_block_pointer(chain_id, peer))
//                            return false;
//                    } else {
//                        accountBlockPointer.set_latest_block_hash(previous_change_block_hash);
//                        if (!save_account_block_pointer(chain_id, peer, accountBlockPointer))
//                            return false;
//                    }
//
//                    // no need to update state linker
//                }
//            }
//
//            if (!delete_state_linker(b.sha256()))
//                return false;
////        for (auto const& item: stateLinker.get_previous_change_block_hash_map()) {
////            auto& pubKey = item.first;
////            auto& previous_change_block_hash = item.second;
////            if (previous_change_block_hash.is_all_zeros()) {
////                if (!delete_account_block_pointer(chain_id, pubKey))
////                    return false;
////            } else {
////                auto accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
////                // if oldest block pointer point to current block, this account was taken on chain on this block, delete it
////                if (accountBlockPointer.oldest_block_hash() == b.sha1()) {
////                    if (!delete_account_block_pointer(chain_id, pubKey))
////                        return false;
////                } else {
////                    accountBlockPointer.set_latest_block_hash(previous_change_block_hash);
////                    if (!save_account_block_pointer(chain_id, pubKey, accountBlockPointer))
////                        return false;
////                }
////
////                // no need to update state linker
////            }
////
////            if (!delete_state_linker(b.sha1()))
////                return false;
////        }
//        }
//
//        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
//        indexKeyInfo.add_non_main_chain_block_hash(b.sha256());
//        indexKeyInfo.clear_main_chain_block_hash();
//        indexKeyInfo.clear_associated_peers();
//        return save_index_info(b.chain_id(), b.block_number(), indexKeyInfo);
//    }

//    bool repository_impl::expire_block(const block &b) {
//        if (b.empty())
//            return false;
//
//        m_discarded_blocks.push_back(b);
//
//        if (b.miner_balance() != 0 || b.miner_nonce() != 0 || b.sender_balance() != 0 || b.sender_nonce() != 0 || b.receiver_balance() != 0 || b.receiver_nonce() != 0) {
//            auto &chain_id = b.chain_id();
//            auto stateLinker = get_state_linker(b.sha256());
//            auto &block_hash_map = stateLinker.get_next_change_block_hash_map();
//            auto peers = b.get_block_peers();
//
//            for (auto const &peer: peers) {
//                sha256_hash next_change_block_hash;
//                auto it = block_hash_map.find(peer);
//                if (it != block_hash_map.end()) {
//                    next_change_block_hash = it->second;
//                }
//
//                if (next_change_block_hash.is_all_zeros()) {
//                    if (!delete_account_block_pointer(chain_id, peer))
//                        return false;
//                } else {
//                    auto accountBlockPointer = get_account_block_pointer(chain_id, peer);
//                    // if oldest block pointer point to current block, this account was taken on chain on this block, delete it
//                    if (accountBlockPointer.latest_block_hash() == b.sha256()) {
//                        if (!delete_account_block_pointer(chain_id, peer))
//                            return false;
//                    } else {
//                        accountBlockPointer.set_oldest_block_hash(next_change_block_hash);
//                        if (!save_account_block_pointer(chain_id, peer, accountBlockPointer))
//                            return false;
//                    }
//
//                    // no need to update state linker
//                }
//            }
//
//            if (!delete_state_linker(b.sha256()))
//                return false;
////        for (auto const& item: stateLinker.get_next_change_block_hash_map()) {
////            auto& pubKey = item.first;
////            auto& next_change_block_hash = item.second;
////            if (next_change_block_hash.is_all_zeros()) {
////                if (!delete_account_block_pointer(chain_id, pubKey))
////                    return false;
////            } else {
////                auto accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
////                // if latest block pointer point to current block, this account was on chain last once, delete it
////                if (accountBlockPointer.latest_block_hash() == b.sha1()) {
////                    if (!delete_account_block_pointer(chain_id, pubKey))
////                        return false;
////                } else {
////                    accountBlockPointer.set_oldest_block_hash(next_change_block_hash);
////                    if (!save_account_block_pointer(chain_id, pubKey, accountBlockPointer))
////                        return false;
////                }
////
////                // no need to update state linker
////            }
////
////            if (!delete_state_linker(b.sha1()))
////                return false;
////        }
//        }
//
//        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
//        indexKeyInfo.add_non_main_chain_block_hash(b.sha256());
//        indexKeyInfo.clear_main_chain_block_hash();
//        indexKeyInfo.clear_associated_peers();
//        return save_index_info(b.chain_id(), b.block_number(), indexKeyInfo);
//    }

//    bool repository_impl::delete_block(const sha256_hash &hash) {
//        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), hash.to_string());
//        return status.ok();
//    }

//    bool repository_impl::delete_expired_data_by_height(const aux::bytes &chain_id, std::int64_t block_number) {
//        index_key_info indexKeyInfo = get_index_info(chain_id, block_number);
//        auto& main_chain_block_hash = indexKeyInfo.main_chain_block_hash();
//        if (!main_chain_block_hash.is_all_zeros()) {
//            if (!delete_block(main_chain_block_hash))
//                return false;
//            if (!delete_state_linker(main_chain_block_hash))
//                return false;
//        }
//
//        auto& non_main_chain_block_hash_set = indexKeyInfo.non_main_chain_block_hash_set();
//        for (auto const& hash: non_main_chain_block_hash_set) {
//            if (!delete_block(hash))
//                return false;
//            if (!delete_state_linker(hash))
//                return false;
//        }
//
//        auto& associated_peers = indexKeyInfo.associated_peers();
//        for (auto const& peer: associated_peers) {
//            auto s = get_account(chain_id, peer);
//            if (!s.empty() && s.block_number() <= block_number) {
//                if (!delete_account_block_pointer(chain_id, peer))
//                    return false;
//            }
//        }
//
//        return delete_index_info(chain_id, block_number);
//    }

//    bool repository_impl::delete_all_outdated_data(const aux::bytes &chain_id, std::int64_t block_number) {
//        // leveldb write batch
//        leveldb::WriteBatch write_batch;
//
//        for (std::int64_t i = block_number; i >=0; i--) {
//            index_key_info indexKeyInfo = get_index_info(chain_id, i);
//            if (indexKeyInfo.empty()) {
//                break;
//            }
//
//            // 1. remove account point
//            for (auto const& peer: indexKeyInfo.associated_peers()) {
//                auto act = get_account(chain_id, peer);
//                if (act.block_number() <= block_number) {
//                    std::string key;
//                    key.insert(key.end(), chain_id.begin(), chain_id.end());
//                    key.insert(key.end(), peer.bytes.begin(), peer.bytes.end());
//                    write_batch.Delete(key);
//                }
//            }
//
//            // 2.1 remove main chain block and state linker
//            if (!indexKeyInfo.main_chain_block_hash().is_all_zeros()) {
//                write_batch.Delete(indexKeyInfo.main_chain_block_hash().to_string());
//
//                std::string key;
//                key.insert(key.end(), indexKeyInfo.main_chain_block_hash().begin(), indexKeyInfo.main_chain_block_hash().end());
//                key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());
//                write_batch.Delete(key);
//            }
//
//            // 2.2 remove non-main chain block and state linker
//            for (auto const& hash: indexKeyInfo.non_main_chain_block_hash_set()) {
//                write_batch.Delete(hash.to_string());
//
//                std::string key;
//                key.insert(key.end(), hash.begin(), hash.end());
//                key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());
//                write_batch.Delete(key);
//            }
//
//            // 3. remove index lastly
//            std::string key_index;
//            key_index.insert(key_index.end(), chain_id.begin(), chain_id.end());
//            key_index.insert(key_index.end(), key_separator.begin(), key_separator.end());
//            std::string str_num = std::to_string(i);
//            key_index.insert(key_index.end(), str_num.begin(), str_num.end());
//            write_batch.Delete(key_index);
//        }
//
//        // flush into leveldb
//        leveldb::Status status = m_leveldb->Write(leveldb::WriteOptions(), &write_batch);
//        if (!status.ok()) {
//            return false;
//        }
//
//        return true;
//    }

//    sha256_hash repository_impl::get_head_block_hash(const aux::bytes &chain_id) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_suffix_head_block_hash.begin(), key_suffix_head_block_hash.end());
//
//        std::string value;
//        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);
//
//        if (!value.empty()) {
//            return sha256_hash(value.data());
//        }
//
//        return sha256_hash();
//    }
//
//    bool repository_impl::set_head_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_suffix_head_block_hash.begin(), key_suffix_head_block_hash.end());
//
//        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, hash.to_string());
//        return status.ok();
//    }
//
//    bool repository_impl::delete_head_block_hash(const aux::bytes &chain_id) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_suffix_head_block_hash.begin(), key_suffix_head_block_hash.end());
//
//        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
//        return status.ok();
//    }
//
//    sha256_hash repository_impl::get_tail_block_hash(const aux::bytes &chain_id) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_suffix_tail_block_hash.begin(), key_suffix_tail_block_hash.end());
//
//        std::string value;
//        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);
//
//        if (!value.empty()) {
//            return sha256_hash(value.data());
//        }
//
//        return sha256_hash();
//    }
//
//    bool repository_impl::set_tail_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_suffix_tail_block_hash.begin(), key_suffix_tail_block_hash.end());
//
//        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, hash.to_string());
//        return status.ok();
//    }
//
//    bool repository_impl::delete_tail_block_hash(const aux::bytes &chain_id) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_suffix_tail_block_hash.begin(), key_suffix_tail_block_hash.end());
//
//        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
//        return status.ok();
//    }
//
//    sha256_hash repository_impl::get_consensus_point_block_hash(const aux::bytes &chain_id) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_suffix_consensus_point_block_hash.begin(), key_suffix_consensus_point_block_hash.end());
//
//        std::string value;
//        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);
//
//        if (!value.empty()) {
//            return sha256_hash(value.data());
//        }
//
//        return sha256_hash();
//    }
//
//    bool repository_impl::set_consensus_point_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_suffix_consensus_point_block_hash.begin(), key_suffix_consensus_point_block_hash.end());
//
//        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, hash.to_string());
//        return status.ok();
//    }
//
//    bool repository_impl::delete_consensus_point_block_hash(const aux::bytes &chain_id) {
//        std::string key;
//        key.insert(key.end(), chain_id.begin(), chain_id.end());
//        key.insert(key.end(), key_suffix_consensus_point_block_hash.begin(), key_suffix_consensus_point_block_hash.end());
//
//        leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
//        return status.ok();
//    }

//    std::shared_ptr<repository> repository_impl::start_tracking() {
//        return std::make_shared<repository_track>(this);
//    }
//
//    void repository_impl::update_batch(const std::map<std::string, std::string> &cache,
//                                       const std::vector<block> &connected_blocks,
//                                       const std::vector<block> &discarded_blocks) {
//        for (auto const& item: cache) {
//            if (item.second.empty()) {
//                m_write_batch.Delete(item.first);
//            } else {
//                m_write_batch.Put(item.first, item.second);
//            }
//        }
//
//        m_connected_blocks.insert(m_connected_blocks.end(), connected_blocks.begin(), connected_blocks.end());
//        m_discarded_blocks.insert(m_discarded_blocks.end(), discarded_blocks.begin(), discarded_blocks.end());
//    }
//
//    bool repository_impl::flush(const aux::bytes &chain_id) {
//        // flush into leveldb
//        leveldb::Status status = m_leveldb->Write(leveldb::WriteOptions(), &m_write_batch);
//        if (!status.ok()) {
//            return false;
//        }
//
//        m_write_batch.Clear();
//
//        // flush into sqlite
//        // get current tail block number
//        auto best_tail_block_hash = get_tail_block_hash(chain_id);
//        auto tail_block = get_block_by_hash(best_tail_block_hash);
//        std::int64_t tail_number = tail_block.block_number();
//
//        std::set<dht::public_key> validate_peers;
//        for (auto const& b: m_connected_blocks) {
//            validate_peers.merge(b.get_block_peers());
//        }
//        for (auto const &b: m_discarded_blocks) {
//            validate_peers.merge(b.get_block_peers());
//        }
//        for (auto const &peer: validate_peers) {
//            auto act = get_account(chain_id, peer);
//            if (act.empty() || act.block_number() < tail_number) {
//                // remove outdated peer
//                delete_peer_in_peer_db(chain_id, peer);
//            } else {
//                add_peer_in_peer_db(chain_id, peer);
//            }
//        }
//
//        m_connected_blocks.clear();
//        m_discarded_blocks.clear();
//
//        return true;
//    }
//
//    // unsupported
//    bool repository_impl::commit() {
//        return false;
//    }
//
//    // unsupported
//    void repository_impl::rollback() {
//
//    }

//    std::set<aux::bytes> repository_impl::get_all_chains() {
//        std::set<aux::bytes> chains;
//        std::string value;
//        leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key_chains, &value);
//        if (!value.empty()) {
//            entry e = bdecode(value);
//            auto & lst = e.list();
//            for (auto const& chain_id: lst) {
//                auto id = chain_id.string();
//                chains.insert(aux::bytes(id.begin(), id.end()));
//            }
//        }
//
//        return chains;
//    }

//    bool repository_impl::save_chains(const std::set<aux::bytes> &chains) {
//        entry::list_type chain_id_list;
//        for (auto const& chain_id: chains) {
//            chain_id_list.push_back(std::string(chain_id.begin(), chain_id.end()));
//        }
//        std::string encode;
//        bencode(std::back_inserter(encode), chain_id_list);
//
//        leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key_chains, encode);
//        return status.ok();
//    }

//    bool repository_impl::delete_all_chain_data(const aux::bytes &chain_id) {
//        // leveldb write batch
//        leveldb::WriteBatch write_batch;
//
//        auto head_block_hash = get_head_block_hash(chain_id);
//        if (!head_block_hash.is_all_zeros()) {
//            auto head_block = get_block_by_hash(head_block_hash);
//            auto block_number = head_block.block_number();
//
//            for (std::int64_t i = block_number; i >= 0; i--) {
//                index_key_info indexKeyInfo = get_index_info(chain_id, i);
//                if (indexKeyInfo.empty()) {
//                    break;
//                }
//
//                // 1. remove account point
//                for (auto const &peer: indexKeyInfo.associated_peers()) {
//                    auto act = get_account(chain_id, peer);
//                    if (act.block_number() <= block_number) {
//                        std::string key;
//                        key.insert(key.end(), chain_id.begin(), chain_id.end());
//                        key.insert(key.end(), peer.bytes.begin(), peer.bytes.end());
//                        write_batch.Delete(key);
//                    }
//                }
//
//                // 2.1 remove main chain block and state linker
//                if (!indexKeyInfo.main_chain_block_hash().is_all_zeros()) {
//                    write_batch.Delete(indexKeyInfo.main_chain_block_hash().to_string());
//
//                    std::string key;
//                    key.insert(key.end(), indexKeyInfo.main_chain_block_hash().begin(),
//                               indexKeyInfo.main_chain_block_hash().end());
//                    key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());
//                    write_batch.Delete(key);
//                }
//
//                // 2.2 remove non-main chain block and state linker
//                for (auto const &hash: indexKeyInfo.non_main_chain_block_hash_set()) {
//                    write_batch.Delete(hash.to_string());
//
//                    std::string key;
//                    key.insert(key.end(), hash.begin(), hash.end());
//                    key.insert(key.end(), key_suffix_state_linker.begin(), key_suffix_state_linker.end());
//                    write_batch.Delete(key);
//                }
//
//                // 3. remove index lastly
//                std::string key_index;
//                key_index.insert(key_index.end(), chain_id.begin(), chain_id.end());
//                key_index.insert(key_index.end(), key_separator.begin(), key_separator.end());
//                std::string str_num = std::to_string(i);
//                key_index.insert(key_index.end(), str_num.begin(), str_num.end());
//                write_batch.Delete(key_index);
//            }
//
//            auto tail_block_hash = get_tail_block_hash(chain_id);
//            auto consensus_point_block_hash = get_consensus_point_block_hash(chain_id);
//            write_batch.Delete(head_block_hash.to_string());
//            write_batch.Delete(tail_block_hash.to_string());
//            write_batch.Delete(consensus_point_block_hash.to_string());
//        }
//
//        // flush into leveldb
//        leveldb::Status status = m_leveldb->Write(leveldb::WriteOptions(), &write_batch);
//        if (!status.ok()) {
//            return false;
//        }
//
//        return true;
//    }

//    std::string repository_impl::get_all_cache() {
//        std::string info = "DB base:\n";
//        for (auto const& blk: m_connected_blocks) {
//            info.append(" connect block:").append(blk.to_string()).append("\n");
//        }
//
//        for (auto const& blk: m_discarded_blocks) {
//            info.append(" discard block:").append(blk.to_string()).append("\n");
//        }
//
//        return info;
//    }

//    bool repository_impl::add_new_chain(const aux::bytes &chain_id) {
//        std::set<aux::bytes> chains = get_all_chains();
//        chains.insert(chain_id);
//
//        return save_chains(chains);
//    }
//
//    bool repository_impl::delete_chain(const aux::bytes &chain_id) {
//        std::set<aux::bytes> chains = get_all_chains();
//        chains.erase(chain_id);
//
//        return save_chains(chains);
//    }

}
