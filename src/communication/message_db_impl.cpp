//
// Copyright (c) 2021, TaiXiang Cui
// All rights reserved.
//
// You may use, distribute and modify this code under the terms of the BSD license,
// see LICENSE file.
//

#include <libTAU/aux_/common.h>
#include "libTAU/aux_/vector_ref.h"
#include "libTAU/communication/message_db_impl.hpp"

namespace libTAU {
    namespace communication {

        // table friends: public key
        bool message_db_impl::init() {
            std::string sql = "CREATE TABLE IF NOT EXISTS FRIENDS(PUBKEY VARCHAR(32) PRIMARY KEY NOT NULL);";
            char *zErrMsg = nullptr;
            int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
            if (ok != SQLITE_OK) {
                sqlite3_free(zErrMsg);
                return false;
            }

            return true;
        }

        std::vector<aux::bytes> message_db_impl::get_all_friends() {
            std::vector<aux::bytes> friends;

            sqlite3_stmt * stmt;
            std::string sql = "SELECT * FROM FRIENDS";
            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok == SQLITE_OK) {
                for (;sqlite3_step(stmt) == SQLITE_ROW;) {
                    const unsigned char *pK = sqlite3_column_text(stmt,0);
                    auto length = sqlite3_column_bytes(stmt, 0);
                    std::string value(pK, pK + length);
                    aux::bytes public_key = aux::asBytes(value);
                    friends.push_back(public_key);
                }
            }

            sqlite3_finalize(stmt);

            return friends;
        }

        bool message_db_impl::save_friend(aux::bytes public_key) {
            sqlite3_stmt * stmt;
            std::string sql = "INSERT INTO FRIENDS VALUES(?)";
            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok != SQLITE_OK) {
                return false;
            }
            std::string value = aux::asString(public_key);
            sqlite3_bind_text(stmt, 1, value.c_str(), value.size(), nullptr);
            ok = sqlite3_step(stmt);
            if (ok != SQLITE_DONE) {
                return false;
            }
            sqlite3_finalize(stmt);

            return true;
        }

        bool message_db_impl::delete_friend(aux::bytes public_key) {
            sqlite3_stmt * stmt;
            std::string sql = "DELETE FROM FRIENDS WHERE PUBKEY=?";
            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok != SQLITE_OK) {
                return false;
            }
            sqlite3_bind_text(stmt, 1, std::string(public_key.begin(), public_key.end()).c_str(), public_key.size(), nullptr);
            ok = sqlite3_step(stmt);
            if (ok != SQLITE_DONE) {
                return false;
            }
            sqlite3_finalize(stmt);

            return true;
        }

        aux::bytes message_db_impl::get_friend_info(std::pair<aux::bytes, aux::bytes> key) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.begin(), key.first.end());
            sKey.insert(sKey.end(), key.second.begin(), key.second.end());

            std::string value;
            leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), sKey, &value);

            aux::bytes buffer;
            buffer.insert(buffer.end(), value.begin(), value.end());
            return buffer;
        }

        bool message_db_impl::save_friend_info(std::pair<aux::bytes, aux::bytes> key, aux::bytes friend_info) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.begin(), key.first.end());
            sKey.insert(sKey.end(), key.second.begin(), key.second.end());

            std::string value(friend_info.begin(), friend_info.end());

            leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), sKey, value);
            return status.ok();
        }

        bool message_db_impl::delete_friend_info(std::pair<aux::bytes, aux::bytes> key) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.begin(), key.first.end());
            sKey.insert(sKey.end(), key.second.begin(), key.second.end());

            leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), sKey);
            return status.ok();
        }

        communication::message message_db_impl::get_message(aux::bytes hash) {
            std::string key(hash.begin(), hash.end());

            std::string value;
            leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), key, &value);
            aux::bytes buffer;
            buffer.insert(buffer.end(), value.begin(), value.end());
            return communication::message(&buffer);
        }

        bool message_db_impl::save_message(communication::message msg) {
            leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(),
                                                    msg.sha256().to_string(),
                                                    std::string (msg.rlp().begin(), msg.rlp().end()));
            return status.ok();
        }

        bool message_db_impl::delete_message(aux::bytes hash) {
            std::string key(hash.begin(), hash.end());
            leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), key);
            return status.ok();
        }

        aux::bytes message_db_impl::get_latest_message_hash_list_encode(std::pair<aux::bytes, aux::bytes> key) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.begin(), key.first.end());
            sKey.insert(sKey.end(), key.second.begin(), key.second.end());

            std::string value;
            leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), sKey, &value);
            aux::bytes buffer;
            buffer.insert(buffer.end(), value.begin(), value.end());
            return buffer;
        }

        bool message_db_impl::save_latest_message_hash_list_encode(std::pair<aux::bytes, aux::bytes> key, aux::bytes encode) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.begin(), key.first.end());
            sKey.insert(sKey.end(), key.second.begin(), key.second.end());

            std::string value(encode.begin(), encode.end());

            leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), sKey, value);
            return status.ok();
        }

        bool message_db_impl::delete_latest_message_hash_list_encode(std::pair<aux::bytes, aux::bytes> key) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.begin(), key.first.end());
            sKey.insert(sKey.end(), key.second.begin(), key.second.end());

            leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), sKey);
            return status.ok();
        }
    }
}
