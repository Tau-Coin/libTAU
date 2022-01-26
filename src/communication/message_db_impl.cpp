//
// Copyright (c) 2021, TaiXiang Cui
// All rights reserved.
//
// You may use, distribute and modify this code under the terms of the BSD license,
// see LICENSE file.
//

#include "libTAU/aux_/common.h"
#include "libTAU/aux_/vector_ref.h"
#include "libTAU/kademlia/types.hpp"
#include "libTAU/communication/message_db_impl.hpp"

namespace libTAU {
    namespace communication {

        namespace {
            // friend info key suffix
            const std::string key_suffix_friend_info = "fi";
            // message hash list key suffix
            const std::string key_suffix_message_hash_list = "mhl";
            // align time key suffix
            const std::string key_suffix_array_align_time = "at";
        }

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

        std::vector<dht::public_key> message_db_impl::get_all_friends() {
            std::vector<dht::public_key> friends;

            sqlite3_stmt * stmt;
            std::string sql = "SELECT * FROM FRIENDS";
            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok == SQLITE_OK) {
                for (;sqlite3_step(stmt) == SQLITE_ROW;) {
                    const unsigned char *pK = sqlite3_column_text(stmt,0);
                    auto length = sqlite3_column_bytes(stmt, 0);
                    std::string value(pK, pK + length);
                    dht::public_key pubKey(value.data());
                    friends.push_back(pubKey);
                }
            }

            sqlite3_finalize(stmt);

            return friends;
        }

        bool message_db_impl::save_friend(const libTAU::dht::public_key &pubKey) {
            sqlite3_stmt * stmt;
            std::string sql = "INSERT INTO FRIENDS VALUES(?)";
            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok != SQLITE_OK) {
                return false;
            }
            std::string value(pubKey.bytes.begin(), pubKey.bytes.end());
            sqlite3_bind_text(stmt, 1, value.c_str(), value.size(), nullptr);
            ok = sqlite3_step(stmt);
            if (ok != SQLITE_DONE) {
                return false;
            }
            sqlite3_finalize(stmt);

            return true;
        }

        bool message_db_impl::delete_friend(const dht::public_key &pubKey) {
            sqlite3_stmt * stmt;
            std::string sql = "DELETE FROM FRIENDS WHERE PUBKEY=?";
            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok != SQLITE_OK) {
                return false;
            }
            sqlite3_bind_text(stmt, 1, std::string(pubKey.bytes.begin(), pubKey.bytes.end()).c_str(), pubKey.len, nullptr);
            ok = sqlite3_step(stmt);
            if (ok != SQLITE_DONE) {
                return false;
            }
            sqlite3_finalize(stmt);

            return true;
        }

        aux::bytes message_db_impl::get_friend_info(const std::pair<dht::public_key, dht::public_key> &key) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.bytes.begin(), key.first.bytes.end());
            sKey.insert(sKey.end(), key.second.bytes.begin(), key.second.bytes.end());
            sKey.insert(sKey.end(), key_suffix_friend_info.begin(), key_suffix_friend_info.end());

            std::string value;
            leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), sKey, &value);

            aux::bytes buffer;
            buffer.insert(buffer.end(), value.begin(), value.end());
            return buffer;
        }

        bool message_db_impl::save_friend_info(const std::pair<dht::public_key, dht::public_key> &key, const aux::bytes& friend_info) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.bytes.begin(), key.first.bytes.end());
            sKey.insert(sKey.end(), key.second.bytes.begin(), key.second.bytes.end());
            sKey.insert(sKey.end(), key_suffix_friend_info.begin(), key_suffix_friend_info.end());

            std::string value(friend_info.begin(), friend_info.end());

            leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), sKey, value);
            return status.ok();
        }

        bool message_db_impl::delete_friend_info(const std::pair<dht::public_key, dht::public_key> &key) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.bytes.begin(), key.first.bytes.end());
            sKey.insert(sKey.end(), key.second.bytes.begin(), key.second.bytes.end());
            sKey.insert(sKey.end(), key_suffix_friend_info.begin(), key_suffix_friend_info.end());

            leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), sKey);
            return status.ok();
        }

        int64_t message_db_impl::get_array_align_time(const std::pair<dht::public_key, dht::public_key> &key) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.bytes.begin(), key.first.bytes.end());
            sKey.insert(sKey.end(), key.second.bytes.begin(), key.second.bytes.end());
            sKey.insert(sKey.end(), key_suffix_array_align_time.begin(), key_suffix_array_align_time.end());

            std::string value;
            leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), sKey, &value);

            if (!value.empty()) {
                return std::stoll(value);
            }

            return 0;
        }

        bool message_db_impl::save_array_align_time(const std::pair<dht::public_key, dht::public_key> &key,
                                                    std::int64_t timestamp) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.bytes.begin(), key.first.bytes.end());
            sKey.insert(sKey.end(), key.second.bytes.begin(), key.second.bytes.end());
            sKey.insert(sKey.end(), key_suffix_array_align_time.begin(), key_suffix_array_align_time.end());

            leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), sKey, std::to_string(timestamp));
            return status.ok();
        }

        bool message_db_impl::delete_array_align_time(const std::pair<dht::public_key, dht::public_key> &key) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.bytes.begin(), key.first.bytes.end());
            sKey.insert(sKey.end(), key.second.bytes.begin(), key.second.bytes.end());
            sKey.insert(sKey.end(), key_suffix_array_align_time.begin(), key_suffix_array_align_time.end());

            leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), sKey);
            return status.ok();
        }

        communication::message message_db_impl::get_message(const sha256_hash &hash) {
            std::string value;
            leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), hash.to_string(), &value);
//            aux::bytes buffer;
//            buffer.insert(buffer.end(), value.begin(), value.end());
            return communication::message(value);
        }

        bool message_db_impl::save_message(const communication::message& msg) {
            if (msg.empty())
                return false;

            std::string key = msg.sha256().to_string();
            // 注意：rlp返回的aux::bytes转换成std::string()的时候，切勿多次调用rlp()，
            // 即不要写成std::string(msg.rlp().begin(), msg.rlp().end())，
            // 这样begin()和end()两个迭代器不在同一个对象上面，会造成内存错误
//            auto encode = msg.rlp();
//            std::string value(encode.begin(), encode.end());

            leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), key, msg.encode());
            return status.ok();
        }

        bool message_db_impl::delete_message(const sha256_hash &hash) {
            leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), hash.to_string());
            return status.ok();
        }

        std::string message_db_impl::get_latest_message_hash_list_encode(
                const std::pair<dht::public_key, dht::public_key> &key) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.bytes.begin(), key.first.bytes.end());
            sKey.insert(sKey.end(), key.second.bytes.begin(), key.second.bytes.end());
            sKey.insert(sKey.end(), key_suffix_message_hash_list.begin(), key_suffix_message_hash_list.end());

            std::string value;
            leveldb::Status status = m_leveldb->Get(leveldb::ReadOptions(), sKey, &value);
//            aux::bytes buffer;
//            buffer.insert(buffer.end(), value.begin(), value.end());
            return value;
        }

        bool message_db_impl::save_latest_message_hash_list_encode(
                const std::pair<dht::public_key, dht::public_key> &key, const std::string& encode) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.bytes.begin(), key.first.bytes.end());
            sKey.insert(sKey.end(), key.second.bytes.begin(), key.second.bytes.end());
            sKey.insert(sKey.end(), key_suffix_message_hash_list.begin(), key_suffix_message_hash_list.end());

//            std::string value(encode.begin(), encode.end());

            leveldb::Status status = m_leveldb->Put(leveldb::WriteOptions(), sKey, encode);
            return status.ok();
        }

        bool message_db_impl::delete_latest_message_hash_list_encode(
                const std::pair<dht::public_key, dht::public_key> &key) {
            std::string sKey;
            sKey.insert(sKey.end(), key.first.bytes.begin(), key.first.bytes.end());
            sKey.insert(sKey.end(), key.second.bytes.begin(), key.second.bytes.end());
            sKey.insert(sKey.end(), key_suffix_message_hash_list.begin(), key_suffix_message_hash_list.end());

            leveldb::Status status = m_leveldb->Delete(leveldb::WriteOptions(), sKey);
            return status.ok();
        }
    }
}
