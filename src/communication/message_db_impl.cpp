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

//        namespace {
//            // friend info key suffix
//            const std::string key_suffix_friend_info = "fi";
//            // message hash list key suffix
//            const std::string key_suffix_message_hash_list = "mhl";
//        }

        // table friends: public key
        bool message_db_impl::init() {
            if (!create_table_friends()) {
                return false;
            }

            if (!create_table_messages()) {
                return false;
            }

            return true;
        }

        bool message_db_impl::create_table_friends() {
            std::string sql = "CREATE TABLE IF NOT EXISTS FRIENDS(PUBKEY BLOB PRIMARY KEY NOT NULL);";
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
                    const char *p = static_cast<const char *>(sqlite3_column_blob(stmt, 0));
                    dht::public_key pubKey(p);
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
            sqlite3_bind_blob(stmt, 1, pubKey.bytes.data(), dht::public_key::len, nullptr);
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
            sqlite3_bind_blob(stmt, 1, pubKey.bytes.data(), dht::public_key::len, nullptr);
            ok = sqlite3_step(stmt);
            if (ok != SQLITE_DONE) {
                return false;
            }
            sqlite3_finalize(stmt);

            return true;
        }

        bool message_db_impl::create_table_messages() {
            std::string sql = "CREATE TABLE IF NOT EXISTS MESSAGES(HASH BLOB PRIMARY KEY NOT NULL,SENDER BLOB,RECEIVER BLOB,TIMESTAMP INTEGER,PAYLOAD BLOB);";
            char *zErrMsg = nullptr;
            int ok = sqlite3_exec(m_sqlite, sql.c_str(), nullptr, nullptr, &zErrMsg);
            if (ok != SQLITE_OK) {
                sqlite3_free(zErrMsg);
                return false;
            }

            return true;
        }

        bool message_db_impl::save_message_if_not_exist(const message &msg) {
            sqlite3_stmt * stmt;
            std::string sql = "INSERT INTO MESSAGES (HASH,SENDER,RECEIVER,TIMESTAMP,PAYLOAD) SELECT ?,?,?,?,? WHERE NOT EXISTS(SELECT * FROM MESSAGES WHERE HASH=?)";
            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok != SQLITE_OK) {
                return false;
            }

            sqlite3_bind_blob(stmt, 1, msg.sha1().data(), libTAU::sha1_hash::size(), nullptr);
            sqlite3_bind_blob(stmt, 2, msg.sender().bytes.data(), dht::public_key::len, nullptr);
            sqlite3_bind_blob(stmt, 3, msg.receiver().bytes.data(), dht::public_key::len, nullptr);
            sqlite3_bind_int64(stmt, 4, msg.timestamp());
            sqlite3_bind_blob(stmt, 5, msg.payload().data(), msg.payload().size(), nullptr);

            ok = sqlite3_step(stmt);
            if (ok != SQLITE_DONE) {
                return false;
            }
            sqlite3_finalize(stmt);

            return true;
        }

        message message_db_impl::get_message_by_hash(const sha1_hash &hash) {
            message msg;

            sqlite3_stmt * stmt;
            std::string sql = "SELECT SENDER,RECEIVER,TIMESTAMP,PAYLOAD FROM MESSAGES WHERE HASH=?;";

            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, hash.data(), libTAU::sha1_hash::size(), nullptr);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *p = static_cast<const char *>(sqlite3_column_blob(stmt, 0));
                    dht::public_key sender(p);

                    p = static_cast<const char *>(sqlite3_column_blob(stmt, 1));
                    dht::public_key receiver(p);

                    std::int64_t timestamp = sqlite3_column_int64(stmt, 2);

                    p = static_cast<const char *>(sqlite3_column_blob(stmt, 3));
                    auto length = sqlite3_column_bytes(stmt, 3);
                    aux::bytes payload(p, p + length);

                    msg = message(timestamp, sender, receiver, payload, hash);
                }
            }

            sqlite3_finalize(stmt);

            return msg;
        }

        communication::message
        message_db_impl::get_latest_transaction(const dht::public_key &sender, const dht::public_key &receiver) {
            communication::message msg;

            sqlite3_stmt * stmt;
            std::string sql = "SELECT HASH,TIMESTAMP,PAYLOAD FROM MESSAGES WHERE SENDER=? AND RECEIVER=? ORDER BY TIMESTAMP DESC LIMIT 1";

            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, sender.bytes.data(), dht::public_key::len, nullptr);
                sqlite3_bind_blob(stmt, 2, receiver.bytes.data(), dht::public_key::len, nullptr);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *p = static_cast<const char *>(sqlite3_column_blob(stmt, 0));
                    sha1_hash hash(p);

                    std::int64_t timestamp = sqlite3_column_int64(stmt, 1);

                    p = static_cast<const char *>(sqlite3_column_blob(stmt, 2));
                    auto length = sqlite3_column_bytes(stmt, 2);
                    aux::bytes payload(p, p + length);

                    msg = message(timestamp, sender, receiver, payload, hash);
                }
            }

            sqlite3_finalize(stmt);

            return msg;
        }

        std::vector<communication::message>
        message_db_impl::get_latest_ten_transactions(const dht::public_key &sender, const dht::public_key &receiver) {
            std::vector<communication::message> messages;

            sqlite3_stmt * stmt;
            std::string sql = "SELECT HASH,TIMESTAMP,PAYLOAD FROM MESSAGES WHERE SENDER=? AND RECEIVER=? ORDER BY TIMESTAMP DESC LIMIT 10";

            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, sender.bytes.data(), dht::public_key::len, nullptr);
                sqlite3_bind_blob(stmt, 2, receiver.bytes.data(), dht::public_key::len, nullptr);
                for (;sqlite3_step(stmt) == SQLITE_ROW;) {
                    const char *p = static_cast<const char *>(sqlite3_column_blob(stmt, 0));
                    sha1_hash hash(p);

                    std::int64_t timestamp = sqlite3_column_int64(stmt, 1);

                    p = static_cast<const char *>(sqlite3_column_blob(stmt, 2));
                    auto length = sqlite3_column_bytes(stmt, 2);
                    aux::bytes payload(p, p + length);

                    auto msg = message(timestamp, sender, receiver, payload, hash);
                    messages.push_back(msg);
                }
            }

            sqlite3_finalize(stmt);

            std::reverse(messages.begin(), messages.end());

            return messages;
        }

        bool message_db_impl::delete_message_by_hash(const sha1_hash &hash) {
            sqlite3_stmt * stmt;
            std::string sql = "DELETE FROM MESSAGES WHERE HASH=?";
            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok != SQLITE_OK) {
                return false;
            }
            sqlite3_bind_blob(stmt, 1, hash.data(), libTAU::sha1_hash::size(), nullptr);

            ok = sqlite3_step(stmt);
            if (ok != SQLITE_DONE) {
                return false;
            }
            sqlite3_finalize(stmt);

            return true;
        }

        bool message_db_impl::is_message_in_db(const sha1_hash &hash) {
            bool ret = false;

            sqlite3_stmt * stmt;
            std::string sql = "SELECT COUNT(*) FROM MESSAGES WHERE HASH=?";

            int ok = sqlite3_prepare_v2(m_sqlite, sql.c_str(), -1, &stmt, nullptr);
            if (ok == SQLITE_OK) {
                sqlite3_bind_blob(stmt, 1, hash.data(), libTAU::sha1_hash::size(), nullptr);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    int num = sqlite3_column_int(stmt, 0);
                    if (num > 0) {
                        ret = true;
                    }
                }
            }

            sqlite3_finalize(stmt);

            return ret;
        }

    }
}
