//
// Copyright (c) 2021, TaiXiang Cui
// All rights reserved.
//
// You may use, distribute and modify this code under the terms of the BSD license,
// see LICENSE file.
//

#include "libtorrent/communication/message_db_impl.hpp"

namespace libtorrent {
    namespace communication {

        // table friends: public key
        bool message_db_impl::init() {
            char *sql = "CREATE TABLE IF NOT EXISTS FRIENDS(PUBKEY VARCHAR(32) PRIMARY KEY NOT NULL);";
            char *zErrMsg = nullptr;
            int ok = sqlite3_exec(m_sqlite, sql, nullptr, nullptr, &zErrMsg);
            if (ok != SQLITE_OK) {
                sqlite3_free(zErrMsg);
                return false;
            }

            return true;
        }

        std::vector<aux::bytes> message_db_impl::get_all_friends() {
            char *sql = "";
            /* Create SQL statement */
            char *zErrMsg = nullptr;
            int rc = sqlite3_exec(m_sqlite, sql, nullptr, nullptr, &zErrMsg);
            if (rc != SQLITE_OK) {
                sqlite3_free(zErrMsg);
            }

            return std::vector<aux::bytes>();
        }

        bool message_db_impl::save_friend(aux::bytes public_key) {
            sqlite3_stmt * stmt;
            char * sql = "INSERT INTO FRIENDS VALUES(?)";
            int ok = sqlite3_prepare_v2(m_sqlite, sql, -1, &stmt, nullptr);
            if (ok != SQLITE_OK) {
                return false;
            }
            sqlite3_bind_text(stmt, 1, reinterpret_cast<const char *>(public_key.data()), public_key.size(), nullptr);
            ok = sqlite3_step(stmt);
            if (ok != SQLITE_DONE) {
                return false;
            }
            sqlite3_finalize(stmt);

            return true;
        }

        bool message_db_impl::delete_friend(aux::bytes public_key) {
            sqlite3_stmt * stmt;
            char * sql = "DELETE FROM FRIENDS WHERE PUBKEY=?";
            int ok = sqlite3_prepare_v2(m_sqlite, sql, -1, &stmt, nullptr);
            if (ok != SQLITE_OK) {
                return false;
            }
            sqlite3_bind_text(stmt, 1, reinterpret_cast<const char *>(public_key.data()), public_key.size(), nullptr);
            ok = sqlite3_step(stmt);
            if (ok != SQLITE_DONE) {
                return false;
            }
            sqlite3_finalize(stmt);

            return true;
        }

        communication::message message_db_impl::get_message(aux::bytes hash) {
            return communication::message();
        }

        void message_db_impl::save_message(communication::message msg) {

        }

        void message_db_impl::delete_message(aux::bytes hash) {

        }

        aux::bytes message_db_impl::get_latest_message_hash_list_encode(aux::bytes public_key) {
            return libtorrent::aux::bytes();
        }

        void message_db_impl::save_latest_message_hash_list_encode(aux::bytes public_key, aux::bytes encode) {

        }

        void message_db_impl::delete_latest_message_hash_list_encode(aux::bytes public_key) {

        }
    }
}
