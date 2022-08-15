/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MESSAGE_DB_IMPL_HPP
#define LIBTAU_MESSAGE_DB_IMPL_HPP


#include <sqlite3.h>
#include <leveldb/db.h>

#include "libTAU/communication/message_db_interface.hpp"

namespace libTAU {
    namespace communication {

        struct message_db_impl final : message_db_interface {

            message_db_impl(sqlite3 *mSqlite, leveldb::DB *mLeveldb) : m_sqlite(mSqlite), m_leveldb(mLeveldb) {}

            // init db
            bool init() override;

            bool create_table_friends() override;

            // get all friends
            std::vector<dht::public_key> get_all_friends() override;

            // save a friend in db
            bool save_friend(const dht::public_key &pubKey) override;

            // delete a friend
            bool delete_friend(const dht::public_key &pubKey) override;

            bool create_table_messages() override;

            // get message by hash
            communication::message get_message(const sha256_hash &hash) override;

            // save message
            bool save_message(const communication::message& msg) override;

            // delete message
            bool delete_message(const sha256_hash &hash) override;

            // get encode of the latest message hash list by key pair<my public key, peer public key>
            std::string get_latest_message_hash_list_encode(const std::pair<dht::public_key, dht::public_key> &key) override;

            // save encode of the latest message hash list with key pair<my public key, peer public key>
            bool save_latest_message_hash_list_encode(const std::pair<dht::public_key, dht::public_key> &key, const std::string& encode) override;

            // delete encode of the latest message hash list by key pair<my public key, peer public key>
            bool delete_latest_message_hash_list_encode(const std::pair<dht::public_key, dht::public_key> &key) override;

        private:

            // sqlite3 instance
            sqlite3 *m_sqlite;

            // level db instance
            leveldb::DB* m_leveldb;
        };
    }
}


#endif //LIBTAU_MESSAGE_DB_IMPL_HPP
