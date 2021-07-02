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

#include "libtorrent/communication/message_db_interface.hpp"

namespace libtorrent {
    namespace communication {

        struct message_db_impl final : message_db_interface {

            message_db_impl(sqlite3 *mSqlite, leveldb::DB *mLeveldb) : m_sqlite(mSqlite), m_leveldb(mLeveldb) {}

            // init db
            bool init() override;

            // get all friends
            std::vector<aux::bytes> get_all_friends() override;

            // save a friend in db
            bool save_friend(aux::bytes public_key) override;

            // delete a friend
            bool delete_friend(aux::bytes public_key) override;

            aux::bytes get_friend_info(aux::bytes public_key) override;

            bool save_friend_info(aux::bytes public_key, aux::bytes friend_info) override;

            bool delete_friend_info(aux::bytes public_key) override;

            // get message by hash
            communication::message get_message(aux::bytes hash) override;

            // save message
            bool save_message(communication::message msg) override;

            // delete message
            bool delete_message(aux::bytes hash) override;

            // get encode of the latest message hash list
            aux::bytes get_latest_message_hash_list_encode(aux::bytes public_key) override;

            // save encode of the latest message hash list
            bool save_latest_message_hash_list_encode(aux::bytes public_key, aux::bytes encode) override;

            // delete encode of the latest message hash list
            bool delete_latest_message_hash_list_encode(aux::bytes public_key) override;

        private:

            // sqlite3 instance
            sqlite3 *m_sqlite;

            // level db instance
            leveldb::DB* m_leveldb;
        };
    }
}


#endif //LIBTAU_MESSAGE_DB_IMPL_HPP
