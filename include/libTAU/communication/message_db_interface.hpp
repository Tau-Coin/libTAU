/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MESSAGE_DB_INTERFACE_HPP
#define LIBTAU_MESSAGE_DB_INTERFACE_HPP

#include <vector>

#include "libTAU/aux_/common.h"
#include "libTAU/aux_/export.hpp"
#include "libTAU/communication/message.hpp"


namespace libTAU {
    namespace communication {

        // The ``message_db_interface`` 提供message相关的存储接口，
        // 包括朋友公钥的存取删除，消息的存取删除，以及最新消息哈希列表编码的存取删除，
        // 每一个朋友都会对应一个最新消息哈希集合，该集合是该通信对最新200个消息完整哈希的时间排列的顺序列表，
        // 每当有更新的消息加入该列表，列表满载时会删除其最老的消息哈希，并根据该哈希删除相应的消息；
        // 并且，该哈希列表也用来生成对应的莱温斯坦数组，只需取哈希的第一个字节，并按对应顺序排列即可
        struct TORRENT_EXPORT message_db_interface {

            // init db
            virtual bool init() = 0;

            // create table friends
            virtual bool create_table_friends() = 0;

            // get all friends
            virtual std::vector<dht::public_key> get_all_friends() = 0;

            // save a friend in db
            virtual bool save_friend(const dht::public_key &pubKey) = 0;

            // delete a friend
            virtual bool delete_friend(const dht::public_key &pubKey) = 0;

            // create table friends
            virtual bool create_table_messages() = 0;

            // save message
            virtual bool save_message_if_not_exist(const communication::message& msg) = 0;

            // get message by hash
            virtual communication::message get_message_by_hash(const sha1_hash &hash) = 0;

            // get the latest tx
            virtual communication::message
            get_latest_transaction(const dht::public_key &sender, const dht::public_key &receiver) = 0;

            // get the latest 10 txs
            virtual std::vector<communication::message>
            get_latest_ten_transactions(const dht::public_key &sender, const dht::public_key &receiver) = 0;

            // delete message
            virtual bool delete_message_by_hash(const sha1_hash &hash) = 0;

            virtual bool is_message_in_db(const sha1_hash &hash) = 0;

            virtual ~message_db_interface() = default;
        };
    }
}


#endif //LIBTAU_MESSAGE_DB_INTERFACE_HPP
