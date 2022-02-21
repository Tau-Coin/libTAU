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

            // get all friends
            virtual std::vector<dht::public_key> get_all_friends() = 0;

            // save a friend in db
            virtual bool save_friend(const dht::public_key &pubKey) = 0;

            // delete a friend
            virtual bool delete_friend(const dht::public_key &pubKey) = 0;

            // get friend info by key pair<my public key, peer public key>
            virtual aux::bytes get_friend_info(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // save friend info
            virtual bool save_friend_info(const std::pair<dht::public_key, dht::public_key> &key, const aux::bytes& friend_info) = 0;

            // delete friend info by key pair<my public key, peer public key>
            virtual bool delete_friend_info(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // get array align time by key pair<my public key, peer public key>
            virtual std::int64_t get_array_align_time(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // save array align time
            virtual bool save_array_align_time(const std::pair<dht::public_key, dht::public_key> &key, std::int64_t timestamp) = 0;

            // delete array align time by key pair<my public key, peer public key>
            virtual bool delete_array_align_time(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // get last detection by key pair<my public key, peer public key>
            virtual std::int64_t get_last_detection_time(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // save last detection time
            virtual bool save_last_detection_time(const std::pair<dht::public_key, dht::public_key> &key, std::int64_t timestamp) = 0;

            // delete last detection time by key pair<my public key, peer public key>
            virtual bool delete_last_detection_time(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // get last communication time by key pair<my public key, peer public key>
            virtual std::int64_t get_last_communication_time(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // save last communication time
            virtual bool save_last_communication_time(const std::pair<dht::public_key, dht::public_key> &key, std::int64_t timestamp) = 0;

            // delete last communication time by key pair<my public key, peer public key>
            virtual bool delete_last_communication_time(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // get levenshtein array time by key pair<my public key, peer public key>
            virtual std::int64_t get_levenshtein_array_time(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // save levenshtein array time
            virtual bool save_levenshtein_array_time(const std::pair<dht::public_key, dht::public_key> &key, std::int64_t timestamp) = 0;

            // delete levenshtein array time by key pair<my public key, peer public key>
            virtual bool delete_levenshtein_array_time(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // get levenshtein array by key pair<my public key, peer public key>
            virtual aux::bytes get_levenshtein_array(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // save levenshtein array
            virtual bool save_levenshtein_array(const std::pair<dht::public_key, dht::public_key> &key, aux::bytes levenshtein_array) = 0;

            // delete levenshtein array by key pair<my public key, peer public key>
            virtual bool delete_levenshtein_array(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // get message by hash
            virtual communication::message get_message(const sha256_hash &hash) = 0;

            // save message
            virtual bool save_message(const communication::message& msg) = 0;

            // delete message
            virtual bool delete_message(const sha256_hash &hash) = 0;

            // get encode of the latest message hash list by key pair<my public key, peer public key>
            virtual std::string get_latest_message_hash_list_encode(
                    const std::pair<dht::public_key, dht::public_key> &key) = 0;

            // save encode of the latest message hash list with key pair<my public key, peer public key>
            virtual bool save_latest_message_hash_list_encode(const std::pair<dht::public_key, dht::public_key> &key, const std::string& encode) = 0;

            // delete encode of the latest message hash list by key pair<my public key, peer public key>
            virtual bool delete_latest_message_hash_list_encode(const std::pair<dht::public_key, dht::public_key> &key) = 0;

            virtual ~message_db_interface() = default;
        };
    }
}


#endif //LIBTAU_MESSAGE_DB_INTERFACE_HPP
