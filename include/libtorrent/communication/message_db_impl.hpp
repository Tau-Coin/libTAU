//
// Created by vincent on 2021/6/19.
//

#ifndef LIBTAU_MESSAGE_DB_IMPL_HPP
#define LIBTAU_MESSAGE_DB_IMPL_HPP


#include "libtorrent/communication/message_db_interface.hpp"

namespace libtorrent {
    namespace communication {

        struct message_db_impl final : message_db_interface {
            // get all friends
            std::vector<aux::bytes> get_all_friends() override;

            // save a friend in db
            void save_friend(aux::bytes public_key) override;

            // delete a friend
            void delete_friend(aux::bytes public_key) override;

            // get message by hash
            communication::message get_message(aux::bytes hash) override;

            // save message
            void save_message(communication::message msg) override;

            // delete message
            void delete_message(aux::bytes hash) override;

            // get encode of the latest message hash list
            aux::bytes get_latest_message_hash_list_encode(aux::bytes public_key) override;

            // save encode of the latest message hash list
            void save_latest_message_hash_list_encode(aux::bytes public_key, aux::bytes encode) override;

            // delete encode of the latest message hash list
            void delete_latest_message_hash_list_encode(aux::bytes public_key) override;
        };
    }
}


#endif //LIBTAU_MESSAGE_DB_IMPL_HPP
