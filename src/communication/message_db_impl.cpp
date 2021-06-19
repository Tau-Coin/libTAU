//
// Created by vincent on 2021/6/19.
//

#include "libtorrent/communication/message_db_impl.hpp"

namespace libtorrent {
    namespace communication {
        std::vector<aux::bytes> message_db_impl::get_all_friends() {
            return std::vector<aux::bytes>();
        }

        void message_db_impl::save_friend(aux::bytes public_key) {

        }

        void message_db_impl::delete_friend(aux::bytes public_key) {

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
