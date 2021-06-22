/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_COMMUNICATION_HPP
#define LIBTAU_COMMUNICATION_HPP


// OVERVIEW
//
// communication模块主要负责朋友或者区块链群组之间消息的沟通，
// 同时作为time server，通过统计网络中位数时间，为其它模块提供时间基准

#include <functional>
#include <vector>
//#include <memory>

#include "libtorrent/aux_/deadline_timer.hpp"
#include "libtorrent/aux_/alert_manager.hpp" // for alert_manager
#include "libtorrent/aux_/session_interface.hpp"
#include "libtorrent/kademlia/item.hpp"
#include "libtorrent/communication/message_db_interface.hpp"

namespace libtorrent {

    namespace dht {

        struct dht_tracker;
        class item;

    }

    namespace communication {

        class TORRENT_EXPORT communication final: std::enable_shared_from_this<communication> {
        public:

            // start communication
            void start();

            // stop
            void stop();

            // set main loop time interval
            void set_loop_time_interval(int milliseconds);

            // set chatting friends
            void set_chatting_friend(aux::bytes chatting_friend);

            // set active friends
            void set_active_friends(std::vector<aux::bytes> &&active_friends);

        private:
            // initialize member variables
            void init();

            aux::bytes select_friend_randomly() const;

            // immutable data callback
            void get_immutable_callback(sha1_hash target
                    , dht::item const& i);

            // mutable data callback
            void get_mutable_callback(dht::item const& i, bool);

            void dht_get_immutable_item(sha1_hash const& target);

            void dht_get_mutable_item(std::array<char, 32> key
                    , std::string salt = std::string());

            void dht_put_immutable_item(entry const& data, sha1_hash target);

            void dht_put_mutable_item(std::array<char, 32> key
                    , std::function<void(entry&, std::array<char,64>&
                    , std::int64_t&, std::string const&)> cb
                    , std::string salt = std::string());

            std::shared_ptr<communication> self()
            { return shared_from_this(); }

            void refresh_timeout(error_code const& e);

            static constexpr int default_refresh_time = 50;

            // session interface
            aux::session_interface& m_ses;

            // deadline timer
            aux::deadline_timer m_refresh_timer;

            // refresh time interval
            int m_refresh_time = default_refresh_time;

            // message db
//            message_db_interface m_message_db;

            // all friends
            std::vector<aux::bytes> m_friends;

            // chatting friend
            aux::bytes m_chatting_friend;

            // active friends
            std::vector<aux::bytes> m_active_friends;
        };
    }
}


#endif //LIBTAU_COMMUNICATION_HPP
