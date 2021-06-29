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
#include <memory>

#include "libtorrent/aux_/deadline_timer.hpp"
#include "libtorrent/aux_/alert_manager.hpp" // for alert_manager
#include "libtorrent/aux_/session_interface.hpp"
#include "libtorrent/kademlia/item.hpp"
#include "libtorrent/communication/message_db_impl.hpp"
#include "libtorrent/communication/message_db_interface.hpp"

namespace libtorrent {

    namespace dht {

        struct dht_tracker;
        class item;

    }

    namespace communication {

        class TORRENT_EXPORT communication final: public std::enable_shared_from_this<communication> {
        public:

            communication(io_context &mIoc, aux::session_interface &mSes) : m_ioc(mIoc), m_ses(mSes), m_refresh_timer(mIoc) {
                m_message_db = std::make_shared<message_db_impl>(m_ses.sqldb(), m_ses.kvdb());
            }

            // start communication
            void start();

            // stop
            void stop();

            // set main loop time interval (ms)
            void set_loop_time_interval(int milliseconds);

            // add new friend in memory & db
            void add_new_friend(const aux::bytes& pubkey);

            // delete friend and all related data in memory & db
            void delete_friend(const aux::bytes& pubkey);

            // set chatting friends
            void set_chatting_friend(aux::bytes chatting_friend);

            // set active friends
            void set_active_friends(std::vector<aux::bytes> &&active_friends);

            // add a new message
            void add_new_message(const message& msg);

            // reset when account changed
            void account_changed();

        private:
            // initialize member variables
            void init();

            // select a friend randomly
            aux::bytes select_friend_randomly() const;

            // save the latest message hash list in database
            void save_friend_latest_message_hash_list(const aux::bytes& peer);

            // try to update the latest message list
            // @return true if message list changed, false otherwise
            bool try_to_update_Latest_message_list(const aux::bytes& peer, message msg);

            // validate message, check if message is oversize( >1000 bytes)
            bool validateMessage(const message& msg);

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

            // io context
            io_context& m_ioc;

            // session interface
            aux::session_interface& m_ses;

            // deadline timer
            aux::deadline_timer m_refresh_timer;

            // refresh time interval
            int m_refresh_time = default_refresh_time;

            // message db
            std::shared_ptr<message_db_interface> m_message_db;

            // all friends
            std::vector<aux::bytes> m_friends;

            // chatting friend
            aux::bytes m_chatting_friend;

            // active friends
            std::vector<aux::bytes> m_active_friends;

            // message list map:key-peer, value-message list
            std::map<aux::bytes, std::list<message>> m_message_list_map;
        };
    }
}


#endif //LIBTAU_COMMUNICATION_HPP
