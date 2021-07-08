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

#include <ctime>
#include <functional>
#include <utility>
#include <vector>
#include <memory>
#include <list>

#include "libTAU/aux_/deadline_timer.hpp"
#include "libTAU/aux_/alert_manager.hpp" // for alert_manager
#include "libTAU/aux_/session_interface.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/communication/message_db_impl.hpp"
#include "libTAU/communication/message_db_interface.hpp"
#include "libTAU/communication/online_signal.hpp"
#include "libTAU/communication/new_msg_signal.hpp"

namespace libTAU {

    namespace dht {
        struct dht_tracker;
        class item;
    }

    namespace communication {

        // default refresh time of main task
        constexpr int communication_default_refresh_time = 50;

        // max message list size(used in Levenshtein Distance)
        constexpr int communication_max_message_list_size = 50;

        // short address(public key) length
        constexpr int communication_short_address_length = 4;

        // salt length (first 16 bytes of public key)
        constexpr int communication_salt_length = 16;

        // max chatting time(30min)
        constexpr int communication_max_chatting_time = 30 * 60;

        // data accepted time(6h)
        constexpr int communication_data_accepted_time = 6 * 60 * 60;


        class TORRENT_EXPORT communication final: public std::enable_shared_from_this<communication> {
        public:

            communication(aux::bytes device_id, io_context &mIoc, aux::session_interface &mSes) :
            m_device_id(std::move(device_id)), m_ioc(mIoc), m_ses(mSes), m_refresh_timer(mIoc) {
                m_message_db = std::make_shared<message_db_impl>(m_ses.sqldb(), m_ses.kvdb());
            }

            // start communication
            bool start();

            // stop
            bool stop();

            // set main loop time interval (ms)
            void set_loop_time_interval(int milliseconds);

            // add new friend in memory & db
            bool add_new_friend(const aux::bytes& pubkey);

            // delete friend and all related data in memory & db
            bool delete_friend(const aux::bytes& pubkey);

            // get friend info by public key
            aux::bytes get_friend_info(aux::bytes pubkey);

            // save friend info
            bool update_friend_info(aux::bytes pubkey, aux::bytes friend_info);

            // set chatting friends
            void set_chatting_friend(aux::bytes chatting_friend);

            // unset chatting friends
            void unset_chatting_friend();

            // set active friends
            void set_active_friends(std::vector<aux::bytes> active_friends);

            // add a new message
            bool add_new_message(const message& msg);

            // reset when account changed
            void account_changed();

        private:
            // initialize member variables
            bool init();

            // request online/new message signal from a given peer
            void request_signal(const aux::bytes& peer);

            // publish online/new message signal to a given peer
            void publish_signal(const aux::bytes& peer);

            // select a friend randomly
            aux::bytes select_friend_randomly();

            // save the latest message hash list in database
            void save_friend_latest_message_hash_list(const aux::bytes& peer);

            // try to update the latest message list
            // @return true if message list changed, false otherwise
            bool try_to_update_Latest_message_list(const aux::bytes& peer, const message& msg);

            // make a salt on mutable channel
            static std::string make_salt(aux::bytes peer);

            // make a salt on sender channel
            std::string make_sender_salt(aux::bytes peer);

            // make a salt on receiver channel
            std::string make_receiver_salt(aux::bytes peer);

            // make online signal on XX channel
            online_signal make_online_signal();

            // make new message signal on XY channel
            new_msg_signal make_new_message_signal(const aux::bytes& peer);

            // validate message, check if message is oversize( >1000 bytes)
            static bool validate_message(const message& msg);

            // immutable data callback
            void get_immutable_callback(sha1_hash target
                    , dht::item const& i);

            // mutable data callback
            void get_mutable_callback(dht::item const& i, bool);

            // get immutable item from dht
            void dht_get_immutable_item(sha1_hash const& target);

            // get mutable item from dht
            void dht_get_mutable_item(std::array<char, 32> key
                    , std::string salt = std::string());

            // put immutable item to dht
            void dht_put_immutable_item(entry const& data, sha1_hash target);

            // put mutable item to dht
            void dht_put_mutable_item(std::array<char, 32> key
                    , std::function<void(entry&, std::array<char,64>&
                    , std::int64_t&, std::string const&)> cb
                    , std::string salt = std::string());

            std::shared_ptr<communication> self()
            { return shared_from_this(); }

            void refresh_timeout(error_code const& e);

            // io context
            io_context& m_ioc;

            // session interface
            aux::session_interface& m_ses;

            // deadline timer
            aux::deadline_timer m_refresh_timer;

            // refresh time interval
            int m_refresh_time = communication_default_refresh_time;

            // message db
            std::shared_ptr<message_db_interface> m_message_db;

            // device id
            aux::bytes m_device_id;

            // all friends
            std::vector<aux::bytes> m_friends;

            // chatting friend
            std::pair<aux::bytes, time_t> m_chatting_friend = std::make_pair(aux::bytes(), 0);

            // active friends
            std::vector<aux::bytes> m_active_friends;

            // friend last seen time(map:key->peer, value->last seen signal time)
            std::map<aux::bytes, time_t> m_last_seen;

            // online/new message signal time(map:key1->peer, key2->device id, value->signal time)
            std::map<aux::bytes, std::map<aux::bytes, time_t>> m_latest_signal_time;

            // message list(map:key->peer, value->message list)
            std::map<aux::bytes, std::list<message>> m_message_list_map;
        };
    }
}


#endif //LIBTAU_COMMUNICATION_HPP
