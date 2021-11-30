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
#include <utility>
#include <vector>
#include <memory>
#include <list>
#include <unordered_set>

#include "libTAU/time.hpp"
#include "libTAU/aux_/deadline_timer.hpp"
#include "libTAU/aux_/alert_manager.hpp" // for alert_manager
#include "libTAU/aux_/session_interface.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/communication/message_db_impl.hpp"
#include "libTAU/communication/message_db_interface.hpp"
#include "libTAU/communication/online_signal.hpp"

namespace libTAU {

    namespace dht {
        struct dht_tracker;
        class item;
    }

    namespace communication {

        using system_clock = std::chrono::system_clock;

        // default refresh time of main task(50ms)(ms)
        constexpr int communication_default_refresh_time = 50;

        // max message list size(used in Levenshtein Distance)
        constexpr int communication_max_message_list_size = 10;

        // short address(public key) length
        constexpr int communication_short_address_length = 4;

        // salt length (first 16 bytes of public key)
        constexpr int communication_salt_length = 16;

        // max chatting friend time(5s)
        constexpr std::int64_t communication_max_chatting_time = 5;

        // data accepted time(6h)(ms)
        constexpr std::int64_t communication_data_accepted_time = 6 * 60 * 60 * 1000;

//#if !defined TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS
        // This is the basic logging and debug interface offered by the communication.
        // a release build with logging disabled (which is the default) will
        // not have this class at all
        struct TORRENT_EXTRA_EXPORT communication_logger
        {
//#ifndef TORRENT_DISABLE_LOGGING
            virtual bool should_log() const = 0;
            virtual void log(char const* fmt, ...) const TORRENT_FORMAT(2,3) = 0;
//#endif
        protected:
            ~communication_logger() {}
        };
//#endif // TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS


        class TORRENT_EXPORT communication final:
                public std::enable_shared_from_this<communication>, communication_logger {
        public:

            communication(aux::bytes device_id, io_context& mIoc, aux::session_interface &mSes) :
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
            bool add_new_friend(const dht::public_key &pubkey);

            // delete friend and all related data in memory & db
            bool delete_friend(const dht::public_key &pubkey);

            // get friend info by public key
            aux::bytes get_friend_info(const dht::public_key &pubkey);

            // save friend info
            bool update_friend_info(const dht::public_key &pubkey, const aux::bytes& friend_info);

            // set chatting friends
            void set_chatting_friend(dht::public_key chatting_friend);

            // unset chatting friends
            void unset_chatting_friend();

            // set active friends
            void set_active_friends(std::vector<dht::public_key> active_friends);

            // add a new message
            bool add_new_message(const message& msg, bool post_alert = false);

            // add a new message
            bool add_new_message(const dht::public_key &peer, const message& msg, bool post_alert = false);

            // reset when account changed
            void account_changed();

            // get current time
            std::int64_t get_current_time();

            // mutable data is pushed here
            void on_dht_item(dht::item const& i);

        private:
            // initialize member variables
            bool init();

            // clear all cache
            void clear();

            // request online/new message signal from a given peer
            void request_signal(const dht::public_key &peer);

            // publish online/new message signal to a given peer
            void publish_signal(const dht::public_key &peer);

            // select a friend randomly
            dht::public_key select_friend_randomly();

            // save the latest message hash list in database
            // @param peer is Y public key
            void save_friend_latest_message_hash_list(const dht::public_key &peer);

            // try to update the latest message list
            // @param peer is Y public key
            // @return true if message list changed, false otherwise
            bool try_to_update_Latest_message_list(const dht::public_key &peer, const message& msg, bool post_alert);

            // 使用LevenshteinDistance算法寻找最佳匹配，并提取相应解需要的中间信息(missing message和confirmation root)
            void find_best_solution(const std::vector<message>& messages, const aux::bytes& hash_prefix_array,
                                    std::vector<message> &missing_messages, std::vector<sha256_hash> &confirmation_roots);

            // make a salt on mutable channel
            static std::string make_salt(dht::public_key peer);

            // make online signal
            online_signal make_signal(const dht::public_key &peer);

            // process signal from dht
            void process_signal(const online_signal & signal, const dht::public_key &peer);

            // validate message, check if message is oversize( >1000 bytes)
            bool validate_message(const message& msg);

            // immutable data callback
            void get_immutable_callback(const dht::public_key &peer, sha256_hash target
                    , dht::item const& i);

            // mutable data callback
            void get_mutable_callback(dht::item const& i, bool);

            // get immutable item from dht
            void dht_get_immutable_item(const dht::public_key &peer, sha256_hash const& target, std::vector<dht::node_entry> const& eps);

            // get mutable item from dht
            void dht_get_mutable_item(std::array<char, 32> key
                    , std::string salt, dht::timestamp t);

            // put immutable item to dht
            void dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target);

            // put mutable item to dht
            void dht_put_mutable_item(std::array<char, 32> key
                    , std::function<void(entry&, std::array<char,64>&
                    , std::int64_t&, std::string const&)> cb
                    , std::string salt, const dht::public_key &peer);

            std::shared_ptr<communication> self()
            { return shared_from_this(); }

//#ifndef TORRENT_DISABLE_LOGGING
            bool should_log() const override;
            void log(char const* fmt, ...) const noexcept override TORRENT_FORMAT(2,3);
//#endif

            void refresh_timeout(error_code const& e);

            // device id
            aux::bytes m_device_id;

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

            bool m_stop = false;

            // all friends
            std::vector<dht::public_key> m_friends;

            // peer access time
            std::map<dht::public_key, std::int64_t> m_peer_access_times;

            // chatting friend(time:s)
            std::pair<dht::public_key, std::int64_t> m_chatting_friend = std::make_pair(dht::public_key(), 0);

            // active friends
            std::vector<dht::public_key> m_active_friends;

            // friend last seen time(map:key->peer, value->last seen signal time(ms))
            std::map<dht::public_key, std::int64_t> m_last_seen;

            // online/new message signal time(map:key1->peer, key2->device id, value->signal time(ms))
            std::map<dht::public_key, std::map<aux::bytes, std::int64_t>> m_latest_signal_time;

            // online/new message signal time(map:key1->peer, key2->device id, value->hash prefix array)
            std::map<dht::public_key, std::map<aux::bytes, aux::bytes>> m_latest_hash_prefix_array;

            // message list(map:key->Y public key, value->message list)
            std::map<dht::public_key, std::list<message>> m_message_list_map;

            // missing messages (map:key->peer, value->missing message list)
            std::map<dht::public_key, std::set<message>> m_missing_messages;

            // put last missing message for 1min
            std::map<dht::public_key, immutable_data_info> m_last_gasp_payload;

            std::map<dht::public_key, std::int64_t> m_last_gasp_time;

            // the latest item timestamp of peer
            std::map<dht::public_key, dht::timestamp> m_latest_item_timestamp;
        };
    }
}


#endif //LIBTAU_COMMUNICATION_HPP
