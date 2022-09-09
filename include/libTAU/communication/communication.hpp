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
#include <queue>
#include <unordered_set>

#include "libTAU/time.hpp"
#include "libTAU/aux_/deadline_timer.hpp"
#include "libTAU/aux_/alert_manager.hpp" // for alert_manager
#include "libTAU/aux_/session_interface.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/common/entry_type.hpp"
#include "libTAU/communication/message_wrapper.hpp"
#include "libTAU/communication/message_db_impl.hpp"
#include "libTAU/communication/message_db_interface.hpp"
#include "libTAU/kademlia/node_entry.hpp"

namespace libTAU {

    namespace dht {
        struct dht_tracker;
        class item;
    }

    namespace communication {

        using system_clock = std::chrono::system_clock;

        // new message key suffix
        const std::string key_suffix_new_message_hash = "new_message_hash";
        // confirmation roots key suffix
//        const std::string key_suffix_confirmation_roots = "confirmation_roots";

        enum COMMUNICATION_GET_ITEM_TYPE {
            NEW_MESSAGE_HASH,
            MESSAGE_WRAPPER,
            CONFIRMATION_ROOTS,
            USER_INFO,
        };

        // communication last put time(5min)
        constexpr std::int64_t communication_min_put_interval = 5 * 60 * 1000;

        // default refresh time of main task(300)(s)
        constexpr int communication_default_refresh_time = 300;

        // max message list size(used in Levenshtein Distance)
        constexpr int communication_max_message_list_size = 10;

        // max entry cache time(ms)
//        constexpr int communication_max_entry_cache_time = 2 * 60 * 60 * 1000;

        // min response interval to the same request(2s)
//        constexpr int communication_same_response_interval = 2 * 1000;

//#if !defined TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS
        // This is the basic logging and debug interface offered by the communication.
        // a release build with logging disabled (which is the default) will
        // not have this class at all
        struct TORRENT_EXTRA_EXPORT communication_logger
        {
//#ifndef TORRENT_DISABLE_LOGGING
            virtual bool should_log(aux::LOG_LEVEL log_level) const = 0;
            virtual void log(aux::LOG_LEVEL log_level, char const* fmt, ...) const TORRENT_FORMAT(3,4) = 0;
//#endif
        protected:
            ~communication_logger() {}
        };
//#endif // TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS


        class TORRENT_EXPORT communication final:
                public std::enable_shared_from_this<communication>, communication_logger {
        public:

            communication(aux::bytes device_id, aux::session_interface &mSes, io_context &mIoc, counters &mCounters) :
                    m_device_id(std::move(device_id)), m_ioc(mIoc), m_ses(mSes), m_counters(mCounters)/*, m_refresh_timer(mIoc)*/ {
                m_message_db = std::make_shared<message_db_impl>(m_ses.sqldb());
            }

            // start communication
            bool start();

            // stop
            bool stop();

            // set main loop time interval (ms)
//            void set_loop_time_interval(int milliseconds);

            // key length < 20 bytes, value length < 1k
            void publish_data(const aux::bytes& key, const aux::bytes& value);

            // key length < 20 bytes
            void subscribe_from_peer(const dht::public_key &peer, const aux::bytes& key);

            // data length < 1k
//            void send_to_peer(const dht::public_key &peer, const aux::bytes& data);

            // pay attention to peer
            void pay_attention_to_peer(const dht::public_key &peer);

            // add new friend in memory & db
            bool add_new_friend(const dht::public_key &pubkey);

            // delete friend and all related data in memory & db
            bool delete_friend(const dht::public_key &pubkey);

//            // request friend info: device id/nickname/timestamp
//            void request_friend_info(const dht::public_key &peer);
//
//            // get friend info by public key
//            aux::bytes get_friend_info(const dht::public_key &pubkey);
//
//            // save friend info
//            bool update_friend_info(const dht::public_key &pubkey, const aux::bytes& friend_info);

            // add a new message
            bool add_new_message(const message& msg, bool post_alert = false);

            // reset when account changed
            void account_changed();

            // get current time
            std::int64_t get_current_time();

            // mutable data is pushed here
            void on_dht_relay(dht::public_key const& peer, entry const& payload);

        private:
            // initialize member variables
            bool init();

            // clear all cache
            void clear();

            // add a new message
//            bool add_new_message(const dht::public_key &peer, const message& msg, bool post_alert = false);

            void publish(const std::string& salt, const entry& data);

            void publish_message_wrapper(dht::public_key const& peer, const sha1_hash &hash, const std::string& salt, const entry& data);

            // key length < 20 bytes
            void subscribe(const dht::public_key &peer, const std::string& salt, COMMUNICATION_GET_ITEM_TYPE type, std::int64_t timestamp = 0, int times = 1);

            // send data to peer
            void send_to(const dht::public_key &peer, entry const& data);

            // send new message signal
            void send_new_message_signal(const dht::public_key &peer, const sha1_hash &hash);

            // send message missing signal
            void send_message_missing_signal(const dht::public_key &peer);

            // send message put done signal
            void send_put_done_signal(const dht::public_key &peer);

            // send message put done signal
            void send_confirmation_signal(const dht::public_key &peer, const sha1_hash &hash);

            void get_new_message_hash(const dht::public_key &peer, std::int64_t timestamp);

            void put_new_message_hash(const dht::public_key &peer, const sha1_hash &hash);

            void get_message_wrapper(const dht::public_key& peer, const sha1_hash &hash, int times = 1);

            void put_message_wrapper(const message_wrapper &messageWrapper);

//            void get_message(const dht::public_key &peer, const sha1_hash &hash);

            // put message
            void put_new_message(const message& msg);

            void get_confirmation_roots(const dht::public_key &peer, const sha1_hash &hash, int times = 1);

            void put_confirmation_roots(const dht::public_key &peer);

            void put_all_messages(const dht::public_key &peer);

            // save the latest message hash list in database
            // @param peer is Y public key
//            void save_friend_latest_message_hash_list(const dht::public_key &peer);

            // try to update the latest message list
            // @param peer is Y public key
            // @return true if message list changed, false otherwise
//            bool try_to_update_Latest_message_list(const dht::public_key &peer, const message& msg, bool post_alert);

            // 使用LevenshteinDistance算法寻找最佳匹配，并提取相应解需要的中间信息(missing message和confirmation root)
            void find_best_solution(const std::vector<message>& messages, const aux::bytes& hash_prefix_array,
                                    std::vector<message> &missing_messages, std::vector<sha1_hash> &confirmation_roots);

            // 使用LevenshteinDistance算法寻找最佳匹配，并提取相应解需要的中间信息(missing message和confirmation root)
            void find_best_solution(const std::vector<message>& messages, const aux::bytes& hash_prefix_array,
                                    std::vector<message> &missing_messages, std::vector<message> &confirmed_messages);

            // make a salt on mutable channel
//            static std::string make_salt(dht::public_key peer, std::int64_t data_type_id);

//            void process_payload(dht::public_key const& peer, std::int64_t data_type_id, entry const& payload, bool is_cache);

            // validate message, check if message is oversize( >1000 bytes)
            bool validate_message(const message& msg);

//            // immutable data callback
//            void get_immutable_callback(const dht::public_key &peer, sha256_hash target
//                    , dht::item const& i);

            // mutable data callback
            void get_mutable_callback(dht::item const& i, bool, COMMUNICATION_GET_ITEM_TYPE type, std::int64_t timestamp = 0, int times = 1);

            // get immutable item from dht
//            void dht_get_immutable_item(const dht::public_key &peer, sha256_hash const& target, std::vector<dht::node_entry> const& eps);

            // get mutable item from dht
//            void dht_get_mutable_item(std::array<char, 32> key
//                    , std::string salt, dht::timestamp t);

            // put immutable item to dht
//            void dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target);

            // put mutable item to dht
//            void dht_put_mutable_item(entry const& data, std::int8_t alpha, std::int8_t beta,
//                                      std::int8_t invoke_limit, std::string salt);

            std::shared_ptr<communication> self()
            { return shared_from_this(); }

//#ifndef TORRENT_DISABLE_LOGGING
            bool should_log(aux::LOG_LEVEL log_level) const override;
            void log(aux::LOG_LEVEL log_level, char const* fmt, ...) const noexcept override TORRENT_FORMAT(3,4);
//#endif

//            void refresh_timeout(error_code const& e);

//            void send_all_unconfirmed_messages(dht::public_key const& peer);

            void on_dht_put_mutable_item(dht::item const& i, int n);

            void on_dht_put_message_wrapper(dht::public_key const& peer, const sha1_hash &hash, dht::item const& i, int n);

            void on_dht_relay_mutable_item(entry const& payload, std::vector<std::pair<dht::node_entry, bool>> const& nodes, dht::public_key const& peer);

            // device id
            aux::bytes m_device_id;

            // io context
            io_context& m_ioc;

            // session interface
            aux::session_interface& m_ses;

            counters& m_counters;

            // deadline timer
//            aux::deadline_timer m_refresh_timer;

            // message db
            std::shared_ptr<message_db_interface> m_message_db;

//            bool m_stop = false;

            // all friends
            std::vector<dht::public_key> m_friends;

            std::map<dht::public_key, std::int64_t> m_all_messages_last_put_time;

            // message wrapper
//            std::map<dht::public_key, message_wrapper> m_message_wrapper;

            // message list(map:key->Y public key, value->message list)
//            std::map<dht::public_key, std::list<message>> m_message_list_map;
        };
    }
}


#endif //LIBTAU_COMMUNICATION_HPP
