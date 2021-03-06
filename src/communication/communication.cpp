/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <cstdlib>
#include <cinttypes> // for PRId64 et.al.
#include <utility>
#include <algorithm>

#include "libTAU/communication/message_hash_list.hpp"
#include "libTAU/communication/communication.hpp"
#include "libTAU/kademlia/dht_tracker.hpp"
#include "libTAU/aux_/common_data.h"

using namespace std::placeholders;

namespace libTAU {
    namespace communication {
        using namespace aux;

        bool communication::start()
        {
            log(LOG_INFO, "INFO: Start Communication...");
            if (!init()) {
                log(LOG_ERR, "ERROR: Init fail.");
                return false;
            }

            m_stop = false;

            m_refresh_timer.expires_after(milliseconds(100));
            m_refresh_timer.async_wait(std::bind(&communication::refresh_timeout, self(), _1));

            return true;
        }

        bool communication::stop()
        {
            m_stop = true;

            m_refresh_timer.cancel();

            clear();

            log(LOG_INFO, "INFO: Stop Communication...");

            return true;
        }

        bool communication::init() {
            try {
                log(LOG_INFO, "INFO: Communication init...");
                if (!m_message_db->init()) {
                    log(LOG_ERR, "ERROR: DB init fail!");
                    return false;
                }

                // get friends from db
                m_friends = m_message_db->get_all_friends();

                dht::public_key *pk = m_ses.pubkey();
                m_friends.push_back(*pk);

                for (auto const & peer: m_friends) {
                    log(LOG_INFO, "INFO: friend: %s", aux::toHex(peer.bytes).c_str());
                    std::string encode = m_message_db->get_latest_message_hash_list_encode(std::make_pair(*pk, peer));

                    if (!encode.empty()) {
                        message_hash_list hashList(encode);
                        log(LOG_INFO, "INFO: %s from peer[%s]", hashList.to_string().c_str(), aux::toHex(peer.bytes).c_str());
                        for (auto const &hash: hashList.hash_list()) {
                            log(LOG_INFO, "INFO: Get message hash:%s", aux::toHex(hash).c_str());
                            message msg = m_message_db->get_message(hash);
                            if (!msg.empty()) {
                                log(LOG_INFO, "INFO: Got message from db[%s]", msg.to_string().c_str());
                                m_message_list_map[peer].push_back(msg);
                            } else {
                                log(LOG_INFO, "INFO: Cannot find message[%s] in db.", aux::toHex(hash).c_str());
                            }
                        }
                    } else {
                        log(LOG_INFO, "INFO: Message hash list is empty.");
                    }

                    m_last_communication_time[peer] = m_message_db->get_last_communication_time(std::make_pair(*pk, peer));
                    m_levenshtein_array_time[peer] = m_message_db->get_levenshtein_array_time(std::make_pair(*pk, peer));
                    m_levenshtein_array[peer] = m_message_db->get_levenshtein_array(std::make_pair(*pk, peer));
                }
            } catch (std::exception &e) {
                log(LOG_ERR, "Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
                return false;
            }

            return true;
        }

        void communication::clear() {
            m_friends.clear();
            m_message_list_map.clear();
        }

        void communication::account_changed() {
            try {
                log(LOG_INFO, "INFO: Change account.");
                // ???????????????????????????????????????
//                stop();
//                start();

                clear();
                init();
            } catch (std::exception &e) {
                log(LOG_ERR, "Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            }
        }

        std::int64_t communication::get_current_time() {
            return total_milliseconds(system_clock::now().time_since_epoch());
        }

        void communication::process_payload(const dht::public_key &peer, std::int64_t data_type_id, const entry &payload, bool is_cache) {
            auto now = get_current_time();

            std::int64_t timestamp = 0;

            log(LOG_INFO, "---------------Got entry[%s] from peer[%s]", payload.to_string().c_str(), aux::toHex(peer.bytes).c_str());
            switch (data_type_id) {
                case common::message_entry::data_type_id: {
                    // time
                    if (auto* i = const_cast<entry *>(payload.find_key(common::entry_time)))
                    {
                        timestamp = i->integer();
                        if (timestamp > m_last_communication_time[peer]) {
                            update_communication_time(peer, timestamp);
                        }
                    }

                    {
                        std::string encode;
                        bencode(std::back_inserter(encode), payload);

                        auto& entry_cache = m_entry_cache[peer];
                        auto it = entry_cache.find(encode);
                        if (it != entry_cache.end()) {
                            log(LOG_INFO, "INFO: Duplicate entry[%s] from peer[%s]", payload.to_string().c_str(), aux::toHex(peer.bytes).c_str());
                            return;
                        } else {
                            entry_cache[encode] = now;
                        }
                    }

                    m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, now);

                    common::message_entry msg_entry(payload);
                    log(LOG_INFO, "INFO: Got message, hash[%s].",
                        aux::toHex(msg_entry.m_msg.sha256().to_string()).c_str());

//                    {
//                        auto it = m_last_same_entry_time[peer].find(
//                                std::make_shared<common::message_entry>(payload));
//                        if (it != m_last_same_entry_time[peer].end()) {
//                            if (now > it->second + communication_same_response_interval) {
//                                m_last_same_entry_time[peer].erase(it);
//                            } else {
//                                log(LOG_INFO, "INFO: The same request from the same peer in 4s.");
//                                break;
//                            }
//                        } else {
//                            m_last_same_entry_time[peer].emplace(std::make_shared<common::message_entry>(payload),
//                                                                 now);
//                        }
//                    }

                    add_new_message(peer, msg_entry.m_msg, true);

                    if (timestamp > m_levenshtein_array_time[peer]) {
                        update_levenshtein_array(peer, msg_entry.m_levenshtein_array, timestamp);

                        // find out missing messages and confirmation root
                        std::vector<message> missing_messages;
                        std::vector<sha256_hash> confirmation_roots;
                        auto &message_list = m_message_list_map[peer];
                        std::vector<message> messages(message_list.begin(), message_list.end());
                        log(LOG_INFO, "INFO: Messages size:%" PRIu64, messages.size());
                        find_best_solution(messages, msg_entry.m_levenshtein_array,
                                           missing_messages, confirmation_roots);

                        if (!confirmation_roots.empty()) {
                            m_ses.alerts().emplace_alert<communication_confirmation_root_alert>(peer,
                                                                                                confirmation_roots,
                                                                                                now);
                            log(LOG_INFO, "INFO: Confirmation roots:%" PRIu64, confirmation_roots.size());
                        }

                        aux::bytes levenshtein_array;
                        auto &msg_list = m_message_list_map[peer];
                        for (auto const &msg: msg_list) {
                            levenshtein_array.push_back(msg.sha256()[0]);
                        }

                        auto size = missing_messages.size();
                        for(auto k = 0; k < size; k++) {
                            common::message_entry messageEntry(missing_messages[k], levenshtein_array, get_current_time());
                            send_to(peer, messageEntry.get_entry());
                        }

                        common::message_levenshtein_array_entry msg_levenshtein_array(levenshtein_array, now);
                        send_to(peer, msg_levenshtein_array.get_entry());
                    }

//                    if (!is_cache) {
//                        send_all_unconfirmed_messages(peer);
//                    }

                    break;
                }
                case common::message_levenshtein_array_entry::data_type_id: {
                    // time
                    if (auto* i = const_cast<entry *>(payload.find_key(common::entry_time)))
                    {
                        timestamp = i->integer();
                        if (timestamp > m_last_communication_time[peer]) {
                            update_communication_time(peer, timestamp);
                        }
                    }

                    {
                        std::string encode;
                        bencode(std::back_inserter(encode), payload);

                        auto& entry_cache = m_entry_cache[peer];
                        auto it = entry_cache.find(encode);
                        if (it != entry_cache.end()) {
                            log(LOG_INFO, "INFO: Duplicate entry[%s] from peer[%s]", payload.to_string().c_str(), aux::toHex(peer.bytes).c_str());
                            return;
                        } else {
                            entry_cache[encode] = now;
                        }
                    }

                    m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, now);

                    common::message_levenshtein_array_entry levenshtein_array_entry(payload);
                    log(LOG_INFO, "INFO: Got message levenshtein array[%s].",
                        aux::toHex(levenshtein_array_entry.m_levenshtein_array).c_str());

//                    {
//                        auto it = m_last_same_entry_time[peer].find(
//                                std::make_shared<common::message_levenshtein_array_entry2>(payload));
//                        if (it != m_last_same_entry_time[peer].end()) {
//                            if (now > it->second + communication_same_response_interval) {
//                                m_last_same_entry_time[peer].erase(it);
//                            } else {
//                                log(LOG_INFO, "INFO: The same request from the same peer in 4s.");
//                                break;
//                            }
//                        } else {
//                            m_last_same_entry_time[peer].emplace(
//                                    std::make_shared<common::message_levenshtein_array_entry2>(payload), now);
//                        }
//                    }

                    if (timestamp >= m_levenshtein_array_time[peer]) {
                        update_levenshtein_array(peer, levenshtein_array_entry.m_levenshtein_array, timestamp);

                        // find out missing messages and confirmation root
                        std::vector<message> missing_messages;
                        std::vector<sha256_hash> confirmation_roots;
                        auto &message_list = m_message_list_map[peer];
                        std::vector<message> messages(message_list.begin(), message_list.end());
                        log(LOG_INFO, "INFO: Messages size:%" PRIu64, messages.size());
                        find_best_solution(messages, levenshtein_array_entry.m_levenshtein_array,
                                           missing_messages, confirmation_roots);

                        if (!confirmation_roots.empty()) {
                            m_ses.alerts().emplace_alert<communication_confirmation_root_alert>(peer,
                                                                                                confirmation_roots,
                                                                                                now);
                            log(LOG_INFO, "INFO: Confirmation roots:%" PRIu64, confirmation_roots.size());
                        }

                        log(LOG_INFO, "INFO: Found missing message size %" PRIu64, missing_messages.size());
                        aux::bytes levenshtein_array;
                        auto &msg_list = m_message_list_map[peer];
                        for (auto const &msg: msg_list) {
                            levenshtein_array.push_back(msg.sha256()[0]);
                        }

                        auto size = missing_messages.size();
                        for(auto k = 0; k < size; k++) {
                            common::message_entry msg_entry(missing_messages[k], levenshtein_array, get_current_time());
                            send_to(peer, msg_entry.get_entry());
                        }
                    }

                    break;
                }
                case common::event_entry::data_type_id: {
                    // time
                    if (auto* i = const_cast<entry *>(payload.find_key(common::entry_time)))
                    {
                        timestamp = i->integer();
                        if (timestamp > m_last_communication_time[peer]) {
                            update_communication_time(peer, timestamp);
                        }
                    }

                    {
                        std::string encode;
                        bencode(std::back_inserter(encode), payload);

                        auto& entry_cache = m_entry_cache[peer];
                        auto it = entry_cache.find(encode);
                        if (it != entry_cache.end()) {
                            log(LOG_INFO, "INFO: Duplicate entry[%s] from peer[%s]", payload.to_string().c_str(), aux::toHex(peer.bytes).c_str());
                            return;
                        } else {
                            entry_cache[encode] = now;
                        }
                    }

                    m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, now);

                    common::event_entry eventEntry(payload);

                    // ??????????????????user event
                    m_ses.alerts().emplace_alert<communication_user_event_alert>(peer, eventEntry.m_value);

                    if (!is_cache) {
                        send_all_unconfirmed_messages(peer);
                    }

                    break;
                }
//                case common::friend_info_request_entry::data_type_id: {
//                    // time
//                    if (auto* i = const_cast<entry *>(payload.find_key(common::entry_time)))
//                    {
//                        timestamp = i->integer();
//                        if (timestamp > m_last_communication_time[peer]) {
//                            update_communication_time(peer, timestamp);
//                        }
//                    }
//
//                    {
//                        std::string encode;
//                        bencode(std::back_inserter(encode), payload);
//
//                        auto& entry_cache = m_entry_cache[peer];
//                        auto it = entry_cache.find(encode);
//                        if (it != entry_cache.end()) {
//                            log(LOG_INFO, "INFO: Duplicate entry[%s] from peer[%s]", payload.to_string().c_str(), aux::toHex(peer.bytes).c_str());
//                            return;
//                        } else {
//                            entry_cache[encode] = now;
//                        }
//                    }
//
//                    m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, now);
//
////                    auto it = m_last_same_entry_time[peer].find(std::make_shared<common::friend_info_request_entry>(payload));
////                    if (it != m_last_same_entry_time[peer].end()) {
////                        if (now > it->second + communication_same_response_interval) {
////                            m_last_same_entry_time[peer].erase(it);
////                        } else {
////                            log(LOG_INFO, "INFO: The same request from the same peer in 4s.");
////                            break;
////                        }
////                    } else {
////                        m_last_same_entry_time[peer].emplace(std::make_shared<common::friend_info_request_entry>(payload), now);
////                    }
//
//                    auto pubkey = *m_ses.pubkey();
//                    auto friend_info = m_message_db->get_friend_info(std::make_pair(pubkey, pubkey));
//                    if (!friend_info.empty()) {
//                        common::friend_info_entry e(friend_info);
//                        send_to(peer, e.get_entry());
//                    }
//
//                    if (!is_cache) {
//                        send_all_unconfirmed_messages(peer);
//                    }
//
//                    break;
//                }
//                case common::friend_info_entry::data_type_id: {
//                    // time
//                    if (auto* i = const_cast<entry *>(payload.find_key(common::entry_time)))
//                    {
//                        timestamp = i->integer();
//                        if (timestamp > m_last_communication_time[peer]) {
//                            update_communication_time(peer, timestamp);
//                        }
//                    }
//
//                    {
//                        std::string encode;
//                        bencode(std::back_inserter(encode), payload);
//
//                        auto& entry_cache = m_entry_cache[peer];
//                        auto it = entry_cache.find(encode);
//                        if (it != entry_cache.end()) {
//                            log(LOG_INFO, "INFO: Duplicate entry[%s] from peer[%s]", payload.to_string().c_str(), aux::toHex(peer.bytes).c_str());
//                            return;
//                        } else {
//                            entry_cache[encode] = now;
//                        }
//                    }
//
//                    m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, now);
//
//                    common::friend_info_entry e(payload);
//                    if (!e.m_friend_info.empty()) {
//                        // ??????????????????friend info
//                        m_ses.alerts().emplace_alert<communication_friend_info_alert>(peer, e.m_friend_info);
//                    }
//
//                    if (!is_cache) {
//                        send_all_unconfirmed_messages(peer);
//                    }
//
//                    break;
//                }
                default: {
                }
            }

        }

        void communication::on_dht_relay(dht::public_key const& peer, entry const& payload) {
            if(payload.type() != entry::dictionary_t){
                log(LOG_ERR, "ERROR: relay data not dict. to string: %s", payload.to_string().c_str());
                return;
            }

            // construct mutable data wrapper from entry
            try {
                // data type id
                if (auto* i = const_cast<entry *>(payload.find_key(common::entry_type))) {
                    auto data_type_id = i->integer();
                    process_payload(peer, data_type_id, payload, false);
                }
            } catch (std::exception &e) {
                log(LOG_ERR, "ERROR: Receive exception data.");
            }
        }

//        void communication::set_loop_time_interval(int milliseconds) {
//            log("INFO: Set loop time:%d(ms)", milliseconds);
//            m_refresh_time = milliseconds;
//            m_refresh_timer.cancel();
//        }

        void communication::publish_data(const aux::bytes& key, const aux::bytes& value) {
            publish(std::string(key.begin(), key.end()), std::string(value.begin(), value.end()));
        }

        void communication::subscribe_from_peer(const dht::public_key &peer, const aux::bytes& key) {
            subscribe(peer, std::string(key.begin(), key.end()));
        }

        void communication::send_to_peer(const dht::public_key &peer, const aux::bytes& data) {
            common::event_entry eventEntry(data, get_current_time());
            send_to(peer, eventEntry.get_entry());
        }

        bool communication::add_new_friend(const dht::public_key &pubkey) {
            if (pubkey == dht::public_key()) {
                log(LOG_ERR, "ERROR: Public key is empty.");
                return false;
            }

            log(LOG_INFO, "INFO: Add new friend, public key %s.", aux::toHex(pubkey.bytes).c_str());

            auto it = find(m_friends.begin(), m_friends.end(), pubkey);
            if (it == m_friends.end()) {
                log(LOG_INFO, "INFO: Friend is not existed.");

                m_friends.push_back(pubkey);
                if (!m_message_db->save_friend(pubkey)) {
                    log(LOG_ERR, "ERROR: Save friend failed!");
                    return false;
                }
            }

            return true;
        }

        bool communication::delete_friend(const dht::public_key &pubkey) {
            log(LOG_INFO, "INFO: Delete friend, public key %s.", aux::toHex(pubkey.bytes).c_str());

            for(auto it = m_friends.begin(); it != m_friends.end(); ++it) {
                if (*it == pubkey) {
                    m_friends.erase(it);
                    break;
                }
            }

            if (!m_message_db->delete_friend(pubkey)) {
                log(LOG_ERR, "ERROR: Delete friend failed!");
                return false;
            }

            const auto &pk = m_ses.pubkey();

            if (!m_message_db->delete_friend_info(std::make_pair(*pk, pubkey))) {
                log(LOG_ERR, "ERROR: Delete friend info failed!");
                return false;
            }

            if (!m_message_db->delete_latest_message_hash_list_encode(std::make_pair(*pk, pubkey))) {
                log(LOG_ERR, "ERROR: Delete friend message hash list encode failed!");
                return false;
            }

            return true;
        }

//        void communication::request_friend_info(const dht::public_key &peer) {
//            common::friend_info_request_entry friendInfoRequestEntry(get_current_time());
//            send_to(peer, friendInfoRequestEntry.get_entry());
//        }
//
//        aux::bytes communication::get_friend_info(const dht::public_key &pubkey) {
//            const auto &pk = m_ses.pubkey();
//            return m_message_db->get_friend_info(std::make_pair(*pk, pubkey));
//        }
//
//        bool communication::update_friend_info(const dht::public_key &pubkey, const aux::bytes& friend_info) {
//            log(LOG_INFO, "INFO: Update peer[%s] friend info[%s]", aux::toHex(pubkey.bytes).c_str(), aux::toHex(friend_info).c_str());
//            const auto &pk = m_ses.pubkey();
//            return m_message_db->save_friend_info(std::make_pair(*pk, pubkey), friend_info);
//        }

        bool communication::add_new_message(const message &msg, bool post_alert) {
            add_new_message(msg.receiver(), msg, post_alert);

            aux::bytes levenshtein_array;
            auto& msg_list = m_message_list_map[msg.receiver()];
            for (auto const &m: msg_list) {
                levenshtein_array.push_back(m.sha256()[0]);
            }

            std::int64_t now = get_current_time();
            common::message_entry msg_entry(msg, levenshtein_array, now);
            send_to(msg.receiver(), msg_entry.get_entry());

            update_communication_time(msg.receiver(), now);

            return true;
        }

        bool communication::add_new_message(const dht::public_key &peer, const message& msg, bool post_alert) {
            if (msg.empty()) {
                log(LOG_ERR, "ERROR: Message is empty.");
                return false;
            }

            log(LOG_INFO, "INFO: Add new msg[%s]", msg.to_string().c_str());

            if (!validate_message(msg))
                return false;

            return try_to_update_Latest_message_list(peer, msg, post_alert);
        }

        bool communication::validate_message(const message& msg) {
            // TODO: size==1000?
            if (msg.encode().size() > 1000) {
                log(LOG_ERR, "ERROR: Message is oversize!");
                return false;
            }

            return true;
        }

        void communication::refresh_timeout(error_code const& e)
        {
            if ((e.value() != 0 && e.value() != boost::asio::error::operation_aborted) || m_stop) return;

            try {
                if (e.value() != boost::asio::error::operation_aborted) {
                    auto now = get_current_time();

                    for (auto &entry_cache: m_entry_cache) {
                        for (auto it = entry_cache.second.begin(); it != entry_cache.second.end();) {
                            // remove outdated date
                            if (now > it->second + communication_max_entry_cache_time) {
                                entry_cache.second.erase(it++);
                            } else {
                                it++;
                            }
                        }
                    }

//                    for (auto &last_same_entry_time: m_last_same_entry_time) {
//                        for (auto it = last_same_entry_time.second.begin(); it != last_same_entry_time.second.end();) {
//                            // remove outdated date
//                            if (now > it->second + communication_same_response_interval) {
//                                last_same_entry_time.second.erase(it++);
//                            } else {
//                                it++;
//                            }
//                        }
//                    }
                }

                m_refresh_timer.expires_after(seconds(communication_default_refresh_time));
                m_refresh_timer.async_wait(std::bind(&communication::refresh_timeout, self(), _1));
            } catch (std::exception &e) {
                log(LOG_ERR, "Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            }
        }

        void communication::save_friend_latest_message_hash_list(const dht::public_key &peer) {
            auto message_list = m_message_list_map.at(peer);
            if (!message_list.empty()) {
                std::vector<sha256_hash> hash_list;
                for (const auto & msg: message_list) {
                    hash_list.push_back(msg.sha256());
                }

                dht::public_key pubkey = *m_ses.pubkey();

                message_hash_list messageHashList(hash_list);
                log(LOG_INFO, "INFO: Save message hash list %s", messageHashList.to_string().c_str());
                m_message_db->save_latest_message_hash_list_encode(std::make_pair(pubkey, peer),messageHashList.encode());
            }
        }

        bool communication::try_to_update_Latest_message_list(const dht::public_key &peer, const message& msg, bool post_alert) {
            if (msg.empty())
                return false;

            bool updated = false;

            std::list<message> message_list = m_message_list_map[peer];
            if (!message_list.empty()) {
                // ??????????????????????????????????????????????????????????????????????????????????????????
                if (msg.timestamp() > message_list.back().timestamp()) {
                    message_list.push_back(msg);
                    updated = true;
                } else {
                    // ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
                    auto it = message_list.rbegin();
                    // ?????????????????????????????????????????????????????????????????????????????????
                    bool insertFirst = true;
                    for (; it != message_list.rend(); ++it) {
                        message reference = *it;
//                        signed long diff = reference.timestamp() - msg.timestamp();
                        // ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
                        if (reference.timestamp() < msg.timestamp()) {
                            updated = true;
                            insertFirst = false;
                            message_list.insert(it.base(), msg);
                            break;
                        } else if (reference.timestamp() == msg.timestamp()) {
                            // ???????????????????????????????????????????????????????????????
                            auto reference_hash = reference.sha256();
                            auto msg_hash = msg.sha256();
                            if (reference_hash != msg_hash) {
                                // ????????????????????????????????????????????????????????????????????????????????????
                                if (reference_hash < msg_hash) {
                                    updated = true;
                                    insertFirst = false;
                                    message_list.insert(it.base(), msg);
                                    break;
                                }
                            } else {
                                // ????????????????????????????????????????????????????????????????????????
                                insertFirst = false;
                                break;
                            }
                        }
                    }

                    if (insertFirst) {
                        updated = true;
                        message_list.insert(std::begin(message_list), msg);
                    }
                }
            } else {
                message_list.push_back(msg);
                updated = true;
            }

            // ????????????
            if (updated) {
                log(LOG_INFO, "INFO: Add message[%s] into message list", msg.to_string().c_str());

                // ??????????????????message
                if (post_alert) {
                    log(LOG_INFO, "DEBUG: Post new message:%s", msg.to_string().c_str());
                    m_ses.alerts().emplace_alert<communication_new_message_alert>(msg);
                }

                // save message in db
                if (!m_message_db->save_message(msg)) {
                    log(LOG_ERR, "ERROR: Save message in db fail[%s]", msg.to_string().c_str());
                    return false;
                }

                // ???????????????????????????????????????????????????????????????????????????????????????????????????????????????
                if (message_list.size() > communication_max_message_list_size) {
                    message_list.pop_front();
                }

                m_message_list_map[peer] = message_list;

                save_friend_latest_message_hash_list(peer);
            }

            return updated;
        }

        namespace {
            /**
             * ??????????????????????????????????????????????????????????????????
             * @param swap ???????????????
             * @param insert ???????????????
             * @param del ???????????????
             * @return 0:?????????1????????????2?????????
             */
            size_t optCode(size_t swap, size_t insert, size_t del) {
                // ??????????????????????????????????????????0?????????
                // ?????????????????????????????????????????????????????????
                if (swap <= insert && swap <= del) {
                    return 0;
                }

                // ???????????????????????????????????????1???????????????????????????????????????????????????????????????
                if (insert < swap && insert <= del) {
                    return 1;
                }

                // ???????????????????????????????????????2??????
                return 2;
            }
        }

        void communication::find_best_solution(const std::vector<message>& messages, const aux::bytes& hash_prefix_array,
                                               std::vector<message> &missing_messages,
                                               std::vector<sha256_hash> &confirmation_roots) {
            // ????????????????????????????????????????????????????????????
            if (hash_prefix_array.empty()) {
                log(LOG_INFO, "INFO: Hash prefix array is empty");
                missing_messages.insert(missing_messages.end(), messages.begin(), messages.end());
                return;
            }

            if (!messages.empty()) {
                auto size = messages.size();
                // ???????????????source
                const aux::bytes& source = hash_prefix_array;
                // ?????????????????????target
                aux::bytes target;
                for (auto const &message: messages) {
                    target.push_back(message.sha256()[0]);
                }

                const size_t sourceLength = source.size();
                const size_t targetLength = size;

                log(LOG_INFO, "INFO: source array[%s], target array[%s]", aux::toHex(source).c_str(), aux::toHex(target).c_str());
                // ??????source???target????????????????????????Levenshtein??????????????????
                if (source == target) {
                    for (auto const &msg: messages) {
//                        log("INFO: Confirm message hash[%s]", aux::toHex(msg.sha256().to_string()).c_str());
                        confirmation_roots.push_back(msg.sha256());
                    }
                    return;
                }

                // ??????????????????
                size_t dist[sourceLength + 1][targetLength + 1];
                // ????????????
                size_t operations[sourceLength + 1][targetLength + 1];

                // ????????????[i, 0]????????????????????????????????????????????????????????????
                for (size_t i = 0; i < sourceLength + 1; i++) {
                    dist[i][0] = i;
                    if (i > 0) {
                        operations[i][0] = 2;
                    }
                }

                // ????????????????????????[0, j]????????????????????????????????????????????????
                for (size_t j = 0; j < targetLength + 1; j++) {
                    dist[0][j] = j;
                    if (j > 0) {
                        operations[0][j] = 1;
                    }
                }

                // ????????????????????????????????????0?????????????????????1??????????????????[i, j]?????????????????????????????????
                for (size_t i = 1; i < sourceLength + 1; i++) {
                    for (size_t j = 1; j < targetLength + 1; j++) {
                        // ???i?????????????????????index??????i-1???????????????????????????????????????????????????0??????????????????1
                        size_t cost = source[i - 1] == target[j - 1] ? 0 : 1;
                        // [i, j]???[i, j-1]?????????????????????????????????????????????1
                        size_t insert = dist[i][j - 1] + 1;
                        // [i, j]???[i-1, j]?????????????????????????????????????????????1
                        size_t del = dist[i - 1][j] + 1;
                        // [i, j]???[i-1, j-1]???????????????????????????????????????1?????????
                        size_t swap = dist[i - 1][j - 1] + cost;

                        // ???[i-1, j]??? [i, j-1]??? [i-1, j-1]???????????????[i, j]?????????????????????????????????
                        dist[i][j] = std::min(std::min(insert, del), swap);

                        // ?????????????????????????????????
                        operations[i][j] = optCode(swap, insert, del);
                    }
                }

                // ???????????????????????????????????????
                auto i = sourceLength;
                auto j = targetLength;
                while (0 != dist[i][j]) {
                    if (0 == operations[i][j]) {
                        // ??????????????????????????????target?????????????????????????????????
                        if (source[i - 1] != target[j - 1]) {
                            missing_messages.push_back(messages[j - 1]);
                        } else {
//                            log("INFO: Confirm message hash[%s]", aux::toHex(messages[j - 1].sha256().to_string()).c_str());
                            confirmation_roots.push_back(messages[j - 1].sha256());
                        }
                        i--;
                        j--;
                    } else if (1 == operations[i][j]) {
                        // ??????????????????????????????target?????????????????????????????????
                        // ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
                        if (1 != j || targetLength != communication_max_message_list_size ||
                            sourceLength != communication_max_message_list_size) {
                            missing_messages.push_back(messages[j - 1]);

                            // ???????????????????????????????????????????????????????????????????????????????????????
                            auto k = j - 1;
                            while (k + 1 < targetLength && target[k] == target[k + 1]) {
                                missing_messages.push_back(messages[k + 1]);
                                k++;
                            }
                        }

                        j--;
                    } else if (2 == operations[i][j]) {
                        // ?????????????????????????????????????????????????????????
                        i--;
                    }
                }

                // ???????????????0????????????????????????????????????????????????????????????dist[i][j]?????????0????????????
                // ?????????????????????????????????confirmation root????????????
                for(; j > 0; j--) {
//                    log("INFO: Confirm message hash[%s]", aux::toHex(messages[j - 1].sha256().to_string()).c_str());
                    confirmation_roots.push_back(messages[j - 1].sha256());
                }

                // reverse missing messages
//                std::reverse(missing_messages.begin(), missing_messages.end());
            }
        }

        void communication::find_best_solution(const std::vector<message> &messages, const aux::bytes &hash_prefix_array,
                                          std::vector<message> &missing_messages,
                                          std::vector<message> &confirmed_messages) {
            // ????????????????????????????????????????????????????????????
            if (hash_prefix_array.empty()) {
                log(LOG_INFO, "INFO: Hash prefix array is empty");
                missing_messages.insert(missing_messages.end(), messages.begin(), messages.end());
                return;
            }

            if (!messages.empty()) {
                auto size = messages.size();
                // ???????????????source
                const aux::bytes& source = hash_prefix_array;
                // ?????????????????????target
                aux::bytes target;
                for (auto const &message: messages) {
                    target.push_back(message.sha256()[0]);
                }

                const size_t sourceLength = source.size();
                const size_t targetLength = size;

                log(LOG_INFO, "INFO: source array[%s], target array[%s]", aux::toHex(source).c_str(), aux::toHex(target).c_str());
                // ??????source???target????????????????????????Levenshtein??????????????????
                if (source == target) {
                    for (auto const &msg: messages) {
//                        log("INFO: Confirm message hash[%s]", aux::toHex(msg.sha256().to_string()).c_str());
                        confirmed_messages.push_back(msg);
                    }
                    return;
                }

                // ??????????????????
                size_t dist[sourceLength + 1][targetLength + 1];
                // ????????????
                size_t operations[sourceLength + 1][targetLength + 1];

                // ????????????[i, 0]????????????????????????????????????????????????????????????
                for (size_t i = 0; i < sourceLength + 1; i++) {
                    dist[i][0] = i;
                    if (i > 0) {
                        operations[i][0] = 2;
                    }
                }

                // ????????????????????????[0, j]????????????????????????????????????????????????
                for (size_t j = 0; j < targetLength + 1; j++) {
                    dist[0][j] = j;
                    if (j > 0) {
                        operations[0][j] = 1;
                    }
                }

                // ????????????????????????????????????0?????????????????????1??????????????????[i, j]?????????????????????????????????
                for (size_t i = 1; i < sourceLength + 1; i++) {
                    for (size_t j = 1; j < targetLength + 1; j++) {
                        // ???i?????????????????????index??????i-1???????????????????????????????????????????????????0??????????????????1
                        size_t cost = source[i - 1] == target[j - 1] ? 0 : 1;
                        // [i, j]???[i, j-1]?????????????????????????????????????????????1
                        size_t insert = dist[i][j - 1] + 1;
                        // [i, j]???[i-1, j]?????????????????????????????????????????????1
                        size_t del = dist[i - 1][j] + 1;
                        // [i, j]???[i-1, j-1]???????????????????????????????????????1?????????
                        size_t swap = dist[i - 1][j - 1] + cost;

                        // ???[i-1, j]??? [i, j-1]??? [i-1, j-1]???????????????[i, j]?????????????????????????????????
                        dist[i][j] = std::min(std::min(insert, del), swap);

                        // ?????????????????????????????????
                        operations[i][j] = optCode(swap, insert, del);
                    }
                }

                // ???????????????????????????????????????
                auto i = sourceLength;
                auto j = targetLength;
                while (0 != dist[i][j]) {
                    if (0 == operations[i][j]) {
                        // ??????????????????????????????target?????????????????????????????????
                        if (source[i - 1] != target[j - 1]) {
                            missing_messages.push_back(messages[j - 1]);
                        } else {
//                            log("INFO: Confirm message hash[%s]", aux::toHex(messages[j - 1].sha256().to_string()).c_str());
                            confirmed_messages.push_back(messages[j - 1]);
                        }
                        i--;
                        j--;
                    } else if (1 == operations[i][j]) {
                        // ??????????????????????????????target?????????????????????????????????
                        // ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
                        if (1 != j || targetLength != communication_max_message_list_size ||
                            sourceLength != communication_max_message_list_size) {
                            missing_messages.push_back(messages[j - 1]);

                            // ???????????????????????????????????????????????????????????????????????????????????????
                            auto k = j - 1;
                            while (k + 1 < targetLength && target[k] == target[k + 1]) {
                                missing_messages.push_back(messages[k + 1]);
                                k++;
                            }
                        }

                        j--;
                    } else if (2 == operations[i][j]) {
                        // ?????????????????????????????????????????????????????????
                        i--;
                    }
                }

                // ???????????????0????????????????????????????????????????????????????????????dist[i][j]?????????0????????????
                // ?????????????????????????????????confirmation root????????????
                for(; j > 0; j--) {
//                    log("INFO: Confirm message hash[%s]", aux::toHex(messages[j - 1].sha256().to_string()).c_str());
                    confirmed_messages.push_back(messages[j - 1]);
                }

                // reverse missing messages
//                std::reverse(missing_messages.begin(), missing_messages.end());
            }
        }

//        std::string communication::make_salt(dht::public_key peer, std::int64_t data_type_id) {
//            std::string salt(peer.bytes.begin(), peer.bytes.begin() + common::salt_pubkey_length);
//            common::protocol_entry protocolEntry(data_type_id);
//            std::string encode = protocolEntry.get_encode();
//            salt.insert(salt.end(), encode.begin(), encode.end());
//
//            return salt;
//        }

//        // callback for dht_immutable_get
//        void communication::get_immutable_callback(const dht::public_key &peer, sha256_hash target
//                , dht::item const& i)
//        {
//            log("DEBUG: Immutable callback");
//            TORRENT_ASSERT(!i.is_mutable());
//            if (!i.empty()) {
//                log("INFO: Got immutable data callback, target[%s].", aux::toHex(target.to_string()).c_str());
////                aux::bytes encode;
////                encode.insert(encode.end(), i.value().string().begin(), i.value().string().end());
//                message msg(i.value());
//
//                add_new_message(peer, msg, true);
//            }
//        }

//        void communication::dht_get_immutable_item(const dht::public_key &peer, sha256_hash const& target, std::vector<dht::node_entry> const& eps)
//        {
//            if (!m_ses.dht()) return;
//            m_ses.dht()->get_item(target, eps, std::bind(&communication::get_immutable_callback
//                    , this, peer, target, _1));
//        }

        // callback for dht_mutable_get
        void communication::get_mutable_callback(dht::item const& i
                , bool const authoritative)
        {
            // ??????????????????user event
            if (!i.empty()) {
                m_ses.alerts().emplace_alert<communication_user_info_alert>(i.pk(),
                                                                            aux::bytes(i.salt().begin(),i.salt().end()),
                                                                            aux::bytes(i.value().string().begin(),
                                                                                       i.value().string().end()));
            }
//            TORRENT_ASSERT(i.is_mutable());
//
//            // construct mutable data wrapper from entry
//            if (!i.empty()) {
////                dht::public_key peer = i.pk();
////
////                // update latest item timestamp
////                if (i.ts() > m_latest_item_timestamp[peer]) {
////                    m_latest_item_timestamp[peer] = i.ts();
////                }
//
//                auto salt = i.salt();
//                std::string id(salt.begin() + communication_salt_pubkey_length, salt.end());
//                std::int64_t data_type_id = std::strtol(id.c_str(), nullptr, 10);
//                process_payload(i.pk(), data_type_id, i.value(), true);
////                online_signal onlineSignal(i.value());
////
////                process_signal(onlineSignal, i.pk());
//            }
        }

        // key is a 32-byte binary string, the public key to look up.
        // the salt is optional
//        void communication::dht_get_mutable_item(std::array<char, 32> key
//                , std::string salt, dht::timestamp t)
//        {
//            if (!m_ses.dht()) return;
//            m_ses.dht()->get_item(dht::public_key(key.data()), std::bind(&communication::get_mutable_callback
//                    , this, _1, _2), std::move(salt), t.value);
//        }

        void communication::on_dht_put_mutable_item(const dht::item &i, int n) {
//            log(true, "INFO: peer[%s], value[%s]", aux::toHex(peer.bytes).c_str(), i.value().to_string().c_str());
//
//            auto salt = i.salt();
//            std::string encode(salt.begin() + common::salt_pubkey_length, salt.end());
//            common::protocol_entry protocolEntry(encode);
//            if (protocolEntry.m_pid == common::protocol_put) {
//                if (protocolEntry.m_data_type_id == common::message_entry::data_type_id) {
//                    for (auto const& n: nodes) {
//                        log(true, "====== nodes:%s, bool:%d", n.first.addr().to_string().c_str(), n.second);
//                    }
//
//                    common::message_entry msgEntry(i.value());
//                    auto now = get_current_time();
//                    m_ses.alerts().emplace_alert<communication_syncing_message_alert>(peer, msgEntry.m_msg.sha256(), now);
//                    for (auto const& n: nodes) {
//                        if (n.second) {
//                            m_ses.alerts().emplace_alert<communication_message_arrived_alert>(peer, msgEntry.m_msg.sha256(), now);
//                            break;
//                        }
//                    }
//                }
//            }
        }

        void communication::on_dht_relay_mutable_item(const entry &payload,
                                                      const std::vector<std::pair<dht::node_entry, bool>> &nodes,
                                                      const dht::public_key &peer) {
            // data type id
            if (auto* i = const_cast<entry *>(payload.find_key(common::entry_type)))
            {
                auto data_type_id = i->integer();
                if (data_type_id == common::message_entry::data_type_id) {
                    for (auto const& n: nodes) {
                        log(LOG_DEBUG, "nodes:%s, bool:%d", n.first.addr().to_string().c_str(), n.second);
                    }

                    common::message_entry msgEntry(payload);
                    auto now = get_current_time();
                    m_ses.alerts().emplace_alert<communication_syncing_message_alert>(peer, msgEntry.m_msg.sha256(), now);
                    for (auto const& n: nodes) {
                        if (n.second) {
                            m_ses.alerts().emplace_alert<communication_message_arrived_alert>(peer, msgEntry.m_msg.sha256(), now);
                            break;
                        }
                    }
                }
            }
        }

//        namespace {
//
//            void on_dht_put_immutable_item(aux::alert_manager& alerts, sha256_hash target, int num)
//            {
//            }
//
//            void put_mutable_data(entry& e, std::array<char, 64>& sig
//                    , std::int64_t& ts
//                    , std::string const& salt
//                    , std::array<char, 32> const& pk
//                    , std::array<char, 64> const& sk
//                    , entry const& data)
//            {
//                using lt::dht::sign_mutable_item;
//
//                e = data;
//                std::vector<char> buf;
//                // bencode????????????mutable data
//                bencode(std::back_inserter(buf), e);
//                dht::signature sign;
//                // get unix timestamp
//                ts = libTAU::aux::utcTime();
//                // ??????????????????????????????(data + salt + ts)????????????
//                sign = sign_mutable_item(buf, salt, dht::timestamp(ts)
//                        , dht::public_key(pk.data())
//                        , dht::secret_key(sk.data()));
//                sig = sign.bytes;
//            }
//
//            void put_mutable_callback(dht::item& i
//                    , std::function<void(entry&, std::array<char, 64>&
//                    , std::int64_t&, std::string const&)> cb)
//            {
//                entry value = i.value();
//                dht::signature sig = i.sig();
//                dht::public_key pk = i.pk();
//                dht::timestamp ts = i.ts();
//                std::string salt = i.salt();
//                // ??????item???????????????cb??????
//                cb(value, sig.bytes, ts.value, salt);
//                // ??????????????????item??????????????????item
//                i.assign(std::move(value), salt, ts, pk, sig);
//            }
//        } // anonymous namespace

        void communication::publish(const std::string& salt, const entry& data) {
            if (!m_ses.dht()) return;
            log(LOG_INFO, "INFO: Publish salt[%s], data[%s]", aux::toHex(salt).c_str(), data.to_string(true).c_str());
            m_ses.dht()->put_item(data, std::bind(&communication::on_dht_put_mutable_item, self(), _1, _2)
                    , 1, 8, 24, salt);
        }

        void communication::subscribe(const dht::public_key &peer, const std::string &salt) {
            if (!m_ses.dht()) return;
            m_ses.dht()->get_item(peer, std::bind(&communication::get_mutable_callback, self(), _1, _2), salt);
        }

        void communication::send_to(const dht::public_key &peer, const entry &data) {
            if (!m_ses.dht()) return;
            log(LOG_INFO, "Send [%s] to peer[%s]", data.to_string(true).c_str(), aux::toHex(peer.bytes).c_str());
            m_ses.dht()->send(peer, data, 1, 8, 100, 10,
                              std::bind(&communication::on_dht_relay_mutable_item, self(), _1, _2, peer));
        }

//        void communication::dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target)
//        {
//            if (!m_ses.dht()) return;
//            m_ses.dht()->put_item(data,  eps, std::bind(&on_dht_put_immutable_item, std::ref(m_ses.alerts())
//                    , target, _1));
//        }

//        void communication::dht_put_mutable_item(entry const& data, std::int8_t alpha, std::int8_t beta,
//                                                 std::int8_t invoke_limit, std::string salt)
//        {
//            if (!m_ses.dht()) return;
//            m_ses.dht()->put_item(data, std::bind(&communication::on_dht_put_mutable_item, self(), _1, _2)
//                    , alpha, beta, invoke_limit, std::move(salt));
//        }

        void communication::send_all_unconfirmed_messages(const dht::public_key &peer) {
            // find out missing messages and confirmation root
            std::vector<message> missing_messages;
            std::vector<sha256_hash> confirmation_roots;
            auto &message_list = m_message_list_map[peer];
            std::vector<message> messages(message_list.begin(), message_list.end());
            log(LOG_INFO, "INFO: Messages size:%" PRIu64, messages.size());
            log(LOG_INFO, "INFO: Send all msgs peer[%s] levenshtein array:%s", aux::toHex(peer.bytes).c_str(),
                aux::toHex(m_levenshtein_array[peer]).c_str());
            find_best_solution(messages, m_levenshtein_array[peer],
                               missing_messages, confirmation_roots);

            log(LOG_INFO, "INFO: Found missing message size %" PRIu64, missing_messages.size());

            auto now = get_current_time();

            aux::bytes levenshtein_array;
            for (auto const &message: messages) {
                levenshtein_array.push_back(message.sha256()[0]);
            }

            auto size = missing_messages.size();
            for(auto k = 0; k < size; k++) {
                common::message_entry msg_entry(missing_messages[k], levenshtein_array, now);
                send_to(peer, msg_entry.get_entry());
            }
        }

        void communication::update_communication_time(const dht::public_key &peer, std::int64_t time) {
            m_last_communication_time[peer] = time;
            m_message_db->save_last_communication_time(std::make_pair(*m_ses.pubkey(), peer), time);
        }

        void communication::update_levenshtein_array(const dht::public_key &peer, const aux::bytes& levenshtein_array, std::int64_t time) {
            m_levenshtein_array[peer] = levenshtein_array;
            m_levenshtein_array_time[peer] = time;
            log(LOG_INFO, "save peer[%s] levenshtein array:%s", aux::toHex(peer.bytes).c_str(), aux::toHex(levenshtein_array).c_str());
            m_message_db->save_levenshtein_array(std::make_pair(*m_ses.pubkey(), peer), levenshtein_array);
            m_message_db->save_levenshtein_array_time(std::make_pair(*m_ses.pubkey(), peer), time);
        }


        bool communication::should_log(aux::LOG_LEVEL log_level) const
        {
            return log_level <= m_ses.get_log_level() && m_ses.alerts().should_post<communication_log_alert>();
        }

        TORRENT_FORMAT(3,4)
        void communication::log(aux::LOG_LEVEL log_level, char const* fmt, ...) const noexcept try
        {
#ifndef TORRENT_DISABLE_LOGGING
            if (!should_log(log_level)) return;

            va_list v;
            va_start(v, fmt);
            m_ses.alerts().emplace_alert<communication_log_alert>(fmt, v);
            va_end(v);
#endif
        }
        catch (std::exception const&) {}

    }
}
