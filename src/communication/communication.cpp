/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <cstdlib>
#include <utility>
#include <algorithm>

#include "libTAU/communication/message_hash_list.hpp"
#include "libTAU/communication/communication.hpp"
#include "libTAU/kademlia/dht_tracker.hpp"
#include "libTAU/aux_/common_data.h"

using namespace std::placeholders;

namespace libTAU {
    namespace communication {

        bool communication::start()
        {
            log("INFO: Start Communication...");
            if (!init()) {
                log("ERROR: Init fail.");
                return false;
            }

            m_stop = false;

            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(std::bind(&communication::refresh_timeout, self(), _1));

            return true;
        }

        bool communication::stop()
        {
            m_stop = true;

            clear();

            log("INFO: Stop Communication...");

            return true;
        }

        bool communication::init() {
            try {
                log("INFO: Communication init...");
                if (!m_message_db->init()) {
                    log("ERROR: DB init fail!");
                    return false;
                }

                // get friends from db
                m_friends = m_message_db->get_all_friends();

                dht::public_key *pk = m_ses.pubkey();
                m_friends.push_back(*pk);

                log("INFO: friend size: %zu", m_friends.size());
                for (auto const & peer: m_friends) {
                    log("INFO: friend: %s", aux::toHex(peer.bytes).c_str());
                    std::string encode = m_message_db->get_latest_message_hash_list_encode(std::make_pair(*pk, peer));

                    if (!encode.empty()) {
                        message_hash_list hashList(encode);
                        log("INFO: %s from peer[%s]", hashList.to_string().c_str(), aux::toHex(peer.bytes).c_str());
                        for (auto const &hash: hashList.hash_list()) {
                            log("INFO: Get message hash:%s", aux::toHex(hash).c_str());
                            message msg = m_message_db->get_message(hash);
                            if (!msg.empty()) {
                                log("INFO: Got message from db[%s]", msg.to_string().c_str());
                                m_message_list_map[peer].push_back(msg);
                            } else {
                                log("INFO: Cannot find message[%s] in db.", aux::toHex(hash).c_str());
                            }
                        }
                    } else {
                        log("INFO: Message hash list is empty.");
                    }
                }
            } catch (std::exception &e) {
                log("Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
                return false;
            }

            return true;
        }

        void communication::clear() {
            m_friends.clear();
            m_tasks.clear();
            m_last_greeting.clear();
            m_peer_access_times.clear();
            m_message_list_map.clear();
            m_chatting_friend = std::make_pair(dht::public_key(), 0);
            m_active_friends.clear();
            m_last_seen.clear();
            m_latest_signal_time.clear();
            m_latest_hash_prefix_array.clear();
            m_missing_messages.clear();
        }

        void communication::account_changed() {
            try {
                log("INFO: Change account.");
                // 账户发生改变，模块重新启动
//                stop();
//                start();

                clear();
                init();
            } catch (std::exception &e) {
                log("Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            }
        }

        std::int64_t communication::get_current_time() {
            return total_milliseconds(system_clock::now().time_since_epoch());
        }

        void communication::on_dht_item(const dht::item &i) {
            // construct mutable data wrapper from entry
            if (!i.empty()) {
//                dht::public_key peer = i.pk();

                // update latest item timestamp
//                if (i.ts() > m_latest_item_timestamp[peer]) {
//                    m_latest_item_timestamp[peer] = i.ts();
//                }

                // check protocol id
                if (auto* p = const_cast<entry *>(i.value().find_key("pid")))
                {
                    auto protocol_id = p->integer();
                    if (online_signal::protocol_id == protocol_id) {
                        online_signal onlineSignal(i.value());

                        process_signal(onlineSignal, i.pk());
                    }
                }


                auto peer = i.pk();
                auto now = get_current_time();
                m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, now);

                // check data type id
                if (auto* p = const_cast<entry *>(i.value().find_key(common::entry_type)))
                {
                    auto data_type_id = p->integer();
                    switch (data_type_id) {
                        case common::message_entry::data_type_id: {
                            common::message_entry msg_entry(i.value());
                            log("INFO: Got message, hash[%s].",
                                aux::toHex(msg_entry.m_msg.sha256().to_string()).c_str());

                            add_new_message(i.pk(), msg_entry.m_msg, true);

                            common::entry_task levenshtein_array_task1(
                                    common::message_levenshtein_array_entry::data_type_id, peer, now);
                            m_tasks.insert(levenshtein_array_task1);
                            common::entry_task levenshtein_array_task2(
                                    common::message_levenshtein_array_entry::data_type_id, peer, now + 1000);
                            m_tasks.insert(levenshtein_array_task2);
                            common::entry_task levenshtein_array_task3(
                                    common::message_levenshtein_array_entry::data_type_id, peer, now + 5000);
                            m_tasks.insert(levenshtein_array_task3);

                            break;
                        }
                        case common::message_levenshtein_array_entry::data_type_id: {
                            common::message_levenshtein_array_entry levenshtein_array_entry(i.value());
                            log("INFO: Got message levenshtein array[%s].",
                                aux::toHex(levenshtein_array_entry.m_levenshtein_array).c_str());

                            // find out missing messages and confirmation root
                            std::vector<message> missing_messages;
                            std::vector<sha256_hash> confirmation_roots;
                            auto &message_list = m_message_list_map[peer];
                            std::vector<message> messages(message_list.begin(), message_list.end());
                            log("INFO: Messages size:%zu", messages.size());
                            find_best_solution(messages, levenshtein_array_entry.m_levenshtein_array,
                                               missing_messages, confirmation_roots);

                            if (!confirmation_roots.empty()) {
                                m_ses.alerts().emplace_alert<communication_confirmation_root_alert>(peer,
                                                                                                    confirmation_roots,
                                                                                                    now);
                                log("INFO: Confirmation roots:%zu", confirmation_roots.size());
                            }
                            log("INFO: Found missing message size %zu", missing_messages.size());

                            auto size = missing_messages.size();
                            for(auto k = 0; k < size; k++) {
                                common::message_entry msg_entry(missing_messages[k]);
                                common::entry_task task(common::message_entry::data_type_id, peer, msg_entry.get_entry(), now + 100 * k);
                                m_tasks.insert(task);
                            }
//                            for(auto k = 0; k < size; k++) {
//                                common::message_entry msg_entry(missing_messages[k]);
//                                common::entry_task task(common::message_entry::data_type_id, peer, msg_entry.get_entry(), now + 1000 + 100 * k);
//                                m_tasks.insert(task);
//                            }
//                            for(auto k = 0; k < size; k++) {
//                                common::message_entry msg_entry(missing_messages[k]);
//                                common::entry_task task(common::message_entry::data_type_id, peer, msg_entry.get_entry(), now + 5000 + 100 * k);
//                                m_tasks.insert(task);
//                            }

                            // check if local levenshtein array != remote levenshtein array
                            aux::bytes levenshtein_array;
                            for (auto const &message: messages) {
                                levenshtein_array.push_back(message.sha256()[0]);
                            }
                            if (levenshtein_array_entry.m_levenshtein_array != levenshtein_array) {
                                common::entry_task levenshtein_array_task1(
                                        common::message_levenshtein_array_entry::data_type_id, peer, now + 6000);
                                m_tasks.insert(levenshtein_array_task1);
                                common::entry_task levenshtein_array_task2(
                                        common::message_levenshtein_array_entry::data_type_id, peer, now + 7000);
                                m_tasks.insert(levenshtein_array_task2);
                                common::entry_task levenshtein_array_task3(
                                        common::message_levenshtein_array_entry::data_type_id, peer, now + 9000);
                                m_tasks.insert(levenshtein_array_task3);
                            }

                            break;
                        }
                        case common::friend_info_request_entry::data_type_id: {
                            auto pubkey = *m_ses.pubkey();
                            auto friend_info = m_message_db->get_friend_info(std::make_pair(pubkey, pubkey));
                            if (!friend_info.empty()) {
                                common::friend_info_entry e(friend_info);
                                common::entry_task task1(common::friend_info_entry::data_type_id, peer, e.get_entry(), now);
                                m_tasks.insert(task1);
                                common::entry_task task2(common::friend_info_entry::data_type_id, peer, e.get_entry(), now + 1000);
                                m_tasks.insert(task2);
                                common::entry_task task3(common::friend_info_entry::data_type_id, peer, e.get_entry(), now + 5000);
                                m_tasks.insert(task3);
                            }

                            break;
                        }
                        case common::friend_info_entry::data_type_id: {
                            common::friend_info_entry e(i.value());
                            if (!e.m_friend_info.empty()) {
                                // 通知用户新的friend info
                                m_ses.alerts().emplace_alert<communication_friend_info_alert>(peer, e.m_friend_info);
                            }

                            break;
                        }
                        default: {
                        }
                    }
                }
            }
        }

        void communication::set_loop_time_interval(int milliseconds) {
            log("INFO: Set loop time:%d(ms)", milliseconds);
            m_refresh_time = milliseconds;
        }

        bool communication::add_new_friend(const dht::public_key &pubkey) {
            if (pubkey == dht::public_key()) {
                log("ERROR: Public key is empty.");
                return false;
            }

            log("INFO: Add new friend, public key %s.", aux::toHex(pubkey.bytes).c_str());

            auto it = find(m_friends.begin(), m_friends.end(), pubkey);
            if (it == m_friends.end()) {
                log("INFO: Friend is not existed.");

                m_friends.push_back(pubkey);
                if (!m_message_db->save_friend(pubkey)) {
                    log("ERROR: Save friend failed!");
                    return false;
                }
            }

            return true;
        }

        bool communication::delete_friend(const dht::public_key &pubkey) {
            log("INFO: Delete friend, public key %s.", aux::toHex(pubkey.bytes).c_str());

            for(auto it = m_friends.begin(); it != m_friends.end(); ++it) {
                if (*it == pubkey) {
                    m_friends.erase(it);
                    break;
                }
            }

            if (!m_message_db->delete_friend(pubkey)) {
                log("ERROR: Delete friend failed!");
                return false;
            }

            const auto &pk = m_ses.pubkey();

            if (!m_message_db->delete_friend_info(std::make_pair(*pk, pubkey))) {
                log("ERROR: Delete friend info failed!");
                return false;
            }

            if (!m_message_db->delete_latest_message_hash_list_encode(std::make_pair(*pk, pubkey))) {
                log("ERROR: Delete friend message hash list encode failed!");
                return false;
            }

            return true;
        }

        void communication::request_friend_info(const dht::public_key &peer) {
            common::friend_info_request_entry friendInfoRequestEntry;
            send_to(peer, friendInfoRequestEntry.get_entry());
            std::int64_t now = get_current_time();
//            common::entry_task task1(common::message_entry::data_type_id, msg.receiver(), msg_entry.get_entry(), now);
//            m_tasks.insert(task1);
            common::entry_task task2(common::friend_info_request_entry::data_type_id, peer, friendInfoRequestEntry.get_entry(), now + 1000);
            m_tasks.insert(task2);
            common::entry_task task3(common::friend_info_request_entry::data_type_id, peer, friendInfoRequestEntry.get_entry(), now + 5000);
            m_tasks.insert(task3);
        }

        aux::bytes communication::get_friend_info(const dht::public_key &pubkey) {
            const auto &pk = m_ses.pubkey();
            return m_message_db->get_friend_info(std::make_pair(*pk, pubkey));
        }

        bool communication::update_friend_info(const dht::public_key &pubkey, const aux::bytes& friend_info) {
            log("INFO: Update peer[%s] friend info[%s]", aux::toHex(pubkey.bytes).c_str(), aux::toHex(friend_info).c_str());
            const auto &pk = m_ses.pubkey();
            return m_message_db->save_friend_info(std::make_pair(*pk, pubkey), friend_info);
        }

        void communication::set_chatting_friend(dht::public_key chatting_friend) {
            log("INFO: Set chatting friend:%s", aux::toHex(chatting_friend.bytes).c_str());
            m_chatting_friend = std::make_pair(chatting_friend, total_seconds(system_clock::now().time_since_epoch()));
        }

        void communication::unset_chatting_friend() {
            if (m_chatting_friend.first != dht::public_key()) {
                log("INFO: Unset chatting friend.");
                m_chatting_friend = std::make_pair(dht::public_key(), 0);
            }
        }

        void communication::set_active_friends(std::vector<dht::public_key> active_friends) {
//            log("INFO: Set active friends[%zu].", active_friends.size());
            m_active_friends = std::move(active_friends);
        }

        bool communication::add_new_message(const message &msg, bool post_alert) {
            if (!add_new_message(msg.receiver(), msg, post_alert))
                return false;

            common::message_entry msg_entry(msg);
            send_to(msg.receiver(), msg_entry.get_entry());
            std::int64_t now = get_current_time();
//            common::entry_task task1(common::message_entry::data_type_id, msg.receiver(), msg_entry.get_entry(), now);
//            m_tasks.insert(task1);
//            common::entry_task task2(common::message_entry::data_type_id, msg.receiver(), msg_entry.get_entry(), now + 1000);
//            m_tasks.insert(task2);
//            common::entry_task task3(common::message_entry::data_type_id, msg.receiver(), msg_entry.get_entry(), now + 5000);
//            m_tasks.insert(task3);

            common::entry_task levenshtein_array_task1(common::message_levenshtein_array_entry::data_type_id, msg.receiver(), now + 6000);
            m_tasks.insert(levenshtein_array_task1);
            common::entry_task levenshtein_array_task2(common::message_levenshtein_array_entry::data_type_id, msg.receiver(), now + 7000);
            m_tasks.insert(levenshtein_array_task2);
            common::entry_task levenshtein_array_task3(common::message_levenshtein_array_entry::data_type_id, msg.receiver(), now + 9000);
            m_tasks.insert(levenshtein_array_task3);

//            {
//                // 本地消息数组为target
//                aux::bytes levenshtein_array;
//                auto &msg_list = m_message_list_map[msg.receiver()];
//                for (auto const &msg: msg_list) {
//                    levenshtein_array.push_back(msg.sha256()[0]);
//                }
//
//                common::message_levenshtein_array_entry msg_levenshtein_array(levenshtein_array);
//
//                common::communication_entries communicationEntries;
//                // big enough?
//                communicationEntries.push_back(msg_entry.get_entry());
//                communicationEntries.push_back(msg_levenshtein_array.get_entry());
//
//                common::entry_task task1(msg.receiver(), communicationEntries.get_entry(), now);
//                m_tasks.insert(task1);
//                common::entry_task task2(msg.receiver(), communicationEntries.get_entry(), now + 1000);
//                m_tasks.insert(task2);
//                common::entry_task task3(msg.receiver(), communicationEntries.get_entry(), now + 5000);
//                m_tasks.insert(task3);
//            }

            return true;
        }

        bool communication::add_new_message(const dht::public_key &peer, const message& msg, bool post_alert) {
            if (msg.empty()) {
                log("ERROR: Message is empty.");
                return false;
            }

            log("INFO: Add new msg[%s]", msg.to_string().c_str());

//            dht::public_key * pk = m_ses.pubkey();
//            aux::bytes public_key;
//            public_key.insert(public_key.end(), pk->bytes.begin(), pk->bytes.end());
//            if (msg.sender() != public_key && msg.receiver() != public_key) {
//                log("ERROR: Unknown message, sender/receiver is not me.");
//                return false;
//            }

//            aux::bytes key_y;
//            if (msg.sender() == public_key) {
//                // sender is me means message comes from me, y is receiver
//                key_y = msg.receiver();
//            } else {
//                // receiver is me means message comes from others, y is sender
//                key_y = msg.sender();
//            }

            if (!validate_message(msg))
                return false;

            return try_to_update_Latest_message_list(peer, msg, post_alert);
        }

        bool communication::validate_message(const message& msg) {
            if (msg.encode().size() > 1000) {
                log("ERROR: Message is oversize!");
                return false;
            }

            return true;
        }

        void communication::process_signal(const online_signal &signal, const dht::public_key &peer) {
            log("INFO: Got online signal:[%s] from peer[%s]", signal.to_string().c_str(), aux::toHex(peer.bytes).c_str());

            dht::public_key pubkey = *m_ses.pubkey();

            auto now_time = total_milliseconds(system_clock::now().time_since_epoch());
            // 验证mutable数据的时间戳，只接受当前时间前后6小时以内的数据
            if ((signal.timestamp() + communication_data_accepted_time < now_time) ||
                (signal.timestamp() - communication_data_accepted_time > now_time)) {
                log("WARNING: Online signal timestamp from peer[%s] is out of range!", aux::toHex(peer.bytes).c_str());
                return;
            }

            // record latest timestamp(update once per second)
            if (signal.timestamp() / 10000 > m_last_seen[peer] / 10000) {
                m_last_seen[peer] = signal.timestamp();
                // 通知用户新的last seen time
                m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, signal.timestamp());
                log("INFO: Last seen peer[%s], time[%ld]", aux::toHex(peer.bytes).c_str(), signal.timestamp());
            }

            auto &device_id = signal.device_id();
            auto &device_time_map = m_latest_signal_time[peer];

            // 检查相应设备信号的时间戳，只处理最新的数据
            if (!device_id.empty() && signal.timestamp() > device_time_map[device_id]) {
                // update the latest signal time
                device_time_map[device_id] = signal.timestamp();
//                    m_latest_signal_time[peer] = device_time_map;

                // if signal is from multi-device, post new device id alert and friend info alert
                if (peer == pubkey && device_id != m_device_id) {
                    // 通知用户新的device id
                    m_ses.alerts().emplace_alert<communication_new_device_id_alert>(device_id);
                    log("INFO: Found new device id: %s", aux::toHex(device_id).c_str());

                    // if data is from multi-device
                    if (!signal.friend_info().empty()) {
                        // 通知用户新的friend info
                        m_ses.alerts().emplace_alert<communication_friend_info_alert>(peer, signal.friend_info());
                        log("INFO: Got friend info:%s", aux::toHex(signal.friend_info()).c_str());
                    }
                }

                // if signal is from multi-device or peer Y, sync immutable data and calc LevenshteinDistance
                if (device_id != m_device_id || peer != pubkey) {
//                    // get immutable message
//                    const immutable_data_info& payload = signal.payload();
//                    log("INFO: Payload:%s", payload.to_string().c_str());
//                    if (!payload.target().is_all_zeros()) {
//                        dht_get_immutable_item(peer, payload.target(), payload.entries());
//                    }

                    // find out missing messages and confirmation root
                    std::vector<message> missing_messages;
                    std::vector<sha256_hash> confirmation_roots;
                    auto message_list = m_message_list_map[peer];
                    std::vector<message> messages(message_list.begin(), message_list.end());
                    log("INFO: Messages size:%zu", messages.size());
                    find_best_solution(messages, signal.hash_prefix_bytes(),
                                       missing_messages, confirmation_roots);

                    auto &device_array_map = m_latest_hash_prefix_array[peer];
                    if (signal.hash_prefix_bytes() != device_array_map[device_id]) {
                        // update the latest hash prefix array
                        device_array_map[device_id] = signal.hash_prefix_bytes();
//                            m_latest_hash_prefix_array[peer] = device_array_map;

                        if (!confirmation_roots.empty()) {
                            m_ses.alerts().emplace_alert<communication_confirmation_root_alert>(peer,
                                                                                                confirmation_roots,
                                                                                                signal.timestamp());
                            log("INFO: Confirmation roots:%zu", confirmation_roots.size());
                        }
                    }

                    log("INFO: Found missing message size %zu", missing_messages.size());

                    for(auto const & msg: missing_messages) {
                        common::message_entry msg_entry(msg);
                        send_to(peer, msg_entry.get_entry());
                    }

////                        if (m_missing_messages[peer].size() < communication_max_message_list_size) {
//                    // Only the data of the latest window is processed
//                    m_missing_messages[peer].clear();
//                    m_missing_messages[peer].insert(missing_messages.begin(), missing_messages.end());
////                        }
                }
            }
        }

        dht::public_key communication::select_friend_randomly() {
            dht::public_key peer{};

            if (!m_friends.empty())
            {
                // 产生随机数
                srand(total_microseconds(system_clock::now().time_since_epoch()));
                auto index = rand() % 10;

                // 检查chatting friend设置时间，如果超过30分钟，则重置
                std::int64_t current_time = total_seconds(system_clock::now().time_since_epoch());
                //log("INFO: Current time:%ld, chatting time:%ld, diff:%ld", current_time, m_chatting_friend.second,
                //    current_time - m_chatting_friend.second);
                if (current_time - m_chatting_friend.second > communication_max_chatting_time) {
                    unset_chatting_friend();
                }

                // chatting friend有80%的概率选中
                if (m_chatting_friend.first != dht::public_key() && index < 8) {
                    peer = m_chatting_friend.first;
                } else {
                    // 以上一次产生的随机数和时间的和作为种子，产生新的随机数，避免时钟太快，产生的随机数一样的情况
                    srand(total_microseconds(system_clock::now().time_since_epoch()));
                    index = rand() % 10;

                    // active friends有70%的概率选中
                    if (!m_active_friends.empty() && index < 7) {
                        srand(total_microseconds(system_clock::now().time_since_epoch()));
                        index = rand() % m_active_friends.size();
                        peer = m_active_friends[index];
                    } else {
                        // 筛选剩余的朋友
                        std::vector<dht::public_key> other_friends = m_friends;
                        for (const auto& fri: m_friends) {
                            bool found = false;
                            for (const auto& active_fri: m_active_friends) {
                                if (active_fri == fri) {
                                    found = true;
                                    break;
                                }
                            }

                            if (!found) {
                                other_friends.push_back(fri);
                            }
                        }

                        // 在剩余的朋友中随机挑选一个
                        if (!other_friends.empty()) {
                            srand(total_microseconds(system_clock::now().time_since_epoch()));
                            index = rand() % other_friends.size();
                            peer = other_friends[index];
                        }
                    }
                }
            }

            return peer;
        }

        void communication::refresh_timeout(error_code const& e)
        {
            if (e || m_stop) return;

            try {
//                // 随机挑选一个朋友put/get
//                dht::public_key peer = select_friend_randomly();
//                std::int64_t current_time = total_milliseconds(system_clock::now().time_since_epoch());
//				int random_time_interval = rand()%400 + 800;
//                if (peer != dht::public_key() && current_time > (m_peer_access_times[peer] + random_time_interval)) {
//                    log("INFO: Select peer:%s", aux::toHex(peer.bytes).c_str());
//                    m_peer_access_times[peer] = current_time;
//
////                    request_signal(peer);
//                    publish_signal(peer);
//                }

                auto now = get_current_time();
                auto size = m_friends.size();
                for (auto i = 0; i < size; i++) {
                    auto& peer = m_friends[i];
                    if (now > m_last_greeting[peer] + 60 * 60 * 1000) {
                        m_last_greeting[peer] = now;

                        common::entry_task levenshtein_array_task1(
                                common::message_levenshtein_array_entry::data_type_id, peer, now + 100 * i);
                        m_tasks.insert(levenshtein_array_task1);
                        common::entry_task levenshtein_array_task2(
                                common::message_levenshtein_array_entry::data_type_id, peer, now + 1000 + 100 * i);
                        m_tasks.insert(levenshtein_array_task2);
                        common::entry_task levenshtein_array_task3(
                                common::message_levenshtein_array_entry::data_type_id, peer, now + 5000 + 100 * i);
                        m_tasks.insert(levenshtein_array_task3);
                    }
                }

                log("--------------------------- tasks size:%lu", m_tasks.size());
                if (!m_tasks.empty()) {
                    auto it = m_tasks.begin();
                    if (it->m_timestamp <= now) {
                        if (it->m_data_type_id == common::message_levenshtein_array_entry::data_type_id) {
                            // 本地消息数组为target
                            aux::bytes levenshtein_array;
                            auto& msg_list = m_message_list_map[it->m_peer];
                            for (auto const &msg: msg_list) {
                                levenshtein_array.push_back(msg.sha256()[0]);
                            }

                            common::message_levenshtein_array_entry msg_levenshtein_array(levenshtein_array);
                            log("------- send peer[%s] levenshtein array", aux::toHex(it->m_peer.bytes).c_str());
                            send_to(it->m_peer, msg_levenshtein_array.get_entry());
                        } else {
                            log("------- send peer[%s] message", aux::toHex(it->m_peer.bytes).c_str());
                            send_to(it->m_peer, it->m_entry);
                        }

                        m_tasks.erase(it);
                    }
                }

                m_refresh_timer.expires_after(milliseconds(m_refresh_time));
                m_refresh_timer.async_wait(std::bind(&communication::refresh_timeout, self(), _1));
            } catch (std::exception &e) {
                log("Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            }
        }

        void communication::launch_scheduled_task(const error_code &e) {
            if (e || m_stop) return;

            try {
//                aux::deadline_timer timer(m_ioc);
//                timer.async_wait(nullptr);
            } catch (std::exception &e) {
                log("Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
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
                log("INFO: Save message hash list %s", messageHashList.to_string().c_str());
                m_message_db->save_latest_message_hash_list_encode(std::make_pair(pubkey, peer),messageHashList.encode());
            }
        }

        bool communication::try_to_update_Latest_message_list(const dht::public_key &peer, const message& msg, bool post_alert) {
            if (msg.empty())
                return false;

            bool updated = false;

            std::list<message> message_list = m_message_list_map[peer];
            if (!message_list.empty()) {
                // 先判断一下是否比最后一个消息时间戳大，如果是，则直接插入末尾
                if (msg.timestamp() > message_list.back().timestamp()) {
                    message_list.push_back(msg);
                    updated = true;
                } else {
                    // 寻找从后往前寻找第一个时间小于当前消息时间的消息，将当前消息插入到到该消息后面
                    auto it = message_list.rbegin();
                    // 是否插入第一个位置，在没找到的情况下会插入到第一个位置
                    bool insertFirst = true;
                    for (; it != message_list.rend(); ++it) {
                        message reference = *it;
//                        signed long diff = reference.timestamp() - msg.timestamp();
                        // 如果差值小于零，说明找到了比当前消息时间戳小的消息位置，将消息插入到目标位置后面一位
                        if (reference.timestamp() < msg.timestamp()) {
                            updated = true;
                            insertFirst = false;
                            message_list.insert(it.base(), msg);
                            break;
                        } else if (reference.timestamp() == msg.timestamp()) {
                            // 如果时间戳一样，寻找第一个哈希比我小的消息
                            auto reference_hash = reference.sha256();
                            auto msg_hash = msg.sha256();
                            if (reference_hash != msg_hash) {
                                // 寻找第一个哈希比我小的消息，插入其前面，否则，继续往前找
                                if (reference_hash < msg_hash) {
                                    updated = true;
                                    insertFirst = false;
                                    message_list.insert(it.base(), msg);
                                    break;
                                }
                            } else {
                                // 如果哈希一样，则本身已经在列表中，也不再进行查找
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

            // 更新成功
            if (updated) {
                log("INFO: Add message[%s] into message list", msg.to_string().c_str());

                // 通知用户新的message
                if (post_alert) {
                    log("DEBUG: Post new message:%s", msg.to_string().c_str());
                    m_ses.alerts().emplace_alert<communication_new_message_alert>(msg);
                }

                // save message in db
                if (!m_message_db->save_message(msg)) {
                    log("ERROR: Save message in db fail[%s]", msg.to_string().c_str());
                    return false;
                }

                // 如果更新了消息列表，则判断是否列表长度过长，过长则删掉旧数据，然后停止循环
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
             * 选用编辑代价最小的，并返回该操作代表的操作数
             * @param swap 替换的代价
             * @param insert 插入的代价
             * @param del 删除的代价
             * @return 0:替换，1：插入，2：删除
             */
            size_t optCode(size_t swap, size_t insert, size_t del) {
                // 如果替换编辑距离最少，则返回0标识，
                // 即使三种操作距离一样，优先选择替换操作
                if (swap <= insert && swap <= del) {
                    return 0;
                }

                // 如果插入操作编辑最少，返回1标识，如果插入和删除距离一样，优先选择插入
                if (insert < swap && insert <= del) {
                    return 1;
                }

                // 如果删除操作编辑最少，返回2标识
                return 2;
            }
        }

        void communication::find_best_solution(const std::vector<message>& messages, const aux::bytes& hash_prefix_array,
                                               std::vector<message> &missing_messages,
                                               std::vector<sha256_hash> &confirmation_roots) {
            // 如果对方没有信息，则本地消息全为缺失消息
            if (hash_prefix_array.empty()) {
                log("INFO: Hash prefix array is empty");
                missing_messages.insert(missing_messages.end(), messages.begin(), messages.end());
                return;
            }

            if (!messages.empty()) {
                auto size = messages.size();
                // 对方数组为source
                const aux::bytes& source = hash_prefix_array;
                // 本地消息数组为target
                aux::bytes target;
                for (auto const &message: messages) {
                    target.push_back(message.sha256()[0]);
                }

                const size_t sourceLength = source.size();
                const size_t targetLength = size;

                log("INFO: source array[%s], target array[%s]", aux::toHex(source).c_str(), aux::toHex(target).c_str());
                // 如果source和target一样，则直接跳过Levenshtein数组匹配计算
                if (source == target) {
                    for (auto const &msg: messages) {
//                        log("INFO: Confirm message hash[%s]", aux::toHex(msg.sha256().to_string()).c_str());
                        confirmation_roots.push_back(msg.sha256());
                    }
                    return;
                }

                // 状态转移矩阵
                size_t dist[sourceLength + 1][targetLength + 1];
                // 操作矩阵
                size_t operations[sourceLength + 1][targetLength + 1];

                // 初始化，[i, 0]转换到空，需要编辑的距离，也即删除的数量
                for (size_t i = 0; i < sourceLength + 1; i++) {
                    dist[i][0] = i;
                    if (i > 0) {
                        operations[i][0] = 2;
                    }
                }

                // 初始化，空转换到[0, j]，需要编辑的距离，也即增加的数量
                for (size_t j = 0; j < targetLength + 1; j++) {
                    dist[0][j] = j;
                    if (j > 0) {
                        operations[0][j] = 1;
                    }
                }

                // 开始填充状态转移矩阵，第0位为空，所以从1开始有数据，[i, j]为当前子串最小编辑操作
                for (size_t i = 1; i < sourceLength + 1; i++) {
                    for (size_t j = 1; j < targetLength + 1; j++) {
                        // 第i个数据，实际的index需要i-1，替换的代价，相同无需替换，代价为0，不同代价为1
                        size_t cost = source[i - 1] == target[j - 1] ? 0 : 1;
                        // [i, j]在[i, j-1]的基础上，最小的编辑操作为增加1
                        size_t insert = dist[i][j - 1] + 1;
                        // [i, j]在[i-1, j]的基础上，最小的编辑操作为删除1
                        size_t del = dist[i - 1][j] + 1;
                        // [i, j]在[i-1, j-1]的基础上，最大的编辑操作为1次替换
                        size_t swap = dist[i - 1][j - 1] + cost;

                        // 在[i-1, j]， [i, j-1]， [i-1, j-1]三种转换到[i, j]的最小操作中，取最小值
                        dist[i][j] = std::min(std::min(insert, del), swap);

                        // 选择一种最少编辑的操作
                        operations[i][j] = optCode(swap, insert, del);
                    }
                }

                // 回溯编辑路径，统计中间信息
                auto i = sourceLength;
                auto j = targetLength;
                while (0 != dist[i][j]) {
                    if (0 == operations[i][j]) {
                        // 如果是替换操作，则将target对应的替换消息加入列表
                        if (source[i - 1] != target[j - 1]) {
                            missing_messages.push_back(messages[j - 1]);
                        } else {
//                            log("INFO: Confirm message hash[%s]", aux::toHex(messages[j - 1].sha256().to_string()).c_str());
                            confirmation_roots.push_back(messages[j - 1].sha256());
                        }
                        i--;
                        j--;
                    } else if (1 == operations[i][j]) {
                        // 如果是插入操作，则将target对应的插入消息加入列表
                        // 注意由于消息是按照时间戳从小到大排列，如果缺第一个，并且此时双方满载，则判定为被挤出去而产生的差异，并非真的缺少
                        if (1 != j || targetLength != communication_max_message_list_size ||
                            sourceLength != communication_max_message_list_size) {
                            missing_messages.push_back(messages[j - 1]);

                            // 如果是插入操作，则将邻近哈希前缀一样的消息也当作缺失的消息
                            auto k = j - 1;
                            while (k + 1 < targetLength && target[k] == target[k + 1]) {
                                missing_messages.push_back(messages[k + 1]);
                                k++;
                            }
                        }

                        j--;
                    } else if (2 == operations[i][j]) {
                        // 如果是删除操作，可能是对方新消息，忽略
                        i--;
                    }
                }

                // 找到距离为0可能仍然不够，可能有前缀相同的情况，这时dist[i][j]很多为0的情况，
                // 因此，需要把剩余的加入confirmation root集合即可
                for(; j > 0; j--) {
//                    log("INFO: Confirm message hash[%s]", aux::toHex(messages[j - 1].sha256().to_string()).c_str());
                    confirmation_roots.push_back(messages[j - 1].sha256());
                }

                // reverse missing messages
//                std::reverse(missing_messages.begin(), missing_messages.end());
            }
        }

        std::string communication::make_salt(dht::public_key peer) {
            std::string salt(peer.bytes.begin(), peer.bytes.begin() + communication_salt_length);

            return salt;
        }

        online_signal communication::make_signal(const dht::public_key &peer) {
            auto now = total_milliseconds(system_clock::now().time_since_epoch());

            // 构造Levenshtein数组，按顺序取每条信息哈希的第一个字节
            aux::bytes hash_prefix_bytes;
            auto message_list = m_message_list_map[peer];
            if (!message_list.empty()) {
                for (const auto & msg: message_list) {
//                    log("DEBUG: Message[%s]", msg.to_string().c_str());
                    hash_prefix_bytes.push_back(msg.sha256()[0]);
                }
            } else {
                log("INFO: Message list from peer[%s] is empty.", aux::toHex(peer.bytes).c_str());
            }

            immutable_data_info payload;
//            auto missing_messages = m_missing_messages[peer];
//            auto size = missing_messages.size();
//            if (size > 0) {
//                srand(now);
//                auto index = rand() % size;
//
//                auto it = missing_messages.begin();
//                for (size_t i = 0; i < index; i++) {
//                    ++it;
//                }
//
//                if (it != missing_messages.end()) {
//                    message missing_message = *it;
//                    m_missing_messages[peer].erase(missing_message);
//
//                    if (!missing_message.empty()) {
//                        // post syncing message hash
//                        m_ses.alerts().emplace_alert<communication_syncing_message_alert>(peer, missing_message.sha256(), now);
//
//                        std::vector<dht::node_entry> entries;
//                        m_ses.dht()->find_live_nodes(missing_message.sha256(), entries);
//                        if (entries.size() > 2) {
//                            entries.resize(2);
//                        }
//                        log("INFO: Put immutable message target[%s], entries[%zu]",
//                            aux::toHex(missing_message.sha256().to_string()).c_str(), entries.size());
//                        dht_put_immutable_item(missing_message.get_entry(), entries, missing_message.sha256());
//
//                        payload = immutable_data_info(missing_message.sha256(), entries);
//
//                        if (1 == size) {
//                            m_last_gasp_payload[peer] = payload;
//                            m_last_gasp_time[peer] = now;
//                        }
//                    } else {
//                        log("INFO: Missing message is empty.");
//                    }
//                }
//            } else {
//                if (now - m_last_gasp_time[peer] < 60000) {
//                    payload = m_last_gasp_payload[peer];
//                    log("INFO: Last gasp.");
//                }
//                log("INFO: Peer[%s] has no missing messages", aux::toHex(peer.bytes).c_str());
//            }

            dht::public_key pubkey = *m_ses.pubkey();

            if (peer == pubkey) {
                // 随机挑选一个朋友发送其信息
                srand(total_milliseconds(system_clock::now().time_since_epoch()));
                auto index = rand() % m_friends.size();
                auto fri = m_friends[index];
                log("INFO: Take friend %s", aux::toHex(fri.bytes).c_str());
                aux::bytes friend_info = m_message_db->get_friend_info(std::make_pair(pubkey, fri));

                online_signal onlineSignal(now, m_device_id, hash_prefix_bytes, payload, friend_info);
                log("INFO: Make online signal:%s on XX channel", onlineSignal.to_string().c_str());

                return onlineSignal;
            } else {
                online_signal onlineSignal(now, m_device_id,hash_prefix_bytes, payload);
                log("INFO: Make online signal:%s on XY channel", onlineSignal.to_string().c_str());

                return onlineSignal;
            }
        }

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
//            log("INFO: Get immutable item, target[%s], entries size[%zu]", aux::toHex(target.to_string()).c_str(), eps.size());
//            m_ses.dht()->get_item(target, eps, std::bind(&communication::get_immutable_callback
//                    , this, peer, target, _1));
//        }

        // callback for dht_mutable_get
//        void communication::get_mutable_callback(dht::item const& i
//                , bool const authoritative)
//        {
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
//                online_signal onlineSignal(i.value());
//
//                process_signal(onlineSignal, i.pk());
//            }
//        }

        // key is a 32-byte binary string, the public key to look up.
        // the salt is optional
//        void communication::dht_get_mutable_item(std::array<char, 32> key
//                , std::string salt, dht::timestamp t)
//        {
//            if (!m_ses.dht()) return;
//            m_ses.dht()->get_item(dht::public_key(key.data()), std::bind(&communication::get_mutable_callback
//                    , this, _1, _2), std::move(salt), t.value);
//        }

        namespace {

            void on_dht_put_immutable_item(aux::alert_manager& alerts, sha256_hash target, int num)
            {
            }

            void put_mutable_data(entry& e, std::array<char, 64>& sig
                    , std::int64_t& ts
                    , std::string const& salt
                    , std::array<char, 32> const& pk
                    , std::array<char, 64> const& sk
                    , entry const& data)
            {
                using lt::dht::sign_mutable_item;

                e = data;
                std::vector<char> buf;
                // bencode要发布的mutable data
                bencode(std::back_inserter(buf), e);
                dht::signature sign;
                // get unix timestamp
                ts = libTAU::aux::utcTime();
                // 对编码完成之后的数据(data + salt + ts)进行签名
                sign = sign_mutable_item(buf, salt, dht::timestamp(ts)
                        , dht::public_key(pk.data())
                        , dht::secret_key(sk.data()));
                sig = sign.bytes;
            }

            void on_dht_put_mutable_item(aux::alert_manager& alerts, dht::item const& i, int num)
            {
            }

            void put_mutable_callback(dht::item& i
                    , std::function<void(entry&, std::array<char, 64>&
                    , std::int64_t&, std::string const&)> cb)
            {
                entry value = i.value();
                dht::signature sig = i.sig();
                dht::public_key pk = i.pk();
                dht::timestamp ts = i.ts();
                std::string salt = i.salt();
                // 提取item信息，交给cb处理
                cb(value, sig.bytes, ts.value, salt);
                // 使用新生成的item信息替换旧的item
                i.assign(std::move(value), salt, ts, pk, sig);
            }
        } // anonymous namespace

//        void communication::request_signal(const dht::public_key &peer) {
//            dht::public_key pubkey = *m_ses.pubkey();
//
//            // salt is x pubkey when request signal
//            auto salt = make_salt(pubkey);
//
//            log("INFO: Get mutable data: peer[%s], salt:[%s]", aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
//            dht_get_mutable_item(peer.bytes, salt, m_latest_item_timestamp[peer]);
//        }

        void communication::publish_signal(const dht::public_key &peer) {
//            entry data;
            dht::public_key * pk = m_ses.pubkey();
            dht::secret_key * sk = m_ses.serkey();

            // salt is y pubkey when publish signal
            auto salt = make_salt(peer);
            online_signal onlineSignal = make_signal(peer);

            log("INFO: Publish online signal: peer[%s], salt[%s], online signal[%s]", aux::toHex(pk->bytes).c_str(),
                aux::toHex(salt).c_str(), onlineSignal.to_string().c_str());

            dht_put_mutable_item(pk->bytes, std::bind(&put_mutable_data, _1, _2, _3, _4
                    , pk->bytes, sk->bytes, onlineSignal.get_entry()), salt, peer);
        }

        void communication::send_to(const dht::public_key &peer, const entry &data) {
            dht::public_key * pk = m_ses.pubkey();
            dht::secret_key * sk = m_ses.serkey();

            // salt is y pubkey when publish signal
            auto salt = make_salt(peer);

            log("INFO: Send to peer[%s], salt[%s], data[%s]", aux::toHex(pk->bytes).c_str(),
                aux::toHex(salt).c_str(), data.to_string().c_str());

            dht_put_mutable_item(pk->bytes, std::bind(&put_mutable_data, _1, _2, _3, _4
                    , pk->bytes, sk->bytes, data), salt, peer);
        }

//        void communication::dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target)
//        {
//            if (!m_ses.dht()) return;
//            log("INFO: Put immutable item target[%s], entries[%zu], data[%s]",
//                aux::toHex(target.to_string()).c_str(), eps.size(), data.to_string().c_str());
//
//            m_ses.dht()->put_item(data,  eps, std::bind(&on_dht_put_immutable_item, std::ref(m_ses.alerts())
//                    , target, _1));
//        }

        void communication::dht_put_mutable_item(std::array<char, 32> key
                , std::function<void(entry&, std::array<char,64>&
                , std::int64_t&, std::string const&)> cb
                , std::string salt, const dht::public_key &peer)
        {
            if (!m_ses.dht()) return;
            m_ses.dht()->put_item(dht::public_key(key.data())
                    , std::bind(&on_dht_put_mutable_item, std::ref(m_ses.alerts()), _1, _2)
                    , std::bind(&put_mutable_callback, _1, std::move(cb)), salt, peer);
        }


        bool communication::should_log() const
        {
            return m_ses.alerts().should_post<communication_log_alert>();
        }

        TORRENT_FORMAT(2,3)
        void communication::log(char const* fmt, ...) const noexcept try
        {
#ifndef TORRENT_DISABLE_LOGGING
            if (!should_log()) return;

            va_list v;
            va_start(v, fmt);
            m_ses.alerts().emplace_alert<communication_log_alert>(fmt, v);
            va_end(v);
#endif
        }
        catch (std::exception const&) {}

    }
}
