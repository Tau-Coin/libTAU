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

//            m_stop = false;

//            m_refresh_timer.expires_after(milliseconds(100));
//            m_refresh_timer.async_wait(std::bind(&communication::refresh_timeout, self(), _1));

            return true;
        }

        bool communication::stop()
        {
//            m_stop = true;
//
//            m_refresh_timer.cancel();

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

//                for (auto const & peer: m_friends) {
//                    log(LOG_INFO, "INFO: friend: %s", aux::toHex(peer.bytes).c_str());
//                    std::string encode = m_message_db->get_latest_message_hash_list_encode(std::make_pair(*pk, peer));
//
//                    if (!encode.empty()) {
//                        message_hash_list hashList(encode);
//                        log(LOG_INFO, "INFO: %s from peer[%s]", hashList.to_string().c_str(), aux::toHex(peer.bytes).c_str());
//                        for (auto const &hash: hashList.hash_list()) {
//                            log(LOG_INFO, "INFO: Get message hash:%s", aux::toHex(hash).c_str());
//                            message msg = m_message_db->get_message(hash);
//                            if (!msg.empty()) {
//                                log(LOG_INFO, "INFO: Got message from db[%s]", msg.to_string().c_str());
//                                m_message_list_map[peer].push_back(msg);
//                            } else {
//                                log(LOG_INFO, "INFO: Cannot find message[%s] in db.", aux::toHex(hash).c_str());
//                            }
//                        }
//                    } else {
//                        log(LOG_INFO, "INFO: Message hash list is empty.");
//                    }
//                }
            } catch (std::exception &e) {
                log(LOG_ERR, "Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
                return false;
            }

            return true;
        }

        void communication::clear() {
            m_friends.clear();
//            m_message_list_map.clear();
        }

        void communication::account_changed() {
            try {
                log(LOG_INFO, "INFO: Change account.");
                // 账户发生改变，模块重新启动
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

//        void communication::process_payload(const dht::public_key &peer, std::int64_t data_type_id, const entry &payload, bool is_cache) {
//            auto now = get_current_time();
//
//            log(LOG_INFO, "---------------Got entry[%s] from peer[%s]", payload.to_string().c_str(), aux::toHex(peer.bytes).c_str());
//            switch (data_type_id) {
//                case common::message_entry::data_type_id: {
//
//                    m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, now);
//
//                    common::message_entry msg_entry(payload);
//                    log(LOG_INFO, "INFO: Got message, hash[%s].",
//                        aux::toHex(msg_entry.m_msg.sha1().to_string()).c_str());
//
//                    add_new_message(peer, msg_entry.m_msg, true);
//
//                    // find out missing messages and confirmation root
//                    std::vector<message> missing_messages;
//                    std::vector<sha1_hash> confirmation_roots;
//                    auto &message_list = m_message_list_map[peer];
//                    std::vector<message> messages(message_list.begin(), message_list.end());
//                    log(LOG_INFO, "INFO: Messages size:%" PRIu64, messages.size());
//                    find_best_solution(messages, msg_entry.m_levenshtein_array,
//                                       missing_messages, confirmation_roots);
//
//                    if (!confirmation_roots.empty()) {
//                        m_ses.alerts().emplace_alert<communication_confirmation_root_alert>(peer,
//                                                                                            confirmation_roots,
//                                                                                            now);
//                        log(LOG_INFO, "INFO: Confirmation roots:%" PRIu64, confirmation_roots.size());
//                    }
//
//                    aux::bytes levenshtein_array;
//                    auto &msg_list = m_message_list_map[peer];
//                    for (auto const &msg: msg_list) {
//                        levenshtein_array.push_back(msg.sha1()[0]);
//                    }
//
//                    auto size = missing_messages.size();
//                    for(auto k = 0; k < size; k++) {
//                        common::message_entry messageEntry(missing_messages[k], levenshtein_array, get_current_time());
//                        send_to(peer, messageEntry.get_entry());
//                    }
//
//                    common::message_levenshtein_array_entry msg_levenshtein_array(levenshtein_array, now);
//                    send_to(peer, msg_levenshtein_array.get_entry());
//
//
//                    break;
//                }
//                case common::message_levenshtein_array_entry::data_type_id: {
//
//                    m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, now);
//
//                    common::message_levenshtein_array_entry levenshtein_array_entry(payload);
//                    log(LOG_INFO, "INFO: Got message levenshtein array[%s].",
//                        aux::toHex(levenshtein_array_entry.m_levenshtein_array).c_str());
//
//                    // find out missing messages and confirmation root
//                    std::vector<message> missing_messages;
//                    std::vector<sha1_hash> confirmation_roots;
//                    auto &message_list = m_message_list_map[peer];
//                    std::vector<message> messages(message_list.begin(), message_list.end());
//                    log(LOG_INFO, "INFO: Messages size:%" PRIu64, messages.size());
//                    find_best_solution(messages, levenshtein_array_entry.m_levenshtein_array,
//                                       missing_messages, confirmation_roots);
//
//                    if (!confirmation_roots.empty()) {
//                        m_ses.alerts().emplace_alert<communication_confirmation_root_alert>(peer,
//                                                                                            confirmation_roots,
//                                                                                            now);
//                        log(LOG_INFO, "INFO: Confirmation roots:%" PRIu64, confirmation_roots.size());
//                    }
//
//                    log(LOG_INFO, "INFO: Found missing message size %" PRIu64, missing_messages.size());
//                    aux::bytes levenshtein_array;
//                    auto &msg_list = m_message_list_map[peer];
//                    for (auto const &msg: msg_list) {
//                        levenshtein_array.push_back(msg.sha1()[0]);
//                    }
//
//                    auto size = missing_messages.size();
//                    for(auto k = 0; k < size; k++) {
//                        common::message_entry msg_entry(missing_messages[k], levenshtein_array, get_current_time());
//                        send_to(peer, msg_entry.get_entry());
//                    }
//
//                    break;
//                }
//                case common::event_entry::data_type_id: {
//
//                    m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, now);
//
//                    common::event_entry eventEntry(payload);
//
//                    // 通知用户新的user event
//                    m_ses.alerts().emplace_alert<communication_user_event_alert>(peer, eventEntry.m_value);
//
//                    break;
//                }
//                default: {
//                }
//            }
//
//        }

        void communication::on_dht_relay(dht::public_key const& peer, entry const& payload) {
//            if(payload.type() != entry::dictionary_t){
//                log(LOG_ERR, "ERROR: relay data not dict. to string: %s", payload.to_string().c_str());
//                return;
//            }

            // construct mutable data wrapper from entry
            try {
                common::signal_entry signalEntry(payload);

                log(LOG_INFO, "INFO: Got signal[%s] from peer[%s]",
                    payload.to_string(true).c_str(), aux::toHex(peer.bytes).c_str());

                switch (signalEntry.m_pid) {
                    case common::COMMUNICATION_NEW_MESSAGE: {
                        m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, signalEntry.m_timestamp);

                        auto new_msg_hash = signalEntry.m_hash;
                        if (!new_msg_hash.is_all_zeros()) {
                            if (!m_message_db->is_message_in_db(new_msg_hash)) {
                                get_message_wrapper(peer, new_msg_hash);
                            }
                        }

//                        get_new_message_hash(peer, signalEntry.m_timestamp - 3);
                        break;
                    }
                    case common::COMMUNICATION_MESSAGE_MISSING: {
                        m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, signalEntry.m_timestamp);

                        put_all_messages(peer);
                        break;
                    }
                    case common::COMMUNICATION_PUT_DONE: {
                        m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, signalEntry.m_timestamp);

                        get_new_message_hash(peer, signalEntry.m_timestamp - 3);
                        break;
                    }
                    case common::COMMUNICATION_CONFIRMATION: {
                        m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, signalEntry.m_timestamp);

                        get_confirmation_roots(peer, signalEntry.m_hash);
                        break;
                    }
                    case common::COMMUNICATION_ATTENTION: {
                        m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, signalEntry.m_timestamp);

                        // 通知用户新的attention
                        m_ses.alerts().emplace_alert<communication_peer_attention_alert>(peer, signalEntry.m_timestamp);
                        break;
                    }
                    default: {
                    }
                }
//                // data type id
//                if (auto* i = const_cast<entry *>(payload.find_key(common::entry_type))) {
//                    auto data_type_id = i->integer();
//                    process_payload(peer, data_type_id, payload, false);
//                }
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
            std::string salt = std::string(key.begin(), key.end());

            log(LOG_INFO, "INFO: Get user info from peer[%s], salt:[%s]",
                aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
            subscribe(peer, salt, COMMUNICATION_GET_ITEM_TYPE::USER_INFO, 0);
        }

//        void communication::send_to_peer(const dht::public_key &peer, const aux::bytes& data) {
//            common::event_entry eventEntry(data, get_current_time());
//            send_to(peer, eventEntry.get_entry());
//        }

        void communication::pay_attention_to_peer(const dht::public_key &peer) {
            common::signal_entry signalEntry(common::COMMUNICATION_ATTENTION, get_current_time() / 1000);
            auto e = signalEntry.get_entry();
            log(LOG_INFO, "Send peer[%s] attention signal[%s]",
                aux::toHex(peer.bytes).c_str(), e.to_string(true).c_str());
            send_to(peer, e);
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

            return true;
        }

        bool communication::add_new_message(const message &msg, bool post_alert) {
            if (!m_message_db->save_message_if_not_exist(msg)) {
                log(LOG_ERR, "ERROR: Save message[%s] fail!", msg.to_string().c_str());
            }

            put_new_message(msg);
//            add_new_message(msg.receiver(), msg, post_alert);
//
//            aux::bytes levenshtein_array;
//            auto& msg_list = m_message_list_map[msg.receiver()];
//            for (auto const &m: msg_list) {
//                levenshtein_array.push_back(m.sha1()[0]);
//            }
//
//            std::int64_t now = get_current_time();
//            common::message_entry msg_entry(msg, levenshtein_array, now);
//            send_to(msg.receiver(), msg_entry.get_entry());

            return true;
        }

//        bool communication::add_new_message(const dht::public_key &peer, const message& msg, bool post_alert) {
//            if (msg.empty()) {
//                log(LOG_ERR, "ERROR: Message is empty.");
//                return false;
//            }
//
//            log(LOG_INFO, "INFO: Add new msg[%s]", msg.to_string().c_str());
//
//            if (!validate_message(msg))
//                return false;
//
//            return try_to_update_Latest_message_list(peer, msg, post_alert);
//        }

        bool communication::validate_message(const message& msg) {
            // TODO: size==1000?
            if (msg.encode().size() > 1000) {
                log(LOG_ERR, "ERROR: Message is oversize!");
                return false;
            }

            return true;
        }

//        void communication::refresh_timeout(error_code const& e)
//        {
//            if ((e.value() != 0 && e.value() != boost::asio::error::operation_aborted) || m_stop) return;
//
//            try {
//                if (e.value() != boost::asio::error::operation_aborted) {
//                }
//
//                m_refresh_timer.expires_after(seconds(communication_default_refresh_time));
//                m_refresh_timer.async_wait(std::bind(&communication::refresh_timeout, self(), _1));
//            } catch (std::exception &e) {
//                log(LOG_ERR, "Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
//            }
//        }

//        void communication::save_friend_latest_message_hash_list(const dht::public_key &peer) {
//            auto message_list = m_message_list_map.at(peer);
//            if (!message_list.empty()) {
//                std::vector<sha1_hash> hash_list;
//                for (const auto & msg: message_list) {
//                    hash_list.push_back(msg.sha1());
//                }
//
//                dht::public_key pubkey = *m_ses.pubkey();
//
//                message_hash_list messageHashList(hash_list);
//                log(LOG_INFO, "INFO: Save message hash list %s", messageHashList.to_string().c_str());
//                m_message_db->save_latest_message_hash_list_encode(std::make_pair(pubkey, peer),messageHashList.encode());
//            }
//        }

//        bool communication::try_to_update_Latest_message_list(const dht::public_key &peer, const message& msg, bool post_alert) {
//            if (msg.empty())
//                return false;
//
//            bool updated = false;
//
//            std::list<message> message_list = m_message_list_map[peer];
//            if (!message_list.empty()) {
//                // 先判断一下是否比最后一个消息时间戳大，如果是，则直接插入末尾
//                if (msg.timestamp() > message_list.back().timestamp()) {
//                    message_list.push_back(msg);
//                    updated = true;
//                } else {
//                    // 寻找从后往前寻找第一个时间小于当前消息时间的消息，将当前消息插入到到该消息后面
//                    auto it = message_list.rbegin();
//                    // 是否插入第一个位置，在没找到的情况下会插入到第一个位置
//                    bool insertFirst = true;
//                    for (; it != message_list.rend(); ++it) {
//                        message reference = *it;
////                        signed long diff = reference.timestamp() - msg.timestamp();
//                        // 如果差值小于零，说明找到了比当前消息时间戳小的消息位置，将消息插入到目标位置后面一位
//                        if (reference.timestamp() < msg.timestamp()) {
//                            updated = true;
//                            insertFirst = false;
//                            message_list.insert(it.base(), msg);
//                            break;
//                        } else if (reference.timestamp() == msg.timestamp()) {
//                            // 如果时间戳一样，寻找第一个哈希比我小的消息
//                            auto reference_hash = reference.sha1();
//                            auto msg_hash = msg.sha1();
//                            if (reference_hash != msg_hash) {
//                                // 寻找第一个哈希比我小的消息，插入其前面，否则，继续往前找
//                                if (reference_hash < msg_hash) {
//                                    updated = true;
//                                    insertFirst = false;
//                                    message_list.insert(it.base(), msg);
//                                    break;
//                                }
//                            } else {
//                                // 如果哈希一样，则本身已经在列表中，也不再进行查找
//                                insertFirst = false;
//                                break;
//                            }
//                        }
//                    }
//
//                    if (insertFirst) {
//                        updated = true;
//                        message_list.insert(std::begin(message_list), msg);
//                    }
//                }
//            } else {
//                message_list.push_back(msg);
//                updated = true;
//            }
//
//            // 更新成功
//            if (updated) {
//                log(LOG_INFO, "INFO: Add message[%s] into message list", msg.to_string().c_str());
//
//                // 通知用户新的message
//                if (post_alert) {
//                    log(LOG_INFO, "DEBUG: Post new message:%s", msg.to_string().c_str());
//                    m_ses.alerts().emplace_alert<communication_new_message_alert>(msg);
//                }
//
//                // save message in db
//                if (!m_message_db->save_message(msg)) {
//                    log(LOG_ERR, "ERROR: Save message in db fail[%s]", msg.to_string().c_str());
//                    return false;
//                }
//
//                // 如果更新了消息列表，则判断是否列表长度过长，过长则删掉旧数据，然后停止循环
//                if (message_list.size() > communication_max_message_list_size) {
//                    message_list.pop_front();
//                }
//
//                m_message_list_map[peer] = message_list;
//
//                save_friend_latest_message_hash_list(peer);
//            }
//
//            return updated;
//        }

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
                                               std::vector<sha1_hash> &confirmation_roots) {
            // 如果对方没有信息，则本地消息全为缺失消息
            if (hash_prefix_array.empty()) {
                log(LOG_INFO, "INFO: Hash prefix array is empty");
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
                    target.push_back(message.sha1()[0]);
                }

                const size_t sourceLength = source.size();
                const size_t targetLength = size;

                log(LOG_INFO, "INFO: source array[%s], target array[%s]", aux::toHex(source).c_str(), aux::toHex(target).c_str());
                // 如果source和target一样，则直接跳过Levenshtein数组匹配计算
                if (source == target) {
                    for (auto const &msg: messages) {
//                        log("INFO: Confirm message hash[%s]", aux::toHex(msg.sha256().to_string()).c_str());
                        confirmation_roots.push_back(msg.sha1());
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
                            confirmation_roots.push_back(messages[j - 1].sha1());
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
                    confirmation_roots.push_back(messages[j - 1].sha1());
                }

                // reverse missing messages
//                std::reverse(missing_messages.begin(), missing_messages.end());
            }
        }

        void communication::find_best_solution(const std::vector<message> &messages, const aux::bytes &hash_prefix_array,
                                          std::vector<message> &missing_messages,
                                          std::vector<message> &confirmed_messages) {
            // 如果对方没有信息，则本地消息全为缺失消息
            if (hash_prefix_array.empty()) {
                log(LOG_INFO, "INFO: Hash prefix array is empty");
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
                    target.push_back(message.sha1()[0]);
                }

                const size_t sourceLength = source.size();
                const size_t targetLength = size;

                log(LOG_INFO, "INFO: source array[%s], target array[%s]", aux::toHex(source).c_str(), aux::toHex(target).c_str());
                // 如果source和target一样，则直接跳过Levenshtein数组匹配计算
                if (source == target) {
                    for (auto const &msg: messages) {
//                        log("INFO: Confirm message hash[%s]", aux::toHex(msg.sha256().to_string()).c_str());
                        confirmed_messages.push_back(msg);
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
                            confirmed_messages.push_back(messages[j - 1]);
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
                , bool const authoritative, COMMUNICATION_GET_ITEM_TYPE type, std::int64_t timestamp, int times)
        {
            TORRENT_ASSERT(i.is_mutable());

            if(!authoritative)
                return;

            // construct mutable data wrapper from entry
            try {
                const auto& peer = i.pk();
                const auto& salt = i.salt();
//            GET_ITEM getItem(chain_id, peer, salt, type);

                log(LOG_INFO, "=====INFO: Got callback[%s], type[%d], salt[%s], timestamp:%" PRId64,
                    i.value().to_string(true).c_str(), type, aux::toHex(i.salt()).c_str(), timestamp);

                if (!i.empty()) {
                    switch (type) {
                        case COMMUNICATION_GET_ITEM_TYPE::NEW_MESSAGE_HASH: {
                            sha1_hash new_msg_hash(i.value().string().c_str());
                            log(LOG_INFO, "INFO: Got new message hash[%s]", aux::toHex(new_msg_hash).c_str());
                            if (!new_msg_hash.is_all_zeros()) {
                                if (!m_message_db->is_message_in_db(new_msg_hash)) {
                                    get_message_wrapper(peer, new_msg_hash);
                                }
                            }

                            break;
                        }
                        case COMMUNICATION_GET_ITEM_TYPE::MESSAGE_WRAPPER: {
                            message_wrapper messageWrapper(i.value());
                            if (!messageWrapper.empty()) {
                                log(LOG_INFO, "INFO: Got new message [%s]", messageWrapper.msg().to_string().c_str());

                                m_ses.alerts().emplace_alert<communication_new_message_alert>(messageWrapper.msg());

                                if (!m_message_db->save_message_if_not_exist(messageWrapper.msg())) {
                                    log(LOG_ERR, "INFO: Save message[%s] fail.", messageWrapper.msg().to_string().c_str());
                                }

                                put_confirmation_roots(peer);

                                if (times < 10 && !messageWrapper.previousHash().is_all_zeros() && !m_message_db->is_message_in_db(messageWrapper.previousHash())) {
                                    get_message_wrapper(peer, messageWrapper.previousHash(), times + 1);
                                }
                            }

                            break;
                        }
                        case COMMUNICATION_GET_ITEM_TYPE::CONFIRMATION_ROOTS: {
                            message_hash_list messageHashList(i.value());
                            auto confirmation_roots = messageHashList.hash_list();
                            if (!confirmation_roots.empty()) {
                                m_ses.alerts().emplace_alert<communication_confirmation_root_alert>(peer,
                                                                                                    confirmation_roots,
                                                                                                    i.ts().value);
                                log(LOG_INFO, "INFO: Confirmation roots:%" PRIu64, confirmation_roots.size());
                            }

                            break;
                        }
                        case COMMUNICATION_GET_ITEM_TYPE::USER_INFO: {
                            m_ses.alerts().emplace_alert<communication_user_info_alert>(peer,
                                                                                        aux::bytes(salt.begin(), salt.end()),
                                                                                        aux::bytes(i.value().string().begin(),
                                                                                                   i.value().string().end()));
                            break;
                        }
                        default: {
                            log(LOG_DEBUG, "INFO: Unknown type.");
                        }
                    }
                } else {
                    log(LOG_INFO, "INFO: Fail to get item: type[%d], salt[%s], timestamp:%" PRId64,
                        type, aux::toHex(i.salt()).c_str(), timestamp);

                    switch (type) {
                        case COMMUNICATION_GET_ITEM_TYPE::NEW_MESSAGE_HASH:
                        case COMMUNICATION_GET_ITEM_TYPE::MESSAGE_WRAPPER: {
                            if (times == 1) {
                                get_message_wrapper(peer, sha1_hash(salt.data()), times + 1);
                            } else if (times >= 2) {
                                send_message_missing_signal(peer);
                            }

                            break;
                        }
                        case COMMUNICATION_GET_ITEM_TYPE::CONFIRMATION_ROOTS: {
                            if (times == 1) {
                                get_confirmation_roots(peer, sha1_hash(salt.data()), times + 1);
                            }
                            break;
                        }
                        case COMMUNICATION_GET_ITEM_TYPE::USER_INFO: {
                            break;
                        }
                        default: {
                            log(LOG_DEBUG, "INFO: ignored type.");
                        }
                    }

                }
            } catch (std::exception &e) {
                log(LOG_ERR, "ERROR: Exception in get mutable callback [CHAIN] %s in file[%s], func[%s], line[%d]",
                    e.what(), __FILE__, __FUNCTION__ , __LINE__);
            }
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

        void communication::on_dht_put_message_wrapper(dht::public_key const& peer, const sha1_hash &hash, const dht::item &i, int n) {
            if (n > 0) {
                m_ses.alerts().emplace_alert<communication_message_arrived_alert>(peer, hash, get_current_time() / 1000);
            }
        }

        void communication::on_dht_relay_mutable_item(const entry &payload,
                                                      const std::vector<std::pair<dht::node_entry, bool>> &nodes,
                                                      const dht::public_key &peer) {
//            // data type id
//            if (auto* i = const_cast<entry *>(payload.find_key(common::entry_type)))
//            {
//                auto data_type_id = i->integer();
//                if (data_type_id == common::message_entry::data_type_id) {
//                    for (auto const& n: nodes) {
//                        log(LOG_DEBUG, "nodes:%s, bool:%d", n.first.addr().to_string().c_str(), n.second);
//                    }
//
//                    common::message_entry msgEntry(payload);
//                    auto now = get_current_time();
//                    m_ses.alerts().emplace_alert<communication_syncing_message_alert>(peer, msgEntry.m_msg.sha1(), now);
//                    for (auto const& n: nodes) {
//                        if (n.second) {
//                            m_ses.alerts().emplace_alert<communication_message_arrived_alert>(peer,
//                                                                                              msgEntry.m_msg.sha1(), now);
//                            break;
//                        }
//                    }
//                }
//            }
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
//                // bencode要发布的mutable data
//                bencode(std::back_inserter(buf), e);
//                dht::signature sign;
//                // get unix timestamp
//                ts = libTAU::aux::utcTime();
//                // 对编码完成之后的数据(data + salt + ts)进行签名
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
//                // 提取item信息，交给cb处理
//                cb(value, sig.bytes, ts.value, salt);
//                // 使用新生成的item信息替换旧的item
//                i.assign(std::move(value), salt, ts, pk, sig);
//            }
//        } // anonymous namespace

        void communication::publish(const std::string& salt, const entry& data) {
            if (!m_ses.dht()) return;
            log(LOG_INFO, "INFO: Publish salt[%s], data[%s]", aux::toHex(salt).c_str(), data.to_string(true).c_str());
            m_ses.dht()->put_item(data, std::bind(&communication::on_dht_put_mutable_item, self(), _1, _2)
                    , 1, 8, 16, salt);
        }

        void communication::publish_message_wrapper(dht::public_key const& peer, const sha1_hash &hash, const std::string &salt, const entry &data) {
            if (!m_ses.dht()) return;
            log(LOG_INFO, "INFO: Publish message wrapper salt[%s], data[%s]", aux::toHex(salt).c_str(), data.to_string(true).c_str());
            m_ses.dht()->put_item(data, std::bind(&communication::on_dht_put_message_wrapper, self(), peer, hash, _1, _2)
                    , 1, 8, 16, salt);
        }

        void communication::subscribe(const dht::public_key &peer, const std::string &salt, COMMUNICATION_GET_ITEM_TYPE type, std::int64_t timestamp, int times) {
            if (!m_ses.dht()) return;
            m_ses.dht()->get_item(peer, std::bind(&communication::get_mutable_callback, self(), _1, _2, type, timestamp, times), 1, 8, 16, salt, timestamp);
        }

        void communication::send_to(const dht::public_key &peer, const entry &data) {
            if (!m_ses.dht()) return;
            log(LOG_INFO, "Send [%s] to peer[%s]", data.to_string(true).c_str(), aux::toHex(peer.bytes).c_str());
            m_ses.dht()->send(peer, data, 1, 8, 16, 1,
                              std::bind(&communication::on_dht_relay_mutable_item, self(), _1, _2, peer));
        }

        void communication::send_new_message_signal(const dht::public_key &peer, const sha1_hash &hash) {
            common::signal_entry signalEntry(common::COMMUNICATION_NEW_MESSAGE, get_current_time() / 1000, hash);
            auto e = signalEntry.get_entry();
            log(LOG_INFO, "Send peer[%s] new message signal[%s]",
                aux::toHex(peer.bytes).c_str(), e.to_string(true).c_str());
            send_to(peer, e);
        }

        void communication::send_message_missing_signal(const dht::public_key &peer) {
            common::signal_entry signalEntry(common::COMMUNICATION_MESSAGE_MISSING, get_current_time() / 1000);
            auto e = signalEntry.get_entry();
            log(LOG_INFO, "Send peer[%s] message missing signal[%s]",
                aux::toHex(peer.bytes).c_str(), e.to_string(true).c_str());
            send_to(peer, e);
        }

        void communication::send_put_done_signal(const dht::public_key &peer) {
            common::signal_entry signalEntry(common::COMMUNICATION_PUT_DONE, get_current_time() / 1000);
            auto e = signalEntry.get_entry();
            log(LOG_INFO, "Send peer[%s] message put done signal[%s]",
                aux::toHex(peer.bytes).c_str(), e.to_string(true).c_str());
            send_to(peer, e);
        }

        void communication::send_confirmation_signal(const dht::public_key &peer, const sha1_hash &hash) {
            common::signal_entry signalEntry(common::COMMUNICATION_CONFIRMATION, get_current_time() / 1000, hash);
            auto e = signalEntry.get_entry();
            log(LOG_INFO, "Send peer[%s] message confirmation signal[%s]",
                aux::toHex(peer.bytes).c_str(), e.to_string(true).c_str());
            send_to(peer, e);
        }

        void communication::get_new_message_hash(const dht::public_key &peer, std::int64_t timestamp) {
            // salt is x pubkey when request signal
            auto pubKey = *m_ses.pubkey();
            std::string data(pubKey.bytes.begin(), pubKey.bytes.end());
            data.insert(data.end(), key_suffix_new_message_hash.begin(), key_suffix_new_message_hash.end());
            auto salt = hasher(data).final().to_string();

            log(LOG_INFO, "INFO: Get new message hash from peer[%s], salt:[%s]",
                aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
            subscribe(peer, salt, COMMUNICATION_GET_ITEM_TYPE::NEW_MESSAGE_HASH, timestamp);
        }

        void communication::put_new_message_hash(const dht::public_key &peer, const sha1_hash &hash) {
            if (!hash.is_all_zeros()) {
                std::string data(peer.bytes.begin(), peer.bytes.end());
                data.insert(data.end(), key_suffix_new_message_hash.begin(), key_suffix_new_message_hash.end());
                auto salt = hasher(data).final().to_string();

                log(LOG_INFO, "INFO: Put new message hash salt[%s]", aux::toHex(salt).c_str());
                publish(salt, hash.to_string());
            }
        }

        void communication::get_message_wrapper(const dht::public_key &peer, const sha1_hash &hash, int times) {
            if (!hash.is_all_zeros()) {
                auto salt = hash.to_string();

                log(LOG_INFO, "INFO: Get message wrapper from peer[%s], salt:[%s]",
                    aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
                subscribe(peer, salt, COMMUNICATION_GET_ITEM_TYPE::MESSAGE_WRAPPER, 0, times);
            }
        }

        void communication::put_message_wrapper(const message_wrapper &messageWrapper) {
            if (!messageWrapper.empty()) {
                auto salt = messageWrapper.sha1().to_string();

                log(LOG_INFO, "INFO: Put message wrapper salt[%s]", aux::toHex(salt).c_str());
                publish_message_wrapper(messageWrapper.msg().receiver(), messageWrapper.msg().sha1(), salt, messageWrapper.get_entry());
            }
        }

//        void communication::get_message(const dht::public_key &peer, const sha1_hash &hash) {
//            if (!hash.is_all_zeros()) {
//                auto salt = hash.to_string();
//
//                log(LOG_INFO, "INFO: Get message from peer[%s], salt:[%s]",
//                    aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
//                subscribe(peer, salt, COMMUNICATION_GET_ITEM_TYPE::MESSAGE, 0);
//            }
//        }

        void communication::put_new_message(const message &msg) {
            auto last_message = m_message_db->get_latest_transaction(msg.sender(), msg.receiver());
            message_wrapper messageWrapper(last_message.sha1(), msg);
            put_message_wrapper(messageWrapper);
            put_new_message_hash(msg.receiver(), messageWrapper.sha1());
            send_new_message_signal(msg.receiver(), messageWrapper.sha1());
        }

        void communication::get_confirmation_roots(const dht::public_key &peer, const sha1_hash &hash, int times) {
            // salt is x pubkey when request signal
            auto salt = hash.to_string();
//            auto pubKey = *m_ses.pubkey();
//            std::string data(pubKey.bytes.begin(), pubKey.bytes.end());
//            data.insert(data.end(), key_suffix_confirmation_roots.begin(), key_suffix_confirmation_roots.end());
//            auto salt = hasher(data).final().to_string();

            log(LOG_INFO, "INFO: Get confirmation roots from peer[%s], salt:[%s], times[%d]",
                aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str(), times);
            subscribe(peer, salt, COMMUNICATION_GET_ITEM_TYPE::CONFIRMATION_ROOTS, 0, times);
        }

        void communication::put_confirmation_roots(const dht::public_key &peer) {
            auto messages = m_message_db->get_latest_ten_transactions(peer, *m_ses.pubkey());
            std::vector<sha1_hash> msgHashList;
            for (auto const& msg: messages) {
                msgHashList.push_back(msg.sha1());
            }
            message_hash_list messageHashList(msgHashList);
            auto hash = messageHashList.sha1();

            auto salt = hash.to_string();

//            std::string data(peer.bytes.begin(), peer.bytes.end());
//            data.insert(data.end(), key_suffix_confirmation_roots.begin(), key_suffix_confirmation_roots.end());
//            auto salt = hasher(data).final().to_string();

            log(LOG_INFO, "INFO: Put confirmation roots salt[%s]", aux::toHex(salt).c_str());
            publish(salt, messageHashList.get_entry());

            send_confirmation_signal(peer, hash);
        }

        void communication::put_all_messages(const dht::public_key &peer) {
            auto now = get_current_time();
            if (now < m_all_messages_last_put_time[peer] + communication_min_put_interval) {
                log(LOG_INFO, "Peer[%s] Already put it", aux::toHex(peer.bytes).c_str());
                return;
            }
            m_all_messages_last_put_time[peer] = now;

            auto messages = m_message_db->get_latest_ten_transactions(*m_ses.pubkey(), peer);
            message_wrapper lastMessageWrapper;
            message_wrapper messageWrapper;
            for (auto const& msg: messages) {
                messageWrapper = message_wrapper(lastMessageWrapper.sha1(), msg);
                put_message_wrapper(messageWrapper);

                lastMessageWrapper = messageWrapper;
            }
            put_new_message_hash(peer, messageWrapper.sha1());

            send_put_done_signal(peer);
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

//        void communication::send_all_unconfirmed_messages(const dht::public_key &peer) {
//            // find out missing messages and confirmation root
//            std::vector<message> missing_messages;
//            std::vector<sha256_hash> confirmation_roots;
//            auto &message_list = m_message_list_map[peer];
//            std::vector<message> messages(message_list.begin(), message_list.end());
//            log(LOG_INFO, "INFO: Messages size:%" PRIu64, messages.size());
//            log(LOG_INFO, "INFO: Send all msgs peer[%s] levenshtein array:%s", aux::toHex(peer.bytes).c_str(),
//                aux::toHex(m_levenshtein_array[peer]).c_str());
//            find_best_solution(messages, m_levenshtein_array[peer],
//                               missing_messages, confirmation_roots);
//
//            log(LOG_INFO, "INFO: Found missing message size %" PRIu64, missing_messages.size());
//
//            auto now = get_current_time();
//
//            aux::bytes levenshtein_array;
//            for (auto const &message: messages) {
//                levenshtein_array.push_back(message.sha256()[0]);
//            }
//
//            auto size = missing_messages.size();
//            for(auto k = 0; k < size; k++) {
//                common::message_entry msg_entry(missing_messages[k], levenshtein_array, now);
//                send_to(peer, msg_entry.get_entry());
//            }
//        }

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
