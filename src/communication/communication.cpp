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
#include "libTAU/communication/mutable_data_wrapper.hpp"
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

            m_refresh_timer.expires_after(seconds(m_refresh_time));
            m_refresh_timer.async_wait(std::bind(&communication::refresh_timeout, self(), _1));

            return true;
        }

        bool communication::stop()
        {
//            m_refresh_timer.cancel();
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
                aux::bytes my_pk(pk->bytes.begin(), pk->bytes.end());
                m_friends.push_back(my_pk);

                log("INFO: friend size: %zu", m_friends.size());
                for (auto const & peer: m_friends) {
                    log("INFO: friend: %s", aux::toHex(peer).c_str());
                    aux::bytes encode = m_message_db->get_latest_message_hash_list_encode(std::make_pair(my_pk, peer));

                    if (!encode.empty()) {
                        message_hash_list hashList(encode);
                        for (auto const &hash: hashList.hash_list()) {
                            message msg = m_message_db->get_message(hash);
                            if (!msg.empty()) {
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
            m_message_list_map.clear();
            m_chatting_friend = std::make_pair(aux::bytes(), 0);
            m_active_friends.clear();
            m_last_seen.clear();
            m_latest_signal_time.clear();
        }

        void communication::account_changed() {
            try {
                // 账户发生改变，模块重新启动
//                stop();
//                start();

                clear();
                init();
            } catch (std::exception &e) {
                log("Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            }
        }

        void communication::set_loop_time_interval(int milliseconds) {
            m_refresh_time = milliseconds;
        }

        bool communication::add_new_friend(const aux::bytes& pubkey) {
            if (pubkey.empty()) {
                log("ERROR: Public key is empty.");
                return false;
            }

            log("INFO: Add new friend, public key %s.", aux::toHex(pubkey).c_str());

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

        bool communication::delete_friend(const aux::bytes& pubkey) {
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
            aux::bytes my_pk;
            my_pk.insert(my_pk.end(), pk->bytes.begin(), pk->bytes.end());

            if (!m_message_db->delete_friend_info(std::make_pair(my_pk, pubkey))) {
                log("ERROR: Delete friend info failed!");
                return false;
            }

            if (!m_message_db->delete_latest_message_hash_list_encode(std::make_pair(my_pk, pubkey))) {
                log("ERROR: Delete friend message hash list encode failed!");
                return false;
            }

            return true;
        }

        aux::bytes communication::get_friend_info(const aux::bytes& pubkey) {
            const auto &pk = m_ses.pubkey();
            aux::bytes my_pk;
            my_pk.insert(my_pk.end(), pk->bytes.begin(), pk->bytes.end());
            return m_message_db->get_friend_info(std::make_pair(my_pk, pubkey));
        }

        bool communication::update_friend_info(const aux::bytes& pubkey, aux::bytes friend_info) {
            const auto &pk = m_ses.pubkey();
            aux::bytes my_pk;
            my_pk.insert(my_pk.end(), pk->bytes.begin(), pk->bytes.end());
            return m_message_db->save_friend_info(std::make_pair(my_pk, pubkey), std::move(friend_info));
        }

        void communication::set_chatting_friend(aux::bytes chatting_friend) {
            m_chatting_friend = std::make_pair(std::move(chatting_friend), time(nullptr));
        }

        void communication::unset_chatting_friend() {
            m_chatting_friend = std::make_pair(aux::bytes(), 0);
        }

        void communication::set_active_friends(std::vector<aux::bytes> active_friends) {
            m_active_friends = std::move(active_friends);
        }

        bool communication::add_new_message(const message& msg) {
            if (!validate_message(msg))
                return false;

            return try_to_update_Latest_message_list(msg.sender(), msg);
        }

        bool communication::validate_message(const message& msg) {
            if (msg.rlp().size() > 1000) {
                log("ERROR: Message is oversize!");
                return false;
            }

            return true;
        }

        aux::bytes communication::select_friend_randomly() {
            aux::bytes peer;

            if (!m_friends.empty())
            {
                // 产生随机数
                srand((unsigned)time(nullptr));
                auto index = rand() % 10;

                // 检查chatting friend设置时间，如果超过30分钟，则重置
                if (time(nullptr) - m_chatting_friend.second > communication_max_chatting_time) {
                    unset_chatting_friend();
                }

                // chatting friend有80%的概率选中
                if (!m_chatting_friend.first.empty() && index < 8) {
                    peer = m_chatting_friend.first;
                } else {
                    // 以上一次产生的随机数和时间的和作为种子，产生新的随机数，避免时钟太快，产生的随机数一样的情况
                    srand((unsigned)time(nullptr) + index);
                    index = rand() % 10;

                    // active friends有70%的概率选中
                    if (!m_active_friends.empty() && index < 7) {
                        srand((unsigned)time(nullptr) + index);
                        index = rand() % m_active_friends.size();
                        peer = m_active_friends[index];
                    } else {
                        // 筛选剩余的朋友
                        std::vector<aux::bytes> other_friends = m_friends;
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
                            srand((unsigned)time(nullptr) + index);
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
            try {
                if (!m_stop) {
                    // 随机挑选一个朋友put/get
                    aux::bytes peer = select_friend_randomly();
                    if (!peer.empty()) {
                        log("INFO: Select peer:%s", aux::toHex(peer).c_str());
                        request_signal(peer);
                        publish_signal(peer);
                    }

                    m_refresh_timer.expires_after(seconds(m_refresh_time));
                    m_refresh_timer.async_wait(
                            std::bind(&communication::refresh_timeout, self(), _1));
                }
            } catch (std::exception &e) {
                log("Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            }
        }

        void communication::save_friend_latest_message_hash_list(const aux::bytes& peer) {
            auto message_list = m_message_list_map.at(peer);
            if (!message_list.empty()) {
                std::vector<aux::bytes> hash_list;
                for (const auto & msg: message_list) {
                    char *p = msg.sha256().data();
                    aux::bytes hash;
                    hash.insert(hash.end(), p, p + strlen(p));
                    hash_list.push_back(hash);
                }

                const auto &pubkey = m_ses.pubkey();
                aux::bytes public_key;
                public_key.insert(public_key.end(), pubkey->bytes.begin(), pubkey->bytes.end());
                // TODO::sqlite or leveldb?
                m_message_db->save_latest_message_hash_list_encode(std::make_pair(public_key, peer),
                                                                   message_hash_list(hash_list).rlp());
            }
        }

        bool communication::try_to_update_Latest_message_list(const aux::bytes &peer, const message& msg) {
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
                        long diff = reference.timestamp() - msg.timestamp();
                        // 如果差值小于零，说明找到了比当前消息时间戳小的消息位置，将消息插入到目标位置后面一位
                        if (diff < 0) {
                            updated = true;
                            insertFirst = false;
                            message_list.insert((++it).base(), msg);
                            break;
                        } else if (diff == 0) {
                            // 如果时间戳一样，寻找第一个哈希比我小的消息
                            auto reference_hash = reference.sha256();
                            auto msg_hash = msg.sha256();
                            if (reference_hash != msg_hash) {
                                // 寻找第一个哈希比我小的消息，插入其前面，否则，继续往前找
                                if (reference_hash < msg_hash) {
                                    updated = true;
                                    insertFirst = false;
                                    message_list.insert((++it).base(), msg);
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
            int optCode(int swap, int insert, int del) {
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
                missing_messages.insert(missing_messages.end(), messages.begin(), messages.end());
                return;
            }

            if (!messages.empty()) {
                auto size = messages.size();
                // 对方数组为source
                const aux::bytes& source = hash_prefix_array;
                // 本地消息数组为target
                aux::bytes target(size);
                for (auto const &message: messages) {
                    target.push_back(message.sha256()[0]);
                }

                auto sourceLength = source.size();
                auto targetLength = size;

                // 如果source和target一样，则直接跳过Levenshtein数组匹配计算
                if (source == target) {
                    for (auto const &message: messages) {
                        confirmation_roots.push_back(message.sha256());
                    }
                    return;
                }

                // 状态转移矩阵
                int dist[sourceLength + 1][targetLength + 1];
                // 操作矩阵
                int operations[sourceLength + 1][targetLength + 1];

                // 初始化，[i, 0]转换到空，需要编辑的距离，也即删除的数量
                for (int i = 0; i < sourceLength + 1; i++) {
                    dist[i][0] = i;
                    if (i > 0) {
                        operations[i][0] = 2;
                    }
                }

                // 初始化，空转换到[0, j]，需要编辑的距离，也即增加的数量
                for (int j = 0; j < targetLength + 1; j++) {
                    dist[0][j] = j;
                    if (j > 0) {
                        operations[0][j] = 1;
                    }
                }

                // 开始填充状态转移矩阵，第0位为空，所以从1开始有数据，[i, j]为当前子串最小编辑操作
                for (int i = 1; i < sourceLength + 1; i++) {
                    for (int j = 1; j < targetLength + 1; j++) {
                        // 第i个数据，实际的index需要i-1，替换的代价，相同无需替换，代价为0，不同代价为1
                        int cost = source[i - 1] == target[j - 1] ? 0 : 1;
                        // [i, j]在[i, j-1]的基础上，最小的编辑操作为增加1
                        int insert = dist[i][j - 1] + 1;
                        // [i, j]在[i-1, j]的基础上，最小的编辑操作为删除1
                        int del = dist[i - 1][j] + 1;
                        // [i, j]在[i-1, j-1]的基础上，最大的编辑操作为1次替换
                        int swap = dist[i - 1][j - 1] + cost;

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
                            confirmation_roots.push_back(messages[j - 1].sha256());
                        }
                        i--;
                        j--;
                    } else if (1 == operations[i][j]) {
                        // 如果是插入操作，则将target对应的插入消息加入列表
                        // 如果缺最后一个，并且此时双方满载，则判定为被挤出去的
                        if (targetLength != j || targetLength != communication_max_message_list_size ||
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
                    confirmation_roots.push_back(messages[j - 1].sha256());
                }

                // reverse missing messages
//                std::reverse(missing_messages.begin(), missing_messages.end());
            }
        }

        std::string communication::make_salt(aux::bytes peer) {
            std::string salt(peer.begin(), peer.begin() + communication_salt_length);

            return salt;
        }

        std::string communication::make_sender_salt(aux::bytes peer) {
            dht::public_key *pubkey = m_ses.pubkey();
            std::string salt;

            // sender channel salt由我和对方的public key各取前4个字节，拼接而成
            salt.insert(salt.end(), pubkey->bytes.begin(), pubkey->bytes.begin() + communication_short_address_length);
            salt.insert(salt.end(), peer.begin(), peer.begin() + communication_short_address_length);

            return salt;
        }

        std::string communication::make_receiver_salt(aux::bytes peer) {
            dht::public_key *pubkey = m_ses.pubkey();
            std::string salt;

            // receiver channel salt由对方和我的public key各取前4个字节，拼接而成
            salt.insert(salt.end(), peer.begin(), peer.begin() + communication_short_address_length);
            salt.insert(salt.end(), pubkey->bytes.begin(), pubkey->bytes.begin() + communication_short_address_length);

            return salt;
        }

        online_signal communication::make_online_signal() {
            dht::public_key * pk = m_ses.pubkey();
            aux::bytes public_key;
            public_key.insert(public_key.end(), pk->bytes.begin(), pk->bytes.end());

            time_t now_time = time(nullptr);

            // 随机挑选一个朋友发送其信息
            srand(now_time);
            auto index = rand() % m_friends.size();
            auto peer = m_friends[index];
            log("INFO: Take friend %s", aux::toHex(peer).c_str());
            aux::bytes friend_info = m_message_db->get_friend_info(std::make_pair(public_key, peer));

            // 构造Levenshtein数组，按顺序取每条信息哈希的第一个字节
            aux::bytes hash_prefix_bytes;
            auto message_list = m_message_list_map[public_key];
            if (!message_list.empty()) {
                for (const auto & msg: message_list) {
                    hash_prefix_bytes.push_back(msg.sha256()[0]);
                }
            }

            immutable_data_info payload;
            auto it = m_missing_messages[public_key].begin();
            if (it != m_missing_messages[public_key].end()) {
                log("INFO: Peer[%s] has no missing messages", aux::toHex(public_key).c_str());
                message missing_message = *it;
                m_missing_messages[public_key].erase(it);

                if (!missing_message.empty()) {
                    // post syncing message hash
                    m_ses.alerts().emplace_alert<communication_syncing_message_alert>(public_key, missing_message.sha256());

                    std::vector<dht::node_entry> entries;
                    m_ses.dht()->find_live_nodes(missing_message.sha256(), entries);
                    auto msg_encode = missing_message.rlp();
                    dht_put_immutable_item(std::string(msg_encode.begin(), msg_encode.end()),
                                           entries, missing_message.sha256());

                    payload = immutable_data_info(missing_message.sha256(), entries);
                } else {
                    log("INFO: Missing message is empty.");
                }
            }

            log("----------------------------online signal-----------------------------------------");

            return online_signal(m_device_id, hash_prefix_bytes, now_time, friend_info, payload);
        }

        new_msg_signal communication::make_new_message_signal(const aux::bytes& peer) {
            time_t now_time = time(nullptr);

            // 构造Levenshtein数组，按顺序取每条信息哈希的第一个字节
            aux::bytes hash_prefix_bytes;
            auto message_list = m_message_list_map[peer];
            if (!message_list.empty()) {
                for (const auto & msg: message_list) {
                    hash_prefix_bytes.push_back(msg.sha256()[0]);
                }
            }

            immutable_data_info payload;
            auto it = m_missing_messages[peer].begin();
            if (it != m_missing_messages[peer].end()) {
                log("INFO: Peer[%s] has no missing messages", aux::toHex(peer).c_str());
                message missing_message = *it;
                m_missing_messages[peer].erase(it);

                if (!missing_message.empty()) {
                    // post syncing message hash
                    m_ses.alerts().emplace_alert<communication_syncing_message_alert>(peer, missing_message.sha256());

                    std::vector<dht::node_entry> entries;
                    m_ses.dht()->find_live_nodes(missing_message.sha256(), entries);
                    auto msg_encode = missing_message.rlp();
                    dht_put_immutable_item(std::string(msg_encode.begin(), msg_encode.end()),
                                           entries, missing_message.sha256());

                    payload = immutable_data_info(missing_message.sha256(), entries);
                } else {
                    log("INFO: Missing message is empty.");
                }
            }

            return new_msg_signal(m_device_id, hash_prefix_bytes, now_time, payload);
        }

        // callback for dht_immutable_get
        void communication::get_immutable_callback(sha256_hash target
                , dht::item const& i)
        {
            TORRENT_ASSERT(!i.is_mutable());
            if (!i.empty()) {
                aux::bytes encode;
                encode.insert(encode.end(), i.value().string().begin(), i.value().string().end());
                message msg(encode);

                add_new_message(msg);
            }
        }

        void communication::dht_get_immutable_item(sha256_hash const& target, std::vector<dht::node_entry> const& eps)
        {
            if (!m_ses.dht()) return;
            m_ses.dht()->get_item(target, std::bind(&communication::get_immutable_callback
                    , this, target, _1));
        }

        // callback for dht_mutable_get
        void communication::get_mutable_callback(dht::item const& i
                , bool const authoritative)
        {
            TORRENT_ASSERT(i.is_mutable());

            // construct mutable data wrapper from entry
            if (!i.empty()) {
//                aux::vector_ref<aux::ibyte> ref((std::string &) i.value().string());
                aux::bytes wrapper_rlp;
                wrapper_rlp.insert(wrapper_rlp.end(), i.value().string().begin(), i.value().string().end());
                mutable_data_wrapper data(wrapper_rlp);

                auto now_time = time(nullptr);
                // 验证mutable数据的时间戳，只接受当前时间前后6小时以内的数据
                if ((data.timestamp() + communication_data_accepted_time < now_time) ||
                    (data.timestamp() - communication_data_accepted_time > now_time)) {
                    log("INFO: Mutable data wrapper timestamp mismatch!");
                    return;
                }

                aux::bytes peer;
                peer.insert(peer.end(), i.pk().bytes.begin(), i.pk().bytes.end());

                // record latest timestamp
                if (data.timestamp() > m_last_seen[peer]) {
                    m_last_seen[peer] = data.timestamp();
                    // 通知用户新的last seen time
                    m_ses.alerts().emplace_alert<communication_last_seen_alert>(peer, data.timestamp());
                }

                switch (data.type()) {
                    case ONLINE_SIGNAL: {
                        online_signal onlineSignal(data.payload());

                        auto device_id = onlineSignal.device_id();
                        auto device_map = m_latest_signal_time[peer];
                        log("INFO: Online signal time:%d", onlineSignal.timestamp());
                        // 检查相应设备信号的时间戳，只处理最新的数据
                        if (onlineSignal.timestamp() > device_map[device_id]) {
                            // update the latest signal time
                            device_map[device_id] = onlineSignal.timestamp();

                            if (onlineSignal.device_id() != m_device_id) {
                                // 通知用户新的device id
                                m_ses.alerts().emplace_alert<communication_new_device_id_alert>(
                                        onlineSignal.device_id());
                                log("INFO: Found new device id: %s", aux::toHex(onlineSignal.device_id()).c_str());

                                if (!onlineSignal.friend_info().empty()) {
                                    // 通知用户新的friend info
                                    m_ses.alerts().emplace_alert<communication_friend_info_alert>(peer,
                                            onlineSignal.friend_info());
                                    log("INFO: Got friend info:%s", aux::toHex(onlineSignal.friend_info()).c_str());
                                }

                                // get immutable message
                                const immutable_data_info& payload = onlineSignal.payload();
                                if (!payload.target().is_all_zeros()) {
                                    dht_get_immutable_item(payload.target(), payload.entries());
                                }

                                // find out missing messages and confirmation root
                                std::vector<message> missing_messages;
                                std::vector<sha256_hash> confirmation_roots;
                                find_best_solution(std::vector<message>(m_message_list_map[peer].begin(),
                                                               m_message_list_map[peer].end()),
                                                   onlineSignal.hash_prefix_bytes(),
                                                   missing_messages, confirmation_roots);

                                if (!confirmation_roots.empty()) {
                                    m_ses.alerts().emplace_alert<communication_confirmation_root_alert>(peer, confirmation_roots);
                                }

                                m_missing_messages[peer].insert(missing_messages.begin(), missing_messages.end());
                            }
                        }

                        break;
                    }
                    case NEW_MSG_SIGNAL: {
                        new_msg_signal newMsgSignal(data.payload());

                        auto device_id = newMsgSignal.device_id();
                        auto device_map = m_latest_signal_time[peer];
                        // 检查相应设备信号的时间戳，只处理最新的数据
                        if (newMsgSignal.timestamp() > device_map[device_id]) {
                            // update the latest signal time
                            device_map[device_id] = newMsgSignal.timestamp();
                        }

                        // get immutable message
                        const immutable_data_info& payload = newMsgSignal.payload();
                        if (!payload.target().is_all_zeros()) {
                            dht_get_immutable_item(payload.target(), payload.entries());
                        }

                        // find out missing messages and confirmation root
                        std::vector<message> missing_messages;
                        std::vector<sha256_hash> confirmation_roots;
                        find_best_solution(std::vector<message>(m_message_list_map[peer].begin(),
                                                                m_message_list_map[peer].end()),
                                           newMsgSignal.hash_prefix_bytes(),
                                           missing_messages, confirmation_roots);

                        if (!confirmation_roots.empty()) {
                            m_ses.alerts().emplace_alert<communication_confirmation_root_alert>(peer, confirmation_roots);
                        }

                        m_missing_messages[peer].insert(missing_messages.begin(), missing_messages.end());

                        break;
                    }
                    default: {
                        // mismatch
                        ;
                    }
                }
            }
        }

        // key is a 32-byte binary string, the public key to look up.
        // the salt is optional
        void communication::dht_get_mutable_item(std::array<char, 32> key
                , std::string salt)
        {
            if (!m_ses.dht()) return;
            m_ses.dht()->get_item(dht::public_key(key.data()), std::bind(&communication::get_mutable_callback
                    , this, _1, _2), std::move(salt));
        }

        namespace {

            void on_dht_put_immutable_item(aux::alert_manager& alerts, sha256_hash target, int num)
            {
            }

            void put_mutable_data(entry& e, std::array<char, 64>& sig
                    , std::int64_t& seq
                    , std::string const& salt
                    , std::array<char, 32> const& pk
                    , std::array<char, 64> const& sk
                    , std::string const& data)
            {
                using lt::dht::sign_mutable_item;

                e = data;
                std::vector<char> buf;
                // bencode要发布的mutable data
                bencode(std::back_inserter(buf), e);
                dht::signature sign;
                // 递增seq
                ++seq;
                // 对编码完成之后的数据(data + salt + seq)进行签名
                sign = sign_mutable_item(buf, salt, dht::sequence_number(seq)
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
                dht::sequence_number seq = i.seq();
                std::string salt = i.salt();
                // 提取item信息，交给cb处理
                cb(value, sig.bytes, seq.value, salt);
                // 使用新生成的item信息替换旧的item
                i.assign(std::move(value), salt, seq, pk, sig);
            }
        } // anonymous namespace

        void communication::request_signal(const aux::bytes &peer) {
            auto salt = make_salt(peer);

            std::array<char, 32> pk{};
            std::copy(peer.begin(), peer.end(), pk.begin());
            dht_get_mutable_item(pk, salt);
        }

        void communication::publish_signal(const aux::bytes &peer) {
            std::string data;
            dht::public_key * pk = m_ses.pubkey();
            dht::secret_key * sk = m_ses.serkey();

            auto salt = make_salt(peer);

            aux::bytes public_key(pk->bytes.begin(), pk->bytes.end());

            // check if peer is myself
            if (peer == public_key) {
                // publish online signal on XX channel
                online_signal onlineSignal = make_online_signal();
                mutable_data_wrapper wrapper(time(nullptr), ONLINE_SIGNAL, onlineSignal.rlp());
                log("-----size:%zu", wrapper.rlp().size());
                data = aux::asString(wrapper.rlp());
            } else {
                // publish new message signal on XY channel
                new_msg_signal newMsgSignal = make_new_message_signal(peer);
                mutable_data_wrapper wrapper(time(nullptr), NEW_MSG_SIGNAL, newMsgSignal.rlp());
                data = aux::asString(wrapper.rlp());
            }

            dht_put_mutable_item(pk->bytes, std::bind(&put_mutable_data, _1, _2, _3, _4
                    , pk->bytes, sk->bytes, data), salt);
        }

        void communication::dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target)
        {
            if (!m_ses.dht()) return;
            m_ses.dht()->put_item(data,  eps, std::bind(&on_dht_put_immutable_item, std::ref(m_ses.alerts())
                    , target, _1));
        }

        void communication::dht_put_mutable_item(std::array<char, 32> key
                , std::function<void(entry&, std::array<char,64>&
                , std::int64_t&, std::string const&)> cb
                , std::string salt)
        {
            if (!m_ses.dht()) return;
            m_ses.dht()->put_item(dht::public_key(key.data())
                    , std::bind(&on_dht_put_mutable_item, std::ref(m_ses.alerts()), _1, _2)
                    , std::bind(&put_mutable_callback, _1, std::move(cb)), salt);
        }


#ifndef TORRENT_DISABLE_LOGGING
        bool communication::should_log() const
        {
            return m_ses.alerts().should_post<communication_log_alert>();
        }

        TORRENT_FORMAT(2,3)
        void communication::log(char const* fmt, ...) const noexcept try
        {
            if (!should_log()) return;

            va_list v;
            va_start(v, fmt);
            m_ses.alerts().emplace_alert<communication_log_alert>(fmt, v);
            va_end(v);
        }
        catch (std::exception const&) {}
#endif

    }
}
