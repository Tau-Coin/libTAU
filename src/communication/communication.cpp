/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <cstdlib>
#include <utility>

#include "libTAU/communication/message_hash_list.hpp"
#include "libTAU/communication/communication.hpp"
#include "libTAU/communication/mutable_data_wrapper.hpp"
#include "libTAU/kademlia/dht_tracker.hpp"

using namespace std::placeholders;

namespace libTAU {
    namespace communication {

        bool communication::start()
        {
            log("INFO: Start Communication...");
            if (!init())
                return false;

            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(std::bind(&communication::refresh_timeout, self(), _1));
        }

        bool communication::stop()
        {
            m_friends.clear();
            m_message_list_map.clear();
            m_chatting_friend = std::make_pair(aux::bytes(), 0);
            m_active_friends.clear();
            m_last_seen.clear();
            m_latest_signal_time.clear();

            m_refresh_timer.cancel();

            log("INFO: Stop Communication...");

            return true;
        }

        bool communication::init() {
            log("INFO: Communication init...");
            if (!m_message_db->init()) {
                log("ERROR: DB init fail!");
                return false;
            }

            // get friends from db
            m_friends = m_message_db->get_all_friends();
            log("INFO: friend size: %zu", m_friends.size());
            for (auto const & peer: m_friends) {
                log("INFO: friend: %s", peer.data());
            }

            return true;
        }

        void communication::account_changed() {
            // 账户发生改变，模块重新启动
            stop();
            start();
        }

        void communication::set_loop_time_interval(int milliseconds) {
            m_refresh_time = milliseconds;
        }

        bool communication::add_new_friend(const aux::bytes& pubkey) {
            if (pubkey.empty()) {
                log("ERROR: Public key is empty.");
                return false;
            }

            log("INFO: Public key %s.", pubkey.data());

            bool update = true;
            for(auto & peer : m_friends) {
                if (peer == pubkey) {
                    update = false;
                    break;
                }
            }

            if (update) {
                m_friends.push_back(pubkey);
            }

            if (!m_message_db->save_friend(pubkey)) {
                log("ERROR: Save friend failed!");
                return false;
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

            if (!m_message_db->delete_friend_info(pubkey)) {
                log("ERROR: Delete friend info failed!");
                return false;
            }

            if (!m_message_db->delete_latest_message_hash_list_encode(pubkey)) {
                log("ERROR: Delete friend message hash list encode failed!");
                return false;
            }

            return true;
        }

        aux::bytes communication::get_friend_info(aux::bytes pubkey) {
            return m_message_db->get_friend_info(std::move(pubkey));
        }

        bool communication::update_friend_info(aux::bytes pubkey, aux::bytes friend_info) {
            return m_message_db->save_friend_info(std::move(pubkey), std::move(friend_info));
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
            // 随机挑选一个朋友put/get
            aux::bytes peer = select_friend_randomly();
            if (!peer.empty()) {
                request_signal(peer);
                publish_signal(peer);
            }
            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(
                    std::bind(&communication::refresh_timeout, self(), _1));
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

//                const auto &pubkey = m_ses.pubkey();
//                aux::bytes public_key;
//                public_key.insert(public_key.end(), pubkey->bytes.begin(), pubkey->bytes.end());
                // TODO::sqlite or leveldb?
                m_message_db->save_latest_message_hash_list_encode(peer, message_hash_list(hash_list).rlp());
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

        std::string communication::make_salt(aux::bytes peer) {
            std::string salt;
            std::copy(peer.begin(), peer.begin() + communication_salt_length, salt.begin());

            return salt;
        }

        std::string communication::make_sender_salt(aux::bytes peer) {
            dht::public_key *pubkey = m_ses.pubkey();
            std::string salt;

            // sender channel salt由我和对方的public key各取前4个字节，拼接而成
            std::copy(pubkey->bytes.begin(), pubkey->bytes.begin() + communication_short_address_length, salt.begin());
            std::copy(peer.begin(), peer.begin() + communication_short_address_length,
                      salt.begin() + communication_short_address_length);

            return salt;
        }

        std::string communication::make_receiver_salt(aux::bytes peer) {
            dht::public_key *pubkey = m_ses.pubkey();
            std::string salt;

            // receiver channel salt由对方和我的public key各取前4个字节，拼接而成
            std::copy(peer.begin(), peer.begin() + communication_short_address_length, salt.begin());
            std::copy(pubkey->bytes.begin(), pubkey->bytes.begin() + communication_short_address_length,
                      salt.begin() + communication_short_address_length);

            return salt;
        }

        online_signal communication::make_online_signal() {
            time_t now_time = time(nullptr);

            // 随机挑选一个朋友发送其信息
            srand(now_time);
            auto index = rand() % m_friends.size();
            auto peer = m_friends[index];
            aux::bytes friend_info = m_message_db->get_friend_info(peer);

            // 构造Levenshtein数组，按顺序取每条信息哈希的第一个字节
            dht::public_key * pk = m_ses.pubkey();
            aux::bytes public_key;
            public_key.insert(public_key.end(), pk->bytes.begin(), pk->bytes.end());
            aux::bytes hash_prefix_bytes;
            auto message_list = m_message_list_map[public_key];
            if (!message_list.empty()) {
                for (const auto & msg: message_list) {
                    hash_prefix_bytes.push_back(msg.sha256()[0]);
                }
            }

            return online_signal(m_device_id, hash_prefix_bytes, now_time, friend_info);
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

            return new_msg_signal(m_device_id, hash_prefix_bytes, now_time);
        }

        // callback for dht_immutable_get
        void communication::get_immutable_callback(sha1_hash target
                , dht::item const& i)
        {
//            TORRENT_ASSERT(!i.is_mutable());
//            m_ses.alerts().emplace_alert<dht_immutable_item_alert>(target, i.value());
        }

        void communication::dht_get_immutable_item(sha1_hash const& target)
        {
//            if (!m_ses.dht()) return;
//            m_ses.dht()->get_item(target, std::bind(&communication::get_immutable_callback
//                    , this, target, _1));
        }

        // callback for dht_mutable_get
        void communication::get_mutable_callback(dht::item const& i
                , bool const authoritative)
        {
            TORRENT_ASSERT(i.is_mutable());

            // construct mutable data wrapper from entry
            aux::vector_ref<aux::ibyte> ref((std::string &) i.value().string());
            mutable_data_wrapper data(ref);

            auto now_time = time(nullptr);
            // 验证mutable数据的时间戳，只接受当前时间前后6小时以内的数据
            if ((data.timestamp() + communication_data_accepted_time < now_time) ||
            (data.timestamp() - communication_data_accepted_time > now_time)) {
                log("INFO: Mutable data wrapper timestamp mismatch!");
                return;
            }

            aux::bytes public_key;
            public_key.insert(public_key.end(), i.pk().bytes.begin(), i.pk().bytes.end());

            // record latest timestamp
            if (data.timestamp() > m_last_seen[public_key]) {
                m_last_seen[public_key] = data.timestamp();
            }

            switch (data.type()) {
                case MESSAGE: {
                    break;
                }
                case ONLINE_SIGNAL: {
                    online_signal onlineSignal(data.payload());

                    auto device_id = onlineSignal.device_id();
                    auto device_map = m_latest_signal_time[public_key];
                    // 检查相应设备信号的时间戳，只处理最新的数据
                    if (onlineSignal.timestamp() > device_map[device_id]) {
                        // update the latest signal time
                        device_map[device_id] = onlineSignal.timestamp();

                        if (onlineSignal.device_id() != m_device_id) {
                            // 通知用户新的device id
                            m_ses.alerts().emplace_alert<communication_new_device_id_alert>(onlineSignal.device_id());
                            log("INFO: Found new device id: %s", onlineSignal.device_id().data());

                            if (!onlineSignal.friend_info().empty()) {
                                // 通知用户新的friend info
                                m_ses.alerts().emplace_alert<communication_friend_info_alert>(onlineSignal.friend_info());
                            }
                        }
                    }

                    break;
                }
                case NEW_MSG_SIGNAL: {
                    new_msg_signal newMsgSignal(data.payload());

                    auto device_id = newMsgSignal.device_id();
                    auto device_map = m_latest_signal_time[public_key];
                    // 检查相应设备信号的时间戳，只处理最新的数据
                    if (newMsgSignal.timestamp() > device_map[device_id]) {
                        // update the latest signal time
                        device_map[device_id] = newMsgSignal.timestamp();
                    }

                    break;
                }
                default: {
                    // mismatch
                    ;
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

            void on_dht_put_immutable_item(aux::alert_manager& alerts, sha1_hash target, int num)
            {
//                if (alerts.should_post<dht_put_alert>())
//                    alerts.emplace_alert<dht_put_alert>(target, num);
            }

            void put_mutable_data(entry& e, std::array<char, 64>& sig
                    , std::int64_t& seq
                    , std::string const& salt
                    , std::array<char, 32> const& pk
                    , std::array<char, 64> const& sk
                    , char const* data)
            {
                using lt::dht::sign_mutable_item;

                e = std::string(data);
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
                // put完成之后，暂无动作
//                if (alerts.should_post<dht_put_alert>())
//                {
//                    dht::signature const sig = i.sig();
//                    dht::public_key const pk = i.pk();
//                    dht::sequence_number const seq = i.seq();
//                    std::string salt = i.salt();
//                    alerts.emplace_alert<dht_put_alert>(pk.bytes, sig.bytes
//                            , std::move(salt), seq.value, num);
//                }
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
            char *data;
            dht::public_key * pk = m_ses.pubkey();
            dht::secret_key * sk = m_ses.serkey();

            auto salt = make_salt(peer);

            aux::bytes public_key;
            public_key.insert(public_key.end(), pk->bytes.begin(), pk->bytes.end());

            // check if peer is myself
            if (peer == public_key) {
                // publish online signal on XX channel
                online_signal onlineSignal = make_online_signal();
                mutable_data_wrapper wrapper(time(nullptr), ONLINE_SIGNAL, onlineSignal.rlp());
                data = reinterpret_cast<char *>(wrapper.rlp().data());
            } else {
                // publish new message signal on XY channel
                new_msg_signal newMsgSignal = make_new_message_signal(peer);
                mutable_data_wrapper wrapper(time(nullptr), NEW_MSG_SIGNAL, newMsgSignal.rlp());
                data = reinterpret_cast<char *>(wrapper.rlp().data());
            }

            dht_put_mutable_item(pk->bytes, std::bind(&put_mutable_data, _1, _2, _3, _4
                    , pk->bytes, sk->bytes, data), salt);
        }

        void communication::dht_put_immutable_item(entry const& data, sha1_hash target)
        {
            if (!m_ses.dht()) return;
            m_ses.dht()->put_item(data, std::bind(&on_dht_put_immutable_item, std::ref(m_ses.alerts())
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
