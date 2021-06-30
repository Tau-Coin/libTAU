/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <ctime>
#include <cstdlib>
#include <utility>

#include "libtorrent/communication/message_hash_list.hpp"
#include "libtorrent/communication/communication.hpp"
#include "libtorrent/kademlia/dht_tracker.hpp"

using namespace std::placeholders;

namespace libtorrent {
    namespace communication {

        void communication::start()
        {
            init();

            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(std::bind(&communication::refresh_timeout, self(), _1));
        }

        void communication::stop()
        {
            m_friends.clear();
            m_message_list_map.clear();

            m_refresh_timer.cancel();
        }

        void communication::init() {
            m_message_db->init();
            // get friends from db
            m_message_db->get_all_friends();
        }

        void communication::account_changed() {
            stop();
            start();
        }

        void communication::set_loop_time_interval(int milliseconds) {
            m_refresh_time = milliseconds;
        }

        void communication::add_new_friend(const aux::bytes& pubkey) {
            m_friends.push_back(pubkey);
            m_message_db->save_friend(pubkey);
        }

        void communication::delete_friend(const aux::bytes& pubkey) {
            for(auto it = m_friends.begin(); it != m_friends.end(); ++it) {
                if (*it == pubkey) {
                    m_friends.erase(it);
                    break;
                }
            }

            m_message_db->delete_friend(pubkey);
            m_message_db->delete_latest_message_hash_list_encode(pubkey);
        }

        void communication::set_chatting_friend(aux::bytes chatting_friend) {
            m_chatting_friend = std::move(chatting_friend);
        }

        void communication::set_active_friends(std::vector<aux::bytes> &&active_friends) {
            m_active_friends = std::move(active_friends);
        }

        void communication::add_new_message(const message& msg) {
            try_to_update_Latest_message_list(msg.sender(), msg);
        }

        bool communication::validateMessage(const message& msg) {
            if (msg.rlp().size() > 1000) {
                return false;
            }

            return true;
        }

        aux::bytes communication::select_friend_randomly() const {
            aux::bytes peer;

            if (!m_friends.empty())
            {
                srand((unsigned)time(nullptr));
                auto index = rand() % 10;

                // chatting friend(80%)
                if (!m_chatting_friend.empty() && index < 8) {
                    peer = m_chatting_friend;
                } else {
                    srand((unsigned)time(nullptr) + index);
                    index = rand() % 10;

                    // active friends(70%)
                    if (!m_active_friends.empty() && index < 7) {
                        srand((unsigned)time(nullptr) + index);
                        index = rand() % m_active_friends.size();
                        peer = m_active_friends[index];
                    } else {
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
            aux::bytes peer = select_friend_randomly();
            if (!peer.empty()) {
                // put / get
//                dht_get_mutable_item();
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
                m_message_db->save_latest_message_hash_list_encode(peer, message_hash_list(hash_list).rlp());
            }
        }

        bool communication::try_to_update_Latest_message_list(const aux::bytes &peer, const message& msg) {
            bool updated = false;

            std::list<message> message_list = m_message_list_map[peer];
            if (!message_list.empty()) {
                // 先判断一下是否比最后一个消息时间戳大，如果是，则直接插入末尾
                if (msg.timestamp() == message_list.back().timestamp()) {
                    message_list.push_back(msg);
                    updated = true;
                } else {
                    // 寻找从后往前寻找第一个时间小于当前消息时间的消息，将当前消息插入到到该消息后面
                    auto it = message_list.rbegin();
                    // 是否插入第一个位置，在没找到的情况下会插入到第一个位置
                    bool insertFirst = true;
                    for (; it != message_list.rend(); ++it) {
                        message reference = *it;
                        int diff = reference.timestamp() - msg.timestamp();
                        // 如果差值小于零，说明找到了比当前消息时间戳小的消息位置，将消息插入到目标位置后面一位
                        if (diff < 0) {
                            updated = true;
                            insertFirst = false;
                            message_list.insert((++it).base(), msg);
//                            int i = linkedList.indexOf(reference);
//                            linkedList.add(i + 1, message);
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

        std::string communication::make_sender_salt(aux::bytes peer) {
            dht::public_key *pubkey = m_ses.pubkey();
            std::string salt;

            std::copy(pubkey, pubkey + communication_short_address_length, salt.begin());
            std::copy(peer.begin(), peer.begin() + communication_short_address_length,
                      salt.begin() + communication_short_address_length);

            return salt;
        }

        std::string communication::make_receiver_salt(aux::bytes peer) {
            dht::public_key *pubkey = m_ses.pubkey();
            std::string salt;

            std::copy(peer.begin(), peer.begin() + communication_short_address_length, salt.begin());
            std::copy(pubkey, pubkey + communication_short_address_length,
                      salt.begin() + communication_short_address_length);

            return salt;
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
//            TORRENT_ASSERT(i.is_mutable());
//            m_alerts.emplace_alert<dht_mutable_item_alert>(i.pk().bytes
//                    , i.sig().bytes, i.seq().value
//                    , i.salt(), i.value(), authoritative);
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

            void on_dht_put_mutable_item(aux::alert_manager& alerts, dht::item const& i, int num)
            {
                if (alerts.should_post<dht_put_alert>())
                {
                    dht::signature const sig = i.sig();
                    dht::public_key const pk = i.pk();
                    dht::sequence_number const seq = i.seq();
                    std::string salt = i.salt();
                    alerts.emplace_alert<dht_put_alert>(pk.bytes, sig.bytes
                            , std::move(salt), seq.value, num);
                }
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
                cb(value, sig.bytes, seq.value, salt);
                i.assign(std::move(value), salt, seq, pk, sig);
            }
        } // anonymous namespace

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

    }
}