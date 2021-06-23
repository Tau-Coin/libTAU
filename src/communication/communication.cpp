/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <ctime>
#include <cstdlib>
#include <utility>

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
            m_refresh_timer.cancel();
        }

        void communication::set_loop_time_interval(int milliseconds) {
            m_refresh_time = milliseconds;
        }

        void communication::set_chatting_friend(aux::bytes chatting_friend) {
            m_chatting_friend = std::move(chatting_friend);
        }

        void communication::set_active_friends(std::vector<aux::bytes> &&active_friends) {
            m_active_friends = std::move(active_friends);
        }

        void communication::init() {
            // get friends from db
            auto a = select_friend_randomly();
        }

        bool communication::validateMessage(message msg) {
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
            }

            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(
                    std::bind(&communication::refresh_timeout, self(), _1));
        }

        // callback for dht_immutable_get
        void communication::get_immutable_callback(sha1_hash target
                , dht::item const& i)
        {
            TORRENT_ASSERT(!i.is_mutable());
            m_ses.alerts().emplace_alert<dht_immutable_item_alert>(target, i.value());
        }

        void communication::dht_get_immutable_item(sha1_hash const& target)
        {
            if (!m_ses.dht()) return;
            m_ses.dht()->get_item(target, std::bind(&communication::get_immutable_callback
                    , this, target, _1));
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
        // TODO: 3 use public_key here instead of std::array
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
                if (alerts.should_post<dht_put_alert>())
                    alerts.emplace_alert<dht_put_alert>(target, num);
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