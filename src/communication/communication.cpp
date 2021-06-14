//
// Created by vincent on 2021/6/7.
//

#include "libtorrent/communication/communication.hpp"

using namespace std::placeholders;

namespace libtorrent {
    namespace communication {

        void communication::start()
        {
            m_refresh_timer.expires_after(milliseconds(50));
            m_refresh_timer.async_wait(std::bind(&communication::refresh_timeout, self(), _1));
        }

        void communication::stop()
        {
            m_refresh_timer.cancel();
        }

        void communication::refresh_timeout(error_code const& e)
        {
            // put/get

            m_refresh_timer.expires_after(milliseconds(50));
            m_refresh_timer.async_wait(
                    std::bind(&communication::refresh_timeout, self(), _1));
        }

        // callback for dht_immutable_get
        void communication::get_immutable_callback(sha1_hash target
                , dht::item const& i)
        {
//            TORRENT_ASSERT(!i.is_mutable());
//            m_alerts.emplace_alert<dht_immutable_item_alert>(target, i.value());
        }

        void communication::dht_get_immutable_item(sha1_hash const& target)
        {
//            if (!m_dht) return;
//            m_dht->get_item(target, std::bind(&communication::get_immutable_callback
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

        // key is a 32-byte binary string, the public key to look up.
        // the salt is optional
        // TODO: 3 use public_key here instead of std::array
        void communication::dht_get_mutable_item(std::array<char, 32> key
                , std::string salt)
        {
//            if (!m_dht) return;
//            m_dht->get_item(dht::public_key(key.data()), std::bind(&communication::get_mutable_callback
//                    , this, _1, _2), std::move(salt));
        }

        void communication::dht_put_immutable_item(entry const& data, sha1_hash target)
        {
//            if (!m_dht) return;
//            m_dht->put_item(data, std::bind(&on_dht_put_immutable_item, std::ref(m_alerts)
//                    , target, _1));
        }

        void communication::dht_put_mutable_item(std::array<char, 32> key
                , std::function<void(entry&, std::array<char,64>&
                , std::int64_t&, std::string const&)> cb
                , std::string salt)
        {
//            if (!m_dht) return;
//            m_dht->put_item(dht::public_key(key.data())
//                    , std::bind(&on_dht_put_mutable_item, std::ref(m_alerts), _1, _2)
//                    , std::bind(&put_mutable_callback, _1, std::move(cb)), salt);
        }

    }
}