//
// Created by vincent on 2021/6/7.
//

#ifndef LIBTAU_COMMUNICATION_HPP
#define LIBTAU_COMMUNICATION_HPP


#include <functional>
//#include <memory>

#include "libtorrent/aux_/deadline_timer.hpp"
#include "libtorrent/aux_/alert_manager.hpp" // for alert_manager
#include "libtorrent/aux_/session_interface.hpp"
#include "libtorrent/kademlia/item.hpp"

namespace libtorrent {
    namespace communication {

        class communication final: std::enable_shared_from_this<communication> {
        public:

            // start communication
            void start();
            // stop
            void stop();

        private:
            // immutable data callback
            void get_immutable_callback(sha1_hash target
                    , dht::item const& i);
            // mutable data callback
            void get_mutable_callback(dht::item const& i, bool);

            void dht_get_immutable_item(sha1_hash const& target);

            void dht_get_mutable_item(std::array<char, 32> key
                    , std::string salt = std::string());

            void dht_put_immutable_item(entry const& data, sha1_hash target);

            void dht_put_mutable_item(std::array<char, 32> key
                    , std::function<void(entry&, std::array<char,64>&
                    , std::int64_t&, std::string const&)> cb
                    , std::string salt = std::string());

            std::shared_ptr<communication> self()
            { return shared_from_this(); }

            void refresh_timeout(error_code const& e);

            // alerts
            aux::alert_manager m_alerts;
            // session interface
            aux::session_interface& m_ses;
            // deadline timer
            aux::deadline_timer m_refresh_timer;
        };
    }
}


#endif //LIBTAU_COMMUNICATION_HPP
