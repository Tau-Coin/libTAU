/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BLOCKCHAIN_HPP
#define LIBTAU_BLOCKCHAIN_HPP


#include <map>
#include <set>
#include <vector>

#include "libTAU/time.hpp"
#include "libTAU/aux_/alert_manager.hpp" // for alert_manager
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/deadline_timer.hpp"
#include "libTAU/aux_/session_interface.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/blockchain/repository.hpp"

namespace libTAU::blockchain {

    using system_clock = std::chrono::system_clock;

    // default refresh time of main task(50)(ms)
    constexpr int blockchain_default_refresh_time = 50;

//#if !defined TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS
    // This is the basic logging and debug interface offered by the blockchain.
    // a release build with logging disabled (which is the default) will
    // not have this class at all
    struct TORRENT_EXTRA_EXPORT blockchain_logger
    {
//#ifndef TORRENT_DISABLE_LOGGING
        virtual bool should_log() const = 0;
        virtual void log(char const* fmt, ...) const TORRENT_FORMAT(2,3) = 0;
//#endif
    protected:
        ~blockchain_logger() {}
    };
//#endif // TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS

    class TORRENT_EXPORT blockchain final:
            public std::enable_shared_from_this<blockchain>, blockchain_logger  {
    public:
        // start blockchain
        bool start();

        // stop
        bool stop();

    private:
        // initialize member variables
        bool init();

        // clear all cache
        void clear();

        std::shared_ptr<blockchain> self()
        { return shared_from_this(); }

//#ifndef TORRENT_DISABLE_LOGGING
        bool should_log() const override;
        void log(char const* fmt, ...) const noexcept override TORRENT_FORMAT(2,3);
//#endif

        void refresh_timeout(error_code const& e);

        // select a chain randomly
        aux::bytes select_chain_randomly();

        // select a peer randomly
        dht::public_key select_peer_randomly(const aux::bytes &chain_id);

        // select a peer randomly
        std::set<dht::public_key> select_unchoked_peers(const aux::bytes &chain_id, std::int64_t block_number);

        // io context
        io_context& m_ioc;

        // session interface
        aux::session_interface& m_ses;

        // refresh time interval
        int m_refresh_time = blockchain_default_refresh_time;

        // deadline timer
        aux::deadline_timer m_refresh_timer;

        // blockchain db
        std::shared_ptr<repository> m_repository;

        bool m_stop = false;

        // all chains
        std::vector<aux::bytes> m_chains;

        // all chain peers
        std::map<aux::bytes, std::set<dht::public_key>> m_chain_peers;

    };
}


#endif //LIBTAU_BLOCKCHAIN_HPP
