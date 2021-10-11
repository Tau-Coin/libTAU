/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BLOCKCHAIN_HPP
#define LIBTAU_BLOCKCHAIN_HPP


#include <set>
#include <map>

#include "libTAU/time.hpp"
#include "libTAU/aux_/alert_manager.hpp" // for alert_manager
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/deadline_timer.hpp"
#include "libTAU/aux_/session_interface.hpp"
#include "libTAU/kademlia/item.hpp"

namespace libTAU::blockchain {

    using system_clock = std::chrono::system_clock;

//#if !defined TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS
    // This is the basic logging and debug interface offered by the communication.
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
    private:
        // initialize member variables
        bool init();

//#ifndef TORRENT_DISABLE_LOGGING
        bool should_log() const override;
        void log(char const* fmt, ...) const noexcept override TORRENT_FORMAT(2,3);
//#endif

        void refresh_timeout(error_code const& e);

        // io context
        io_context& m_ioc;

        // session interface
        aux::session_interface& m_ses;

        // deadline timer
        aux::deadline_timer m_refresh_timer;

        // all chains
        std::set<aux::bytes> m_chains;
    };
}


#endif //LIBTAU_BLOCKCHAIN_HPP
