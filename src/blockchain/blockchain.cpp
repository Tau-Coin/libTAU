/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/blockchain.hpp"

namespace libTAU::blockchain {

    bool blockchain::init() {
        return false;
    }

    void blockchain::refresh_timeout(const error_code &e) {

    }

    bool blockchain::should_log() const
    {
        return m_ses.alerts().should_post<communication_log_alert>();
    }

    TORRENT_FORMAT(2,3)
    void blockchain::log(char const* fmt, ...) const noexcept try
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