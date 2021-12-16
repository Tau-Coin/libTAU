/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MESSAGE_ENTRY_HPP
#define LIBTAU_MESSAGE_ENTRY_HPP

#include "libTAU/aux_/export.hpp"
#include "libTAU/communication/message.hpp"
#include "libTAU/entry.hpp"

#include <utility>

namespace libTAU::common {
    struct TORRENT_EXPORT message_entry {
        // data type id
        static std::int64_t data_type_id;

        // @param Construct with entry
        explicit message_entry(const entry& e);

        explicit message_entry(communication::message mMsg) : m_msg(std::move(mMsg)) {}

        // @returns the corresponding entry
        entry get_entry() const;

        communication::message m_msg;
    };
}


#endif //LIBTAU_MESSAGE_ENTRY_HPP
