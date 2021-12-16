/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/common/message_entry.hpp"

namespace libTAU::common {
    message_entry::message_entry(const entry &e) {
        // message
        if (auto* i = const_cast<entry *>(e.find_key("m")))
        {
            m_msg = communication::message(*i);
        }
    }

    entry message_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e["tid"] = entry(data_type_id);
        // message
        e["m"] = m_msg.get_entry();

        return e;
    }
}
