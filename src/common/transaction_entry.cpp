/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/common/transaction_entry.hpp"

namespace libTAU::common {
    transaction_entry::transaction_entry(const entry &e) {
        // transaction
        if (auto* i = const_cast<entry *>(e.find_key("t")))
        {
            m_tx = blockchain::transaction(*i);
        }
    }

    entry transaction_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e["tid"] = entry(data_type_id);
        // transaction
        e["t"] = m_tx.get_entry();

        return e;
    }
}
