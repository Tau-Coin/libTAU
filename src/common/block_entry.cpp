/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/common/block_entry.hpp"

namespace libTAU::common {
    block_entry::block_entry(const entry &e) {
        // block
        if (auto* i = const_cast<entry *>(e.find_key("b")))
        {
            m_blk = blockchain::block(*i);
        }
    }

    entry block_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e["tid"] = entry(data_type_id);
        // block
        e["b"] = m_blk.get_entry();

        return e;
    }
}
