/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/common/entry_type.hpp"

namespace libTAU::common {

    message_entry::message_entry(const entry &e) {
        // message
        if (auto* i = const_cast<entry *>(e.find_key("v")))
        {
            m_msg = communication::message(*i);
        }
    }

    entry message_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type_id] = entry(data_type_id);
        // message
        e["v"] = m_msg.get_entry();

        return e;
    }


    message_levenshtein_array_entry::message_levenshtein_array_entry(const entry &e) {
        // message levenshtein array
        if (auto* i = const_cast<entry *>(e.find_key("v")))
        {
            std::string levenshtein_array = i->string();
            m_levenshtein_array = aux::bytes(levenshtein_array.begin(), levenshtein_array.end());
        }
    }

    entry message_levenshtein_array_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type_id] = entry(data_type_id);
        // message levenshtein array
        e["v"] = entry(std::string(m_levenshtein_array.begin(), m_levenshtein_array.end()));

        return e;
    }

    block_entry::block_entry(const entry &e) {
        // block
        if (auto* i = const_cast<entry *>(e.find_key("v")))
        {
            m_blk = blockchain::block(*i);
        }
    }

    entry block_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type_id] = entry(data_type_id);
        // block
        e["v"] = m_blk.get_entry();

        return e;
    }


    transaction_entry::transaction_entry(const entry &e) {
        // transaction
        if (auto* i = const_cast<entry *>(e.find_key("v")))
        {
            m_tx = blockchain::transaction(*i);
        }
    }

    entry transaction_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type_id] = entry(data_type_id);
        // transaction
        e["v"] = m_tx.get_entry();

        return e;
    }

}
