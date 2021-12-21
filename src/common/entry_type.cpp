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
        if (auto* i = const_cast<entry *>(e.find_key(entry_type_value)))
        {
            m_msg = communication::message(*i);
        }
    }

    entry message_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type_id] = entry(data_type_id);
        // message
        e[entry_type_value] = m_msg.get_entry();

        return e;
    }


    message_levenshtein_array_entry::message_levenshtein_array_entry(const entry &e) {
        // message levenshtein array
        if (auto* i = const_cast<entry *>(e.find_key(entry_type_value)))
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
        e[entry_type_value] = entry(std::string(m_levenshtein_array.begin(), m_levenshtein_array.end()));

        return e;
    }

    entry friend_info_request_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type_id] = entry(data_type_id);

        return e;
    }

    friend_info_entry::friend_info_entry(const entry &e) {
        // friend info
        if (auto* i = const_cast<entry *>(e.find_key(entry_type_value)))
        {
            std::string friend_info = i->string();
            m_friend_info = aux::bytes(friend_info.begin(), friend_info.end());
        }
    }

    entry friend_info_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type_id] = entry(data_type_id);
        // friend info
        e[entry_type_value] = entry(std::string(m_friend_info.begin(), m_friend_info.end()));

        return e;
    }



    block_entry::block_entry(const entry &e) {
        // block
        if (auto* i = const_cast<entry *>(e.find_key(entry_type_value)))
        {
            m_blk = blockchain::block(*i);
        }
    }

    entry block_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type_id] = entry(data_type_id);
        // block
        e[entry_type_value] = m_blk.get_entry();

        return e;
    }


    transaction_entry::transaction_entry(const entry &e) {
        // transaction
        if (auto* i = const_cast<entry *>(e.find_key(entry_type_value)))
        {
            m_tx = blockchain::transaction(*i);
        }
    }

    entry transaction_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type_id] = entry(data_type_id);
        // transaction
        e[entry_type_value] = m_tx.get_entry();

        return e;
    }

}
