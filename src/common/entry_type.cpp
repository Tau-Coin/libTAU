/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/common/entry_type.hpp"

namespace libTAU::common {

//    communication_entries::communication_entries(const entry &e) {
//        // entries
//        if (auto* i = const_cast<entry *>(e.find_key(protocol_payload))) {
//            entry::list_type entries = i->list();
//            for (const auto &n: entries) {
//                m_entries.push_back(n);
//            }
//        }
//    }
//
//    entry communication_entries::get_entry() const {
//        entry e(entry::dictionary_t);
//        // protocol id
//        e[protocol_type] = entry(protocol_id);
//
//        // entries
//        entry::list_type l;
//        for (const auto &n: m_entries) {
//            l.push_back(n);
//        }
//        // protocol payload
//        e[protocol_payload] = l;
//
//        return e;
//    }

//    blockchain_entries::blockchain_entries(const entry &e) {
//        // entries
//        if (auto* i = const_cast<entry *>(e.find_key(protocol_payload))) {
//            entry::list_type entries = i->list();
//            for (const auto &n: entries) {
//                m_entries.push_back(n);
//            }
//        }
//    }
//
//    entry blockchain_entries::get_entry() const {
//        entry e(entry::dictionary_t);
//        // protocol id
//        e[protocol_type] = entry(protocol_id);
//
//        // entries
//        entry::list_type l;
//        for (const auto &n: m_entries) {
//            l.push_back(n);
//        }
//        // protocol payload
//        e[protocol_payload] = l;
//
//        return e;
//    }

    message_entry::message_entry(const entry &e) {
        // message
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            m_msg = communication::message(*i);
        }
        // message levenshtein array
        if (auto* i = const_cast<entry *>(e.find_key(entry_levenshtein_array)))
        {
            std::string levenshtein_array = i->string();
            m_levenshtein_array = aux::bytes(levenshtein_array.begin(), levenshtein_array.end());
        }
        // time
        if (auto* i = const_cast<entry *>(e.find_key(entry_time)))
        {
            m_timestamp = i->integer();
        }
    }

    entry message_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // message
        e[entry_value] = m_msg.get_entry();
        // message levenshtein array
        e[entry_levenshtein_array] = entry(std::string(m_levenshtein_array.begin(), m_levenshtein_array.end()));
        // time
        e[entry_time] = entry(m_timestamp);

        return e;
    }


    message_levenshtein_array_entry::message_levenshtein_array_entry(const entry &e) {
        // message levenshtein array
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            std::string levenshtein_array = i->string();
            m_levenshtein_array = aux::bytes(levenshtein_array.begin(), levenshtein_array.end());
        }
        // time
        if (auto* i = const_cast<entry *>(e.find_key(entry_time)))
        {
            m_timestamp = i->integer();
        }
    }

    entry message_levenshtein_array_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // message levenshtein array
        e[entry_value] = entry(std::string(m_levenshtein_array.begin(), m_levenshtein_array.end()));
        // time
        e[entry_time] = entry(m_timestamp);

        return e;
    }

    friend_info_request_entry::friend_info_request_entry(const entry &e) {
        // time
        if (auto* i = const_cast<entry *>(e.find_key(entry_time)))
        {
            m_timestamp = i->integer();
        }
    }

    entry friend_info_request_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // time
        e[entry_time] = entry(m_timestamp);

        return e;
    }

    friend_info_entry::friend_info_entry(const entry &e) {
        // friend info
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            std::string friend_info = i->string();
            m_friend_info = aux::bytes(friend_info.begin(), friend_info.end());
        }
        // time
        if (auto* i = const_cast<entry *>(e.find_key(entry_time)))
        {
            m_timestamp = i->integer();
        }
    }

    entry friend_info_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // friend info
        e[entry_value] = entry(std::string(m_friend_info.begin(), m_friend_info.end()));
        // time
        e[entry_time] = entry(m_timestamp);

        return e;
    }


    block_request_entry::block_request_entry(const entry &e) {
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
        // block hash
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            auto hash = i->string();
            m_hash = sha256_hash(hash.data());
        }
    }

    entry block_request_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // block hash
        e[entry_value] = entry(m_hash.to_string());

        return e;
    }

    block_entry::block_entry(const entry &e) {
        // block
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            m_blk = blockchain::block(*i);
        }
    }

    entry block_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // block
        e[entry_value] = m_blk.get_entry();

        return e;
    }


    transaction_request_entry::transaction_request_entry(const entry &e) {
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
        // tx hash
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            auto hash = i->string();
            m_hash = sha256_hash(hash.data());
        }
    }

    entry transaction_request_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // block hash
        e[entry_value] = entry(m_hash.to_string());

        return e;
    }

    transaction_entry::transaction_entry(const entry &e) {
        // transaction
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            m_tx = blockchain::transaction(*i);
        }
    }

    entry transaction_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // transaction
        e[entry_value] = m_tx.get_entry();

        return e;
    }



    vote_request_entry::vote_request_entry(const entry &e) {
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
    }

    entry vote_request_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));

        return e;
    }

    vote_entry::vote_entry(const entry &e) {
        // vote
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            m_vote = blockchain::vote(*i);
        }
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
    }

    entry vote_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // vote
        e[entry_value] = m_vote.get_entry();

        return e;
    }

    head_block_request_entry::head_block_request_entry(const entry &e) {
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
    }

    entry head_block_request_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));

        return e;
    }

    head_block_entry::head_block_entry(const entry &e) {
        // block
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            m_blk = blockchain::block(*i);
        }
    }

    entry head_block_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // block
        e[entry_value] = m_blk.get_entry();

        return e;
    }

    tx_pool_entry::tx_pool_entry(const entry &e) {
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
        // tx pool levenshtein array
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            std::string levenshtein_array = i->string();
            m_levenshtein_array = aux::bytes(levenshtein_array.begin(), levenshtein_array.end());
        }
    }

    entry tx_pool_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // message levenshtein array
        e[entry_value] = entry(std::string(m_levenshtein_array.begin(), m_levenshtein_array.end()));

        return e;
    }

    state_request_entry::state_request_entry(const entry &e) {
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
    }

    entry state_request_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));

        return e;
    }

    state_entry::state_entry(const entry &e) {
        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
        // state
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            m_act = blockchain::account(*i);
        }
    }

    entry state_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // state
        e[entry_value] = m_act.get_entry();

        return e;
    }

}
