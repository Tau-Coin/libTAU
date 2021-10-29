/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/blockchain_signal.hpp"


namespace libTAU::blockchain {

    blockchain_signal::blockchain_signal(const entry &e) {
        populate(e);
    }

    entry blockchain_signal::get_entry() const {
        entry e(entry::dictionary_t);

//        // consensus point block hash
//        e["ch"] = entry(m_consensus_point_block_hash.to_string());
//
//        // consensus point block number
//        e["cn"] = entry(m_consensus_point_block_number);

        e["cv"] = m_consensus_point_vote.get_entry();

        // best block
        e["bb"] = m_best_tip_block_info.get_entry();

        // immutable block
        e["ib"] = m_consensus_point_block_info.get_entry();

        // block set
        entry::list_type block_list;
        for (auto const& item: m_block_info_set) {
            block_list.push_back(item.get_entry());
        }
        e["bs"] = block_list;

        // tx set
        entry::list_type tx_list;
        for (auto const& item: m_tx_info_set) {
            tx_list.push_back(item.get_entry());
        }
        e["ts"] = tx_list;

        // demand block hash set
        entry::list_type demand_block_hash_list;
        for (auto const& hash: m_demand_block_hash_set) {
            demand_block_hash_list.push_back(hash.to_string());
        }
        e["db"] = demand_block_hash_list;

//        // demand tx hash set
//        entry::list_type demand_tx_hash_list;
//        for (auto const& hash: m_demand_tx_hash_set) {
//            demand_tx_hash_list.push_back(hash.to_string());
//        }
//        e["dt"] = demand_tx_hash_list;

        // tx hash prefix bytes
        e["ta"] = entry(std::string(m_tx_hash_prefix_array.begin(), m_tx_hash_prefix_array.end()));

        return e;
    }

    std::string blockchain_signal::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    void blockchain_signal::populate(const entry &e) {
//        // consensus point block hash
//        if (auto* i = const_cast<entry *>(e.find_key("ch")))
//        {
//            m_consensus_point_block_hash = sha256_hash(i->string().data());
//        }
//        // consensus point block number
//        if (auto* i = const_cast<entry *>(e.find_key("cn")))
//        {
//            m_consensus_point_block_number = i->integer();
//        }
        // consensus point vote
        if (auto* i = const_cast<entry *>(e.find_key("cv")))
        {
            m_consensus_point_vote = vote(*i);
        }
        // best block
        if (auto* i = const_cast<entry *>(e.find_key("bb")))
        {
            m_best_tip_block_info = immutable_data_info(*i);
        }
        // immutable block
        if (auto* i = const_cast<entry *>(e.find_key("ib")))
        {
            m_consensus_point_block_info = immutable_data_info(*i);
        }
        // block set
        if (auto* i = const_cast<entry *>(e.find_key("bs")))
        {
            auto & lst = i->list();
            for (auto const& item: lst) {
                m_block_info_set.emplace(item);
            }
        }
        // tx set
        if (auto* i = const_cast<entry *>(e.find_key("ts")))
        {
            auto & lst = i->list();
            for (auto const& item: lst) {
                m_tx_info_set.emplace(item);
            }
        }
        // demand block hash set
        if (auto* i = const_cast<entry *>(e.find_key("db")))
        {
            auto & lst = i->list();
            for (auto const& hash: lst) {
                m_demand_block_hash_set.emplace(hash.string().data());
            }
        }
//        // demand tx hash set
//        if (auto* i = const_cast<entry *>(e.find_key("dt")))
//        {
//            auto & lst = i->list();
//            for (auto const& hash: lst) {
//                m_demand_tx_hash_set.emplace(hash.string().data());
//            }
//        }
        // tx hash prefix bytes
        if (auto* i = const_cast<entry *>(e.find_key("ta")))
        {
            std::string hash_prefix_array = i->string();
            m_tx_hash_prefix_array = aux::bytes(hash_prefix_array.begin(), hash_prefix_array.end());
        }
    }

}