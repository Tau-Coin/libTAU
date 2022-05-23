/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/blockchain_signal.hpp"


//namespace libTAU::blockchain {
//
//    const std::int64_t blockchain_signal::protocol_id = 1;
//
//    blockchain_signal::blockchain_signal(const entry &e) {
//        populate(e);
//    }
//
//    entry blockchain_signal::get_entry() const {
//        entry e(entry::dictionary_t);
//
//        // protocol id
//        e["pid"] = entry(protocol_id);
//
//        // chain id
//        e["cid"] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
//
////        // consensus point block hash
////        e["ch"] = entry(m_consensus_point_block_hash.to_string());
////
////        // consensus point block number
////        e["cn"] = entry(m_consensus_point_block_number);
//
//        // timestamp
//        e["ts"] = entry(m_timestamp);
//
//        e["cv"] = m_consensus_point_vote.get_entry();
//
//        // best block
//        e["bb"] = m_head_block_info.get_entry();
//
//        // immutable block
//        e["ib"] = m_voting_point_block_info.get_entry();
//
//        // block set
//        entry::list_type block_list;
//        for (auto const& item: m_block_info_set) {
//            block_list.push_back(item.get_entry());
//        }
//        e["bs"] = block_list;
//
//        // tx set
//        entry::list_type tx_list;
//        for (auto const& item: m_tx_info_set) {
//            tx_list.push_back(item.get_entry());
//        }
//        e["ti"] = tx_list;
//
//        // demand block hash set
//        entry::list_type demand_block_hash_list;
//        for (auto const& hash: m_demand_block_hash_set) {
//            demand_block_hash_list.push_back(hash.to_string());
//        }
//        e["db"] = demand_block_hash_list;
//
////        // demand tx hash set
////        entry::list_type demand_tx_hash_list;
////        for (auto const& hash: m_demand_tx_hash_set) {
////            demand_tx_hash_list.push_back(hash.to_string());
////        }
////        e["dt"] = demand_tx_hash_list;
//
//        // tx hash prefix bytes
////        e["ta"] = entry(std::string(m_tx_hash_prefix_array.begin(), m_tx_hash_prefix_array.end()));
//
//        // latest tx hash prefix bytes
//        e["lt"] = entry(std::string(m_latest_tx_hash_prefix_array.begin(), m_latest_tx_hash_prefix_array.end()));
//
//        // gossip peer
//        e["pr"] = entry(std::string(m_gossip_peer.bytes.begin(), m_gossip_peer.bytes.end()));
//
//        return e;
//    }
//
//    std::string blockchain_signal::get_encode() const {
//        std::string encode;
//        auto e = get_entry();
//        bencode(std::back_inserter(encode), e);
//
//        return encode;
//    }
//
//    void blockchain_signal::populate(const entry &e) {
//        // chain id
//        if (auto* i = const_cast<entry *>(e.find_key("cid")))
//        {
//            auto chain_id = i->string();
//            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
//        }
////        // consensus point block hash
////        if (auto* i = const_cast<entry *>(e.find_key("ch")))
////        {
////            m_consensus_point_block_hash = sha256_hash(i->string().data());
////        }
////        // consensus point block number
////        if (auto* i = const_cast<entry *>(e.find_key("cn")))
////        {
////            m_consensus_point_block_number = i->integer();
////        }
//        // timestamp
//        if (auto* i = const_cast<entry *>(e.find_key("ts")))
//        {
//            m_timestamp = i->integer();
//        }
//        // consensus point vote
//        if (auto* i = const_cast<entry *>(e.find_key("cv")))
//        {
//            m_consensus_point_vote = vote(*i);
//        }
//        // best block
//        if (auto* i = const_cast<entry *>(e.find_key("bb")))
//        {
//            m_head_block_info = immutable_data_info(*i);
//        }
//        // immutable block
//        if (auto* i = const_cast<entry *>(e.find_key("ib")))
//        {
//            m_voting_point_block_info = immutable_data_info(*i);
//        }
//        // block set
//        if (auto* i = const_cast<entry *>(e.find_key("bs")))
//        {
//            auto & lst = i->list();
//            for (auto const& item: lst) {
//                m_block_info_set.emplace(item);
//            }
//        }
//        // tx set
//        if (auto* i = const_cast<entry *>(e.find_key("ti")))
//        {
//            auto & lst = i->list();
//            for (auto const& item: lst) {
//                m_tx_info_set.emplace(item);
//            }
//        }
//        // demand block hash set
//        if (auto* i = const_cast<entry *>(e.find_key("db")))
//        {
//            auto & lst = i->list();
//            for (auto const& hash: lst) {
//                m_demand_block_hash_set.emplace(hash.string().data());
//            }
//        }
////        // demand tx hash set
////        if (auto* i = const_cast<entry *>(e.find_key("dt")))
////        {
////            auto & lst = i->list();
////            for (auto const& hash: lst) {
////                m_demand_tx_hash_set.emplace(hash.string().data());
////            }
////        }
//        // tx hash prefix bytes
////        if (auto* i = const_cast<entry *>(e.find_key("ta")))
////        {
////            std::string hash_prefix_array = i->string();
////            m_tx_hash_prefix_array = aux::bytes(hash_prefix_array.begin(), hash_prefix_array.end());
////        }
//        // latest tx hash prefix bytes
//        if (auto* i = const_cast<entry *>(e.find_key("lt")))
//        {
//            std::string hash_prefix_array = i->string();
//            m_latest_tx_hash_prefix_array = aux::bytes(hash_prefix_array.begin(), hash_prefix_array.end());
//        }
//        // gossip peer
//        if (auto* i = const_cast<entry *>(e.find_key("pr")))
//        {
//            auto peer = i->string();
//            m_gossip_peer = dht::public_key(peer.data());
//        }
//    }
//
//    std::string blockchain_signal::to_string() const {
//        std::ostringstream os;
//        os << *this;
//        return os.str();
//    }
//
//    std::ostream &operator<<(std::ostream &os, const blockchain_signal &signal) {
//        os << "m_chain_id: " << aux::toHex(signal.m_chain_id) << " m_timestamp: " << signal.m_timestamp
//           << " m_consensus_point_vote: " << signal.m_consensus_point_vote << " m_best_tip_block_info: "
//           << signal.m_head_block_info << " m_consensus_point_block_info: " << signal.m_voting_point_block_info
////           << " m_tx_hash_prefix_array: " << aux::toHex(signal.m_tx_hash_prefix_array)
//           << " m_latest_tx_hash_prefix_array: " << aux::toHex(signal.m_latest_tx_hash_prefix_array)
//           << " m_gossip_peer: " << aux::toHex(signal.m_gossip_peer.bytes);
//
//        os << " m_block_info_set: ";
//        for (auto const& block_info: signal.m_block_info_set) {
//            os << " block info: " << block_info;
//        }
//
//        os << " m_tx_info_set: ";
//        for (auto const& tx_info: signal.m_tx_info_set) {
//            os << " tx info: " << tx_info;
//        }
//
//        os << " m_demand_block_hash_set: ";
//        for (auto const& hash: signal.m_demand_block_hash_set) {
//            os << " demand block hash: " << aux::toHex(hash.to_string());
//        }
//
//        return os;
//    }
//
//}