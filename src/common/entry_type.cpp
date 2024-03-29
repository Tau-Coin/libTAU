/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/common/entry_type.hpp"

namespace libTAU::common {

    signal_entry::signal_entry(const entry &e) {
        auto const& lst = e.list();
        if (!lst.empty()) {
            int spid = aux::intFromLittleEndianString(lst[0].string());
            m_pid = static_cast<signal_id>(spid);
            switch (m_pid) {
                case COMMUNICATION_NEW_MESSAGE:
                case COMMUNICATION_CONFIRMATION:{
                    if (lst.size() == 3) {
                        // timestamp
                        auto timestamp = lst[1].string();
                        m_timestamp = aux::int64FromLittleEndianString(timestamp);
                        // hash
                        m_hash = sha1_hash(lst[2].string().data());
                    }

                    break;
                }
//                case COMMUNICATION_MESSAGE_MISSING:
//                case COMMUNICATION_PUT_DONE:
                case COMMUNICATION_ATTENTION: {
                    if (lst.size() == 2) {
                        // timestamp
                        auto timestamp = lst[1].string();
                        m_timestamp = aux::int64FromLittleEndianString(timestamp);
                    }

                    break;
                }
                case BLOCKCHAIN_ONLINE:
                case BLOCKCHAIN_RECOMMEND: {
                    if (lst.size() == 3) {
                        // timestamp
                        auto timestamp = lst[1].string();
                        m_timestamp = aux::int64FromLittleEndianString(timestamp);
                        // short chain id
                        auto chain_id = lst[2].string();
                        m_short_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
                    } else if (lst.size() == 4) {
                        // timestamp
                        auto timestamp = lst[1].string();
                        m_timestamp = aux::int64FromLittleEndianString(timestamp);
                        // short chain id
                        auto chain_id = lst[2].string();
                        m_short_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
                        // gossip peer
                        m_gossip_peer = dht::public_key(lst[3].string().data());
                    }

                    break;
                }
//                case BLOCKCHAIN_RECOMMEND: {
//                    if (lst.size() == 4) {
//                        // timestamp
//                        auto timestamp = lst[1].string();
//                        m_timestamp = aux::int64FromLittleEndianString(timestamp);
//                        // short chain id
//                        auto chain_id = lst[2].string();
//                        m_short_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
//                        // gossip peer
//                        m_gossip_peer = dht::public_key(lst[3].string().data());
//                    }
//
//                    break;
//                }
                case BLOCKCHAIN_NEW_HEAD_BLOCK:
                case BLOCKCHAIN_NEW_TRANSFER_TX: {
                    if (lst.size() == 6) {
                        // timestamp
                        auto timestamp = lst[1].string();
                        m_timestamp = aux::int64FromLittleEndianString(timestamp);
                        // short chain id
                        auto chain_id = lst[2].string();
                        m_short_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
                        // hash
                        m_hash = sha1_hash(lst[3].string().data());
                        // peer
                        m_peer = dht::public_key(lst[4].string().data());
                        // value
                        auto value = lst[5].string();
                        m_value = aux::int64FromLittleEndianString(value);
                    } else if (lst.size() == 7) {
                        // timestamp
                        auto timestamp = lst[1].string();
                        m_timestamp = aux::int64FromLittleEndianString(timestamp);
                        // short chain id
                        auto chain_id = lst[2].string();
                        m_short_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
                        // hash
                        m_hash = sha1_hash(lst[3].string().data());
                        // peer
                        m_peer = dht::public_key(lst[4].string().data());
                        // value
                        auto value = lst[5].string();
                        m_value = aux::int64FromLittleEndianString(value);
                        // gossip peer
                        m_gossip_peer = dht::public_key(lst[6].string().data());
                    }

                    break;
                }
                case BLOCKCHAIN_NEW_NOTE_TX:
                case BLOCKCHAIN_NEW_NEWS_TX: {
                    if (lst.size() == 5) {
                        // timestamp
                        auto timestamp = lst[1].string();
                        m_timestamp = aux::int64FromLittleEndianString(timestamp);
                        // short chain id
                        auto chain_id = lst[2].string();
                        m_short_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
                        // hash
                        m_hash = sha1_hash(lst[3].string().data());
                        // peer
                        m_peer = dht::public_key(lst[4].string().data());
                    } else if (lst.size() == 6) {
                        // timestamp
                        auto timestamp = lst[1].string();
                        m_timestamp = aux::int64FromLittleEndianString(timestamp);
                        // short chain id
                        auto chain_id = lst[2].string();
                        m_short_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
                        // hash
                        m_hash = sha1_hash(lst[3].string().data());
                        // peer
                        m_peer = dht::public_key(lst[4].string().data());
                        // gossip peer
                        m_gossip_peer = dht::public_key(lst[5].string().data());
                    }

                    break;
                }
                default: {

                }
            }
        }
    }

    entry signal_entry::get_entry() {
        entry::list_type lst;

        switch (m_pid) {
            case COMMUNICATION_NEW_MESSAGE:
            case COMMUNICATION_CONFIRMATION:{
                // protocol id:1 byte
                auto pid = aux::intToLittleEndianString((int)m_pid);
                lst.push_back(pid);
                // timestamp:4 bytes
                auto timestamp = aux::int64ToLittleEndianString(m_timestamp);
                lst.push_back(timestamp);
                // hash:20 bytes
                lst.push_back(m_hash.to_string());

                break;
            }
//            case COMMUNICATION_MESSAGE_MISSING:
//            case COMMUNICATION_PUT_DONE:
            case COMMUNICATION_ATTENTION: {
                // protocol id:1 byte
                auto pid = aux::intToLittleEndianString((int)m_pid);
                lst.push_back(pid);
                // timestamp:4 bytes
                auto timestamp = aux::int64ToLittleEndianString(m_timestamp);
                lst.push_back(timestamp);

                break;
            }
            case BLOCKCHAIN_ONLINE:
            case BLOCKCHAIN_RECOMMEND: {
                // protocol id:1 byte
                auto pid = aux::intToLittleEndianString((int)m_pid);
                lst.push_back(pid);
                // timestamp:4 bytes
                auto timestamp = aux::int64ToLittleEndianString(m_timestamp);
                lst.push_back(timestamp);
                // short chain id <= 4 bytes
                if (m_short_chain_id.size() > blockchain::short_chain_id_length) {
                    lst.push_back(std::string(m_short_chain_id.begin(), m_short_chain_id.begin() + blockchain::short_chain_id_length));
                } else {
                    lst.push_back(std::string(m_short_chain_id.begin(), m_short_chain_id.end()));
                }
                // gossip peer:32 bytes
                if (!m_gossip_peer.is_all_zeros()) {
                    lst.push_back(std::string(m_gossip_peer.bytes.begin(), m_gossip_peer.bytes.end()));
                }

                break;
            }
//            case BLOCKCHAIN_RECOMMEND: {
//                // protocol id:1 byte
//                auto pid = aux::intToLittleEndianString((int)m_pid);
//                lst.push_back(pid);
//                // timestamp:4 bytes
//                auto timestamp = aux::int64ToLittleEndianString(m_timestamp);
//                lst.push_back(timestamp);
//                // short chain id <= 4 bytes
//                if (m_short_chain_id.size() > blockchain::short_chain_id_length) {
//                    lst.push_back(std::string(m_short_chain_id.begin(), m_short_chain_id.begin() + blockchain::short_chain_id_length));
//                } else {
//                    lst.push_back(std::string(m_short_chain_id.begin(), m_short_chain_id.end()));
//                }
//                // gossip peer:32 bytes
//                lst.push_back(std::string(m_gossip_peer.bytes.begin(), m_gossip_peer.bytes.end()));
//
//                break;
//            }
            case BLOCKCHAIN_NEW_HEAD_BLOCK:
            case BLOCKCHAIN_NEW_TRANSFER_TX: {
                // protocol id:1 byte
                auto pid = aux::intToLittleEndianString((int)m_pid);
                lst.push_back(pid);
                // timestamp:4 bytes
                auto timestamp = aux::int64ToLittleEndianString(m_timestamp);
                lst.push_back(timestamp);
                // short chain id <= 4 bytes
                if (m_short_chain_id.size() > blockchain::short_chain_id_length) {
                    lst.push_back(std::string(m_short_chain_id.begin(), m_short_chain_id.begin() + blockchain::short_chain_id_length));
                } else {
                    lst.push_back(std::string(m_short_chain_id.begin(), m_short_chain_id.end()));
                }
                // hash:20 bytes
                lst.push_back(m_hash.to_string());
                // peer:32 bytes
                lst.push_back(std::string(m_peer.bytes.begin(), m_peer.bytes.end()));
                // value
                auto value = aux::int64ToLittleEndianString(m_value);
                lst.push_back(value);
                // gossip peer:32 bytes
                if (!m_gossip_peer.is_all_zeros()) {
                    lst.push_back(std::string(m_gossip_peer.bytes.begin(), m_gossip_peer.bytes.end()));
                }

                break;
            }
            case BLOCKCHAIN_NEW_NOTE_TX:
            case BLOCKCHAIN_NEW_NEWS_TX: {
                // protocol id:1 byte
                auto pid = aux::intToLittleEndianString((int)m_pid);
                lst.push_back(pid);
                // timestamp:4 bytes
                auto timestamp = aux::int64ToLittleEndianString(m_timestamp);
                lst.push_back(timestamp);
                // short chain id <= 4 bytes
                if (m_short_chain_id.size() > blockchain::short_chain_id_length) {
                    lst.push_back(std::string(m_short_chain_id.begin(), m_short_chain_id.begin() + blockchain::short_chain_id_length));
                } else {
                    lst.push_back(std::string(m_short_chain_id.begin(), m_short_chain_id.end()));
                }
                // hash:20 bytes
                lst.push_back(m_hash.to_string());
                // peer:32 bytes
                lst.push_back(std::string(m_peer.bytes.begin(), m_peer.bytes.end()));
                // gossip peer:32 bytes
                if (!m_gossip_peer.is_all_zeros()) {
                    lst.push_back(std::string(m_gossip_peer.bytes.begin(), m_gossip_peer.bytes.end()));
                }

                break;
            }
            default: {

            }
        }

        return lst;
    }

    std::string signal_entry::get_encode() {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    gossip_cache_peers_entry::gossip_cache_peers_entry(const entry &e) {
        // gossip peers
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            entry::list_type lst = i->list();
            for (const auto& n: lst) {
                m_peers.insert(dht::public_key(n.string().data()));
            }
        }
    }

    entry gossip_cache_peers_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // gossip peers
        entry::list_type l;
        for (auto const& peer: m_peers) {
            l.push_back(entry(std::string(peer.bytes.begin(), peer.bytes.end())));
        }
        e[entry_value] = l;

        return e;
    }

    voting_block_cache_entry::voting_block_cache_entry(const entry &e) {
        // block
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            m_blk = blockchain::block(*i);
        }
    }

    entry voting_block_cache_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // block
        e[entry_value] = m_blk.get_entry();

        return e;
    }

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

        auto et = get_real_payload_entry();
        std::string encode;
        bencode(std::back_inserter(encode), et);
        m_real_payload_hash = hasher(encode).final();
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

    entry message_entry::get_real_payload_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // message
        e[entry_value] = m_msg.get_entry();

        return e;
    }

    message_levenshtein_array_entry::message_levenshtein_array_entry() {
        auto et = get_real_payload_entry();
        std::string encode;
        bencode(std::back_inserter(encode), et);
        m_real_payload_hash = hasher(encode).final();
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

        auto et = get_real_payload_entry();
        std::string encode;
        bencode(std::back_inserter(encode), et);
        m_real_payload_hash = hasher(encode).final();
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

    entry message_levenshtein_array_entry::get_real_payload_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // message levenshtein array
//        e[entry_value] = entry(std::string(m_levenshtein_array.begin(), m_levenshtein_array.end()));

        return e;
    }

//    friend_info_request_entry::friend_info_request_entry() {
//        auto et = get_real_payload_entry();
//        std::string encode;
//        bencode(std::back_inserter(encode), et);
//        m_real_payload_hash = dht::item_target_id(encode);
//    }
//
//    friend_info_request_entry::friend_info_request_entry(const entry &e) {
//        // time
//        if (auto* i = const_cast<entry *>(e.find_key(entry_time)))
//        {
//            m_timestamp = i->integer();
//        }
//
//        auto et = get_real_payload_entry();
//        std::string encode;
//        bencode(std::back_inserter(encode), et);
//        m_real_payload_hash = dht::item_target_id(encode);
//    }
//
//    entry friend_info_request_entry::get_entry() const {
//        entry e(entry::dictionary_t);
//        // data type id
//        e[entry_type] = entry(data_type_id);
//        // time
//        e[entry_time] = entry(m_timestamp);
//
//        return e;
//    }
//
//    entry friend_info_request_entry::get_real_payload_entry() const {
//        entry e(entry::dictionary_t);
//        // data type id
//        e[entry_type] = entry(data_type_id);
//
//        return e;
//    }
//
//    friend_info_entry::friend_info_entry(const entry &e) {
//        // friend info
//        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
//        {
//            std::string friend_info = i->string();
//            m_friend_info = aux::bytes(friend_info.begin(), friend_info.end());
//        }
//        // time
//        if (auto* i = const_cast<entry *>(e.find_key(entry_time)))
//        {
//            m_timestamp = i->integer();
//        }
//
//        auto et = get_real_payload_entry();
//        std::string encode;
//        bencode(std::back_inserter(encode), et);
//        m_real_payload_hash = dht::item_target_id(encode);
//    }
//
//    entry friend_info_entry::get_entry() const {
//        entry e(entry::dictionary_t);
//        // data type id
//        e[entry_type] = entry(data_type_id);
//        // friend info
//        e[entry_value] = entry(std::string(m_friend_info.begin(), m_friend_info.end()));
//        // time
//        e[entry_time] = entry(m_timestamp);
//
//        return e;
//    }
//
//    entry friend_info_entry::get_real_payload_entry() const {
//        entry e(entry::dictionary_t);
//        // data type id
//        e[entry_type] = entry(data_type_id);
//        // friend info
//        e[entry_value] = entry(std::string(m_friend_info.begin(), m_friend_info.end()));
//
//        return e;
//    }

    event_entry::event_entry(const entry &e) {
        // value
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            auto value = i->string();
            m_value = aux::bytes(value.begin(), value.end());
        }
        // time
        if (auto* i = const_cast<entry *>(e.find_key(entry_time)))
        {
            m_timestamp = i->integer();
        }

        auto et = get_real_payload_entry();
        std::string encode;
        bencode(std::back_inserter(encode), et);
        m_real_payload_hash = hasher(encode).final();
    }

    entry event_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // friend info
        e[entry_value] = entry(std::string(m_value.begin(), m_value.end()));
        // time
        e[entry_time] = entry(m_timestamp);

        return e;
    }

    entry event_entry::get_real_payload_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // value
        e[entry_value] = entry(std::string(m_value.begin(), m_value.end()));

        return e;
    }


    block_request_entry::block_request_entry(const entry &e) {
        m_entry = e;

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
            m_hash = sha1_hash(hash.data());
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
        m_entry = e;

        // block
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            m_blk = blockchain::block(*i);
            m_chain_id = m_blk.chain_id();
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
        m_entry = e;

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
            m_hash = sha1_hash(hash.data());
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
        m_entry = e;

        // transaction
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            m_tx = blockchain::transaction(*i);
            m_chain_id = m_tx.chain_id();
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

//    vote_request_entry::vote_request_entry(const entry &e) {
//        m_entry = e;
//
//        // chain id
//        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
//        {
//            auto chain_id = i->string();
//            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
//        }
//    }
//
//    entry vote_request_entry::get_entry() const {
//        entry e(entry::dictionary_t);
//        // data type id
//        e[entry_type] = entry(data_type_id);
//        // chain id
//        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
//
//        return e;
//    }
//
//    vote_entry::vote_entry(const entry &e) {
//        m_entry = e;
//
//        // vote
//        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
//        {
//            m_vote = blockchain::vote(*i);
//        }
//        // chain id
//        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
//        {
//            auto chain_id = i->string();
//            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
//        }
//    }
//
//    entry vote_entry::get_entry() const {
//        entry e(entry::dictionary_t);
//        // data type id
//        e[entry_type] = entry(data_type_id);
//        // chain id
//        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
//        // vote
//        e[entry_value] = m_vote.get_entry();
//
//        return e;
//    }

    head_block_request_entry::head_block_request_entry(const entry &e) {
        m_entry = e;

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
        m_entry = e;

        // block
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            m_blk = blockchain::block(*i);
            m_chain_id = m_blk.chain_id();
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

//    tx_pool_request_entry::tx_pool_request_entry(const entry &e) {
//        m_entry = e;
//
//        // chain id
//        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
//        {
//            auto chain_id = i->string();
//            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
//        }
//        // tx pool levenshtein array
//        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
//        {
//            entry v = entry(*i);
//            if (auto* p = const_cast<entry *>(v.find_key("v1")))
//            {
//                std::string levenshtein_array = p->string();
//                m_fee_pooL_levenshtein_array = aux::bytes(levenshtein_array.begin(), levenshtein_array.end());
//            }
//            if (auto* p = const_cast<entry *>(v.find_key("v2")))
//            {
//                std::string levenshtein_array = p->string();
//                m_time_pooL_levenshtein_array = aux::bytes(levenshtein_array.begin(), levenshtein_array.end());
//            }
//        }
//    }
//
//    entry tx_pool_request_entry::get_entry() const {
//        entry e(entry::dictionary_t);
//        // data type id
//        e[entry_type] = entry(data_type_id);
//        // chain id
//        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
//        // message levenshtein array
//        entry v(entry::dictionary_t);
//        v["v1"] = entry(std::string(m_fee_pooL_levenshtein_array.begin(), m_fee_pooL_levenshtein_array.end()));
//        v["v2"] = entry(std::string(m_time_pooL_levenshtein_array.begin(), m_time_pooL_levenshtein_array.end()));
//        e[entry_value] = v;
//
//        return e;
//    }

    state_request_entry::state_request_entry(const entry &e) {
        m_entry = e;

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
        m_entry = e;

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

//    transaction_reply_entry::transaction_reply_entry(const entry &e) {
//        m_entry = e;
//
//        // chain id
//        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
//        {
//            auto chain_id = i->string();
//            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
//        }
//        // tx hash
//        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
//        {
//            auto hash = i->string();
//            m_hash = sha256_hash(hash.data());
//        }
//    }
//
//    entry transaction_reply_entry::get_entry() const {
//        entry e(entry::dictionary_t);
//        // data type id
//        e[entry_type] = entry(data_type_id);
//        // chain id
//        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
//        // block hash
//        e[entry_value] = entry(m_hash.to_string());
//
//        return e;
//    }

//    block_reply_entry::block_reply_entry(const entry &e) {
//        m_entry = e;
//
//        // chain id
//        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
//        {
//            auto chain_id = i->string();
//            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
//        }
//        // tx hash
//        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
//        {
//            auto hash = i->string();
//            m_hash = sha256_hash(hash.data());
//        }
//    }
//
//    entry block_reply_entry::get_entry() const {
//        entry e(entry::dictionary_t);
//        // data type id
//        e[entry_type] = entry(data_type_id);
//        // chain id
//        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
//        // block hash
//        e[entry_value] = entry(m_hash.to_string());
//
//        return e;
//    }


//    tx_pool_entry::tx_pool_entry(const entry &e) {
//        m_entry = e;
//
//        // chain id
//        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
//        {
//            auto chain_id = i->string();
//            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
//        }
//        // tx pool levenshtein array
//        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
//        {
//            entry v = entry(*i);
//            if (auto* p = const_cast<entry *>(v.find_key("v1")))
//            {
//                std::string levenshtein_array = p->string();
//                m_fee_pooL_levenshtein_array = aux::bytes(levenshtein_array.begin(), levenshtein_array.end());
//            }
//            if (auto* p = const_cast<entry *>(v.find_key("v2")))
//            {
//                std::string levenshtein_array = p->string();
//                m_time_pooL_levenshtein_array = aux::bytes(levenshtein_array.begin(), levenshtein_array.end());
//            }
//        }
//    }
//
//    entry tx_pool_entry::get_entry() const {
//        entry e(entry::dictionary_t);
//        // data type id
//        e[entry_type] = entry(data_type_id);
//        // chain id
//        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
//        // message levenshtein array
//        entry v(entry::dictionary_t);
//        v["v1"] = entry(std::string(m_fee_pooL_levenshtein_array.begin(), m_fee_pooL_levenshtein_array.end()));
//        v["v2"] = entry(std::string(m_time_pooL_levenshtein_array.begin(), m_time_pooL_levenshtein_array.end()));
//        e[entry_value] = v;
//
//        return e;
//    }


    gossip_peers_entry::gossip_peers_entry(const entry &e) {
        m_entry = e;

        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
        // gossip peers
        if (auto* i = const_cast<entry *>(e.find_key(entry_value)))
        {
            entry::list_type lst = i->list();
            for (const auto& n: lst) {
                m_peers.insert(dht::public_key(n.string().data()));
            }
        }
        // balance
        if (auto* i = const_cast<entry *>(e.find_key("b")))
        {
            m_balance = i->integer();
        }
    }

    entry gossip_peers_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // gossip peers
        entry::list_type l;
        for (auto const& peer: m_peers) {
            l.push_back(entry(std::string(peer.bytes.begin(), peer.bytes.end())));
        }
        e[entry_value] = l;
        // balance
        e["b"] = entry(m_balance);

        return e;
    }

    fee_tx_pool_entry::fee_tx_pool_entry(const entry &e) {
        m_entry = e;

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
            m_fee_pooL_levenshtein_array = aux::bytes(levenshtein_array.begin(), levenshtein_array.end());
        }
    }

    entry fee_tx_pool_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // message levenshtein array
        e[entry_value] = entry(std::string(m_fee_pooL_levenshtein_array.begin(), m_fee_pooL_levenshtein_array.end()));

        return e;
    }

    time_tx_pool_entry::time_tx_pool_entry(const entry &e) {
        m_entry = e;

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
            m_time_pooL_levenshtein_array = aux::bytes(levenshtein_array.begin(), levenshtein_array.end());
        }
    }

    entry time_tx_pool_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));
        // message levenshtein array
        e[entry_value] = entry(std::string(m_time_pooL_levenshtein_array.begin(), m_time_pooL_levenshtein_array.end()));

        return e;
    }

    stop_entry::stop_entry(const entry &e) {
        m_entry = e;

        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
    }

    entry stop_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));

        return e;
    }

    ping_entry::ping_entry(const entry &e) {
        m_entry = e;

        // chain id
        if (auto* i = const_cast<entry *>(e.find_key(entry_chain_id)))
        {
            auto chain_id = i->string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
        }
    }

    entry ping_entry::get_entry() const {
        entry e(entry::dictionary_t);
        // data type id
        e[entry_type] = entry(data_type_id);
        // chain id
        e[entry_chain_id] = entry(std::string(m_chain_id.begin(), m_chain_id.end()));

        return e;
    }

}
