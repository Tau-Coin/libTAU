/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/index_key_info.hpp"


namespace libTAU::blockchain {

    index_key_info::index_key_info(const entry &e) {
        populate(e);
    }

    entry index_key_info::get_entry() const {
        entry e(entry::dictionary_t);

        // main chain block hash
        e["m"] = entry(m_main_chain_block_hash.to_string());

        // block hash no non-main chain
        entry::list_type non_main_hash_list;
        for (auto const& hash: m_non_main_chain_block_hash_set) {
            non_main_hash_list.push_back(hash.to_string());
        }
        e["n"] = non_main_hash_list;

        // associated peers
        entry::list_type peer_list;
        for (auto const& peer: m_associated_peers) {
            peer_list.push_back(entry(std::string(peer.bytes.begin(), peer.bytes.end())));
        }
        e["p"] = peer_list;

        return e;
    }

    std::string index_key_info::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    void index_key_info::populate(const entry &e) {
        // main chain block hash
        if (auto* i = const_cast<entry *>(e.find_key("m")))
        {
            m_main_chain_block_hash = sha256_hash(i->string().data());
        }
        // block hash no non-main chain
        if (auto* i = const_cast<entry *>(e.find_key("n")))
        {
            auto & lst = i->list();
            for (auto const& hash: lst) {
                m_non_main_chain_block_hash_set.emplace(hash.string().data());
            }
        }
        // associated peers
        if (auto* i = const_cast<entry *>(e.find_key("p")))
        {
            auto & lst = i->list();
            for (auto const& peer: lst) {
                m_associated_peers.emplace(peer.string().data());
            }
        }
    }

    std::string index_key_info::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const index_key_info &info) {
        os << "m_main_chain_block_hash: " << aux::toHex(info.m_main_chain_block_hash) << " m_non_main_chain_block_hash_set: ";
        for (auto const& hash: info.m_non_main_chain_block_hash_set) {
            os << " hash:" << aux::toHex(hash.to_string());
        }
        os << " m_associated_peers: ";
        for (auto const& peer: info.m_associated_peers) {
            os << " peer:" << aux::toHex(peer.bytes);
        }

        return os;
    }

}
