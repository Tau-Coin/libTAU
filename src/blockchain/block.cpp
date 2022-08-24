/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/kademlia/item.hpp"
#include "libTAU/kademlia/ed25519.hpp"
#include "libTAU/blockchain/block.hpp"

namespace libTAU::blockchain {
    block::block(const entry& e) {
        populate(e);

        std::string encode;
        bencode(std::back_inserter(encode), e);
        m_hash = hasher(encode).final();
    }

    const sha1_hash &block::genesis_block_hash() const {
        if (m_block_number % CHAIN_EPOCH_BLOCK_SIZE == 0) {
            return m_hash;
        } else {
            return m_multiplex_hash;
        }
    }

    entry block::get_entry() const {
        auto e = get_entry_without_signature();
        // signature
        // signature
        e.list().push_back(std::string(m_signature.bytes.begin(), m_signature.bytes.end()));

        return e;
    }

    std::string block::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

//    const sha256_hash &block::sha256() {
//        if (m_hash.is_all_zeros()) {
//            auto encode = get_encode();
//            m_hash = dht::item_target_id(encode);
//        }
//
//        return m_hash;
//    }

    void block::sign(const dht::public_key &pk, const dht::secret_key &sk) {
        m_signature = ed25519_sign(get_encode_without_signature(), pk, sk);

        auto encode = get_encode();
        m_hash = hasher(encode).final();
    }

    bool block::verify_signature() const {
        return ed25519_verify(m_signature, get_encode_without_signature(), m_miner);
    }

    std::string block::get_encode_without_signature() const {
        std::string encode;
        auto e = get_entry_without_signature();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    entry block::get_entry_without_signature() const {
        entry::list_type lst;

        // chain id
        lst.push_back(std::string(m_chain_id.begin(), m_chain_id.end()));
        // version
        auto version = aux::intToLittleEndianString((int)m_version);
        lst.push_back(version);
        // timestamp
        auto timestamp = aux::int64ToLittleEndianString(m_timestamp);
        lst.push_back(timestamp);
        // block number
        auto block_number = aux::int64ToLittleEndianString(m_block_number);
        lst.push_back(block_number);
        // previous block hash
        lst.push_back(m_previous_block_hash.to_string());
        // base target
        auto base_target = aux::uint64ToLittleEndianString(m_base_target);
        lst.push_back(base_target);
        // cumulative difficulty
        auto cumulative_difficulty = aux::uint64ToLittleEndianString(m_cumulative_difficulty);
        lst.push_back(cumulative_difficulty);
        // generation signature
        lst.push_back(m_generation_signature.to_string());
        // multiplex hash
        lst.push_back(m_multiplex_hash.to_string());
        // miner
        lst.push_back(std::string(m_miner.bytes.begin(), m_miner.bytes.end()));
        if (!m_tx.empty()) {
            // tx
            lst.push_back(m_tx.get_entry());
        }

        return lst;
    }


    void block::populate(const entry &e) {
        auto const& lst = e.list();

        if (lst.size() == 11) {
            // chain id
            auto chain_id = lst[0].string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
            // version
            int version = aux::intFromLittleEndianString(lst[1].string());
            m_version = static_cast<block_version>(version);
            // timestamp
            m_timestamp = aux::int64FromLittleEndianString(lst[2].string());
            // block number
            m_block_number = aux::int64FromLittleEndianString(lst[3].string());
            // previous block hash
            m_previous_block_hash = sha1_hash(lst[4].string().data());
            // base target
            m_base_target = aux::uint64FromLittleEndianString(lst[5].string());
            // cumulative difficulty
            m_cumulative_difficulty = aux::uint64FromLittleEndianString(lst[6].string());
            // generation signature
            m_generation_signature = sha1_hash(lst[7].string().data());
            // multiplex hash
            m_multiplex_hash = sha1_hash(lst[8].string().data());
            // miner
            m_miner = dht::public_key(lst[9].string().data());
            // signature
            m_signature = dht::signature(lst[10].string().data());
        }

        if (lst.size() == 12) {
            // chain id
            auto chain_id = lst[0].string();
            m_chain_id = aux::bytes(chain_id.begin(), chain_id.end());
            // version
            int version = aux::intFromLittleEndianString(lst[1].string());
            m_version = static_cast<block_version>(version);
            // timestamp
            m_timestamp = aux::int64FromLittleEndianString(lst[2].string());
            // block number
            m_block_number = aux::int64FromLittleEndianString(lst[3].string());
            // previous block hash
            m_previous_block_hash = sha1_hash(lst[4].string().data());
            // base target
            m_base_target = aux::uint64FromLittleEndianString(lst[5].string());
            // cumulative difficulty
            m_cumulative_difficulty = aux::uint64FromLittleEndianString(lst[6].string());
            // generation signature
            m_generation_signature = sha1_hash(lst[7].string().data());
            // multiplex hash
            m_multiplex_hash = sha1_hash(lst[8].string().data());
            // miner
            m_miner = dht::public_key(lst[9].string().data());
            // tx
            m_tx = transaction(lst[10]);
            // signature
            m_signature = dht::signature(lst[11].string().data());
        }
    }

    std::set<dht::public_key> block::get_block_peers() const {
        std::set<dht::public_key> peers;
        peers.insert(m_miner);
        if (!m_tx.empty()) {
            if (m_tx.type() == tx_type::type_transfer) {
                peers.insert(m_tx.sender());
                peers.insert(m_tx.receiver());
            } else if (m_tx.type() == tx_type::type_note) {
                peers.insert(m_tx.sender());
            }
        }

        return peers;
    }

    std::string block::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const block &block) {
        os << " block hash: " << aux::toHex(block.m_hash.to_string()) << " m_chain_id: "
           << aux::toHex(block.m_chain_id) << " m_version: " << block.m_version << " m_timestamp: "
           << block.m_timestamp << " m_block_number: " << block.m_block_number << " m_previous_block_hash: "
           << aux::toHex(block.m_previous_block_hash.to_string()) << " m_base_target: " << block.m_base_target
           << " m_cumulative_difficulty: " << block.m_cumulative_difficulty << " m_generation_signature: "
           << aux::toHex(block.m_generation_signature.to_string()) << " multiplex hash: "
           << aux::toHex(block.m_multiplex_hash.to_string()) << " m_tx: " << block.m_tx
           << " m_miner: " << aux::toHex(block.m_miner.bytes);
        return os;
    }
}