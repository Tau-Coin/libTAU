/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_ENTRY_TYPE_HPP
#define LIBTAU_ENTRY_TYPE_HPP

#include <utility>
#include <ostream>

#include "libTAU/aux_/export.hpp"
#include "libTAU/blockchain/account.hpp"
#include "libTAU/blockchain/block.hpp"
#include "libTAU/blockchain/constants.hpp"
#include "libTAU/blockchain/vote.hpp"
#include "libTAU/communication/message.hpp"
#include "libTAU/entry.hpp"

namespace libTAU::common {

    // salt length (first 12 bytes of public key)
    constexpr int salt_pubkey_length = 12;

    // TODO:: tlv
    const std::string protocol_type = "p";
    const std::string entry_type = "t";
    const std::string entry_short_chain_id = "s";
    const std::string entry_value = "v";
    const std::string entry_chain_id = "i";
    const std::string entry_time = "m";
    const std::string entry_levenshtein_array = "l";

    enum signal_id {
        BLOCKCHAIN_ALL_DATA = 20, // 0
        BLOCKCHAIN_ALL_BLOCKS, // 1
        BLOCKCHAIN_ALL_STATE, // 2
        BLOCKCHAIN_ONLINE, // 3
        BLOCKCHAIN_NEW_HEAD_BLOCK, // 4
        BLOCKCHAIN_NEW_TRANSFER_TX, // 5
        BLOCKCHAIN_NEW_NOTE_TX, // 6
        COMMUNICATION_NEW_MESSAGE, // 7
        COMMUNICATION_MESSAGE_MISSING, // 8
        COMMUNICATION_PUT_DONE, // 9
        COMMUNICATION_CONFIRMATION, // 10
        COMMUNICATION_ATTENTION, // 11
    };

    struct TORRENT_EXPORT signal_entry {
        // @param Construct with entry
        explicit signal_entry(const entry& e);

        // @param Construct with bencode
        explicit signal_entry(std::string encode): signal_entry(bdecode(encode)) {}

        signal_entry(signal_id mPid, int64_t mTimestamp) : m_pid(mPid), m_timestamp(mTimestamp) {}

        signal_entry(signal_id mPid, aux::bytes mShortChainId, int64_t mTimestamp) : m_pid(mPid),
            m_short_chain_id(std::move(mShortChainId)), m_timestamp(mTimestamp) {}

        signal_entry(signal_id mPid, aux::bytes mShortChainId, int64_t mTimestamp,
                     const dht::public_key &mGossipPeer) : m_pid(mPid), m_short_chain_id(std::move(mShortChainId)),
                                                           m_timestamp(mTimestamp), m_gossip_peer(mGossipPeer) {}

        signal_entry(signal_id mPid, int64_t mTimestamp, const sha1_hash &mHash)
                : m_pid(mPid), m_timestamp(mTimestamp), m_hash(mHash) {}

        signal_entry(signal_id mPid, aux::bytes mShortChainId, int64_t mTimestamp, const sha1_hash &mHash)
                : m_pid(mPid), m_short_chain_id(std::move(mShortChainId)), m_timestamp(mTimestamp), m_hash(mHash) {}

        signal_entry(signal_id mPid, aux::bytes mShortChainId, int64_t mTimestamp, const sha1_hash &mHash,
                     const dht::public_key &mGossipPeer) : m_pid(mPid), m_short_chain_id(std::move(mShortChainId)),
                                                           m_timestamp(mTimestamp), m_hash(mHash),
                                                           m_gossip_peer(mGossipPeer) {}

        entry get_entry();

        std::string get_encode();

        // protocol id
        signal_id m_pid;

        // data type id
        aux::bytes m_short_chain_id;

        // timestamp
        std::int64_t m_timestamp{};

        // hash
        sha1_hash m_hash;

        // gossip peer
        dht::public_key m_gossip_peer;
    };

    struct TORRENT_EXPORT gossip_cache_peers_entry {
        // data type id
        static inline constexpr std::int64_t data_type_id = 8;

        // @param Construct with entry
        explicit gossip_cache_peers_entry(const entry& e);

        // @param Construct with bencode
        explicit gossip_cache_peers_entry(std::string encode): gossip_cache_peers_entry(bdecode(encode)) {}

        explicit gossip_cache_peers_entry(std::set<dht::public_key> mPeers) : m_peers(std::move(mPeers)) {}

        // @returns the corresponding entry
        entry get_entry() const;

        std::set<dht::public_key> m_peers;
    };

    struct TORRENT_EXPORT voting_block_cache_entry {
        // data type id
        static inline constexpr std::int64_t data_type_id = 9;

        // @param Construct with entry
        explicit voting_block_cache_entry(const entry& e);

        // @param Construct with bencode
        explicit voting_block_cache_entry(std::string encode): voting_block_cache_entry(bdecode(encode)) {}

        explicit voting_block_cache_entry(blockchain::block mBlk) : m_blk(std::move(mBlk)) {}

        // @returns the corresponding entry
        entry get_entry() const;

        blockchain::block m_blk;
    };

    struct communication_entry_base {
        virtual std::int64_t get_data_type_id() const = 0;

        virtual entry get_entry() const = 0;

        virtual entry get_real_payload_entry() const = 0;

        virtual void set_timestamp(std::int64_t t) = 0;

        bool operator<(const communication_entry_base &rhs) const {
            return m_real_payload_hash < rhs.m_real_payload_hash;
        }

        // timestamp
        std::int64_t m_timestamp{};

        sha1_hash m_real_payload_hash;
    };

    struct less_communication_entry_base: std::binary_function<const std::shared_ptr<communication_entry_base>&, const std::shared_ptr<communication_entry_base>&, bool>
    {
        bool operator() (const std::shared_ptr<communication_entry_base>& lhs, const std::shared_ptr<communication_entry_base>& rhs) const { return *lhs < *rhs; }
    };

    struct blockchain_entry_base {
        virtual entry get_entry() const = 0;

        bool operator<(const blockchain_entry_base &rhs) const {
            if (m_chain_id < rhs.m_chain_id)
                return true;
            if (rhs.m_chain_id < m_chain_id)
                return false;

            std::string encode;
            bencode(std::back_inserter(encode), m_entry);
            std::string rhs_encode;
            bencode(std::back_inserter(rhs_encode), rhs.m_entry);
            if (encode < rhs_encode)
                return true;
            if (encode > rhs_encode)
                return false;
        }

        friend std::ostream &operator<<(std::ostream &os, const blockchain_entry_base &base) {
            os << "m_entry: " << base.m_entry.to_string(true);
            return os;
        }

        // chain id
        aux::bytes m_chain_id;

        // entry
        entry m_entry;
    };

    struct less_blockchain_entry_base: std::binary_function<const std::unique_ptr<blockchain_entry_base>&, const std::unique_ptr<blockchain_entry_base>&, bool>
    {
        bool operator() (const std::unique_ptr<blockchain_entry_base>& lhs, const std::unique_ptr<blockchain_entry_base>& rhs) const { return *lhs < *rhs; }
    };

    struct TORRENT_EXPORT entry_task {
        entry_task(int64_t mDataTypeId, entry mEntry)
                : m_data_type_id(mDataTypeId), m_entry(std::move(mEntry)) {}

        entry_task(int64_t mDataTypeId, const dht::public_key &mPeer, entry mEntry)
                : m_data_type_id(mDataTypeId), m_peer(mPeer), m_entry(std::move(mEntry)) {}

        entry_task(int64_t mDataTypeId, const dht::public_key &mPeer) : m_data_type_id(mDataTypeId),
                                                                                            m_peer(mPeer) {}

//        entry_task(int mAlpha, int mBeta, int mInvokeNumber, int64_t mDataTypeId, const dht::public_key &mPeer)
//                : m_alpha(mAlpha), m_beta(mBeta), m_invoke_number(mInvokeNumber), m_data_type_id(mDataTypeId),
//                m_peer(mPeer) {}
//
//        entry_task(int mAlpha, int mBeta, int mInvokeNumber, int64_t mDataTypeId, const dht::public_key &mPeer,
//                   entry mEntry) : m_alpha(mAlpha), m_beta(mBeta), m_invoke_number(mInvokeNumber),
//                   m_data_type_id(mDataTypeId), m_peer(mPeer), m_entry(std::move(mEntry)) {}

        bool operator==(const entry_task &rhs) const {
            return m_data_type_id == rhs.m_data_type_id &&
                   m_peer == rhs.m_peer &&
                   m_entry == rhs.m_entry;
        }

        bool operator!=(const entry_task &rhs) const {
            return !(rhs == *this);
        }

        bool operator<(const entry_task &rhs) const {

            if (m_peer < rhs.m_peer)
                return true;
            if (m_peer > rhs.m_peer)
                return false;

            if (m_data_type_id != 1) {
                std::string encode;
                bencode(std::back_inserter(encode), m_entry);
                std::string rhs_encode;
                bencode(std::back_inserter(rhs_encode), rhs.m_entry);
                if (encode < rhs_encode)
                    return true;
                if (encode > rhs_encode)
                    return false;
            }

            return false;
        }

        bool operator>(const entry_task &rhs) const {
            return rhs < *this;
        }

        bool operator<=(const entry_task &rhs) const {
            return !(rhs < *this);
        }

        bool operator>=(const entry_task &rhs) const {
            return !(*this < rhs);
        }

//        int m_alpha = 1;
//
//        int m_beta = 3;
//
//        int m_invoke_number = 3;

        std::int64_t m_data_type_id;

        dht::public_key m_peer;

        entry m_entry;
    };

    struct TORRENT_EXPORT blockchain_entry_task {

        blockchain_entry_task(aux::bytes mChainId, int64_t mDataTypeId, entry mEntry) :
                m_chain_id(std::move(mChainId)), m_data_type_id(mDataTypeId), m_entry(std::move(mEntry)) {}

        blockchain_entry_task(aux::bytes mChainId, int64_t mDataTypeId, const dht::public_key &mPeer, entry mEntry) :
                m_chain_id(std::move(mChainId)), m_data_type_id(mDataTypeId), m_peer(mPeer), m_entry(std::move(mEntry)) {}

        bool operator==(const blockchain_entry_task &rhs) const {
            return m_data_type_id == rhs.m_data_type_id &&
                   m_peer == rhs.m_peer &&
                   m_entry == rhs.m_entry;
        }

        bool operator!=(const blockchain_entry_task &rhs) const {
            return !(rhs == *this);
        }

        bool operator<(const blockchain_entry_task &rhs) const {

            if (m_chain_id < rhs.m_chain_id)
                return true;
            if (m_chain_id > rhs.m_chain_id)
                return false;

            if (m_peer < rhs.m_peer)
                return true;
            if (m_peer > rhs.m_peer)
                return false;

            std::string encode;
            bencode(std::back_inserter(encode), m_entry);
            std::string rhs_encode;
            bencode(std::back_inserter(rhs_encode), rhs.m_entry);
            if (encode < rhs_encode)
                return true;
            if (encode > rhs_encode)
                return false;

            return false;
        }

        bool operator>(const blockchain_entry_task &rhs) const {
            return rhs < *this;
        }

        bool operator<=(const blockchain_entry_task &rhs) const {
            return !(rhs < *this);
        }

        bool operator>=(const blockchain_entry_task &rhs) const {
            return !(*this < rhs);
        }

        aux::bytes m_chain_id;

        std::int64_t m_data_type_id;

        dht::public_key m_peer;

        entry m_entry;
    };

//    struct TORRENT_EXPORT communication_entries final : entry_base {
//        // data type id
//        static inline constexpr std::int64_t protocol_id = 0;
//
//        communication_entries() = default;
//
//        // @param Construct with entry
//        explicit communication_entries(const entry& e);
//
//        explicit communication_entries(std::vector<entry> mEntries) : m_entries(std::move(mEntries)) {}
//
//        void push_back(const entry& e) { m_entries.push_back(e); }
//
//        void pop_back() { m_entries.pop_back(); }
//
//        // @returns the corresponding entry
//        entry get_entry() const override;
//
//        std::vector<entry> m_entries;
//    };

//    struct TORRENT_EXPORT blockchain_entries final : entry_base {
//        // data type id
//        static inline constexpr std::int64_t protocol_id = 1;
//
//        blockchain_entries() = default;
//
//        // @param Construct with entry
//        explicit blockchain_entries(const entry& e);
//
//        explicit blockchain_entries(std::vector<entry> mEntries) : m_entries(std::move(mEntries)) {}
//
//        void push_back(const entry& e) { m_entries.push_back(e); }
//
//        void pop_back() { m_entries.pop_back(); }
//
//        // @returns the corresponding entry
//        entry get_entry() const override;
//
//        std::vector<entry> m_entries;
//    };

    struct TORRENT_EXPORT message_entry final : communication_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 50;

        // @param Construct with entry
        explicit message_entry(const entry& e);

        explicit message_entry(communication::message mMsg) : m_msg(std::move(mMsg)) {
            auto et = get_real_payload_entry();
            std::string encode;
            bencode(std::back_inserter(encode), et);
            m_real_payload_hash = hasher(encode).final();
        }

//        message_entry(communication::message mMsg, int64_t mTimestamp) : m_msg(std::move(mMsg)), m_timestamp(mTimestamp) {}

        message_entry(communication::message mMsg, aux::bytes mLevenshteinArray, int64_t mTimestamp)
                : m_msg(std::move(mMsg)), m_levenshtein_array(std::move(mLevenshteinArray)) {
            m_timestamp = mTimestamp;

            auto et = get_real_payload_entry();
            std::string encode;
            bencode(std::back_inserter(encode), et);
            m_real_payload_hash = hasher(encode).final();
        }

        std::int64_t get_data_type_id() const override { return data_type_id; }

        // @returns the corresponding entry
        entry get_entry() const override;

        // @returns the corresponding entry
        entry get_real_payload_entry() const override;

        void set_levenshtein_array(const aux::bytes &mLevenshteinArray) {
            m_levenshtein_array = mLevenshteinArray;
        }

        void set_timestamp(std::int64_t t) override {
            m_timestamp = t;
        }

        bool operator<(const message_entry &rhs) const {
            if (m_msg < rhs.m_msg)
                return true;
            if (rhs.m_msg < m_msg)
                return false;
            return m_levenshtein_array < rhs.m_levenshtein_array;
        }

        communication::message m_msg;

        // bytes consist of first byte of ordered messages hash
        aux::bytes m_levenshtein_array;
    };

    struct TORRENT_EXPORT message_levenshtein_array_entry final : communication_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 51;

        message_levenshtein_array_entry();

        // @param Construct with entry
        explicit message_levenshtein_array_entry(const entry& e);

//        explicit message_levenshtein_array_entry(aux::bytes mLevenshteinArray) : m_levenshtein_array(std::move(mLevenshteinArray)) {}

        message_levenshtein_array_entry(aux::bytes mLevenshteinArray, int64_t mTimestamp) : m_levenshtein_array(std::move(mLevenshteinArray)) {
            m_timestamp = mTimestamp;

            auto et = get_real_payload_entry();
            std::string encode;
            bencode(std::back_inserter(encode), et);
            m_real_payload_hash = hasher(encode).final();
        }

        std::int64_t get_data_type_id() const override { return data_type_id; }

        // @returns the corresponding entry
        entry get_entry() const override;

        // @returns the corresponding entry
        entry get_real_payload_entry() const override;

        void set_timestamp(std::int64_t t) override {
            m_timestamp = t;
        }

        bool operator<(const message_levenshtein_array_entry &rhs) const {
            return m_levenshtein_array < rhs.m_levenshtein_array;
        }

        // bytes consist of first byte of ordered messages hash
        aux::bytes m_levenshtein_array;
    };

//    struct TORRENT_EXPORT friend_info_request_entry final : communication_entry_base {
//        // data type id
//        static inline constexpr std::int64_t data_type_id = 52;
//
//        friend_info_request_entry();
//
//        // @param Construct with entry
//        explicit friend_info_request_entry(const entry& e);
//
//        explicit friend_info_request_entry(int64_t mTimestamp) {
//            m_timestamp = mTimestamp;
//
//            auto et = get_real_payload_entry();
//            std::string encode;
//            bencode(std::back_inserter(encode), et);
//            m_real_payload_hash = dht::item_target_id(encode);
//        }
//
//        std::int64_t get_data_type_id() const override { return data_type_id; }
//
//        // @returns the corresponding entry
//        entry get_entry() const override;
//
//        // @returns the corresponding entry
//        entry get_real_payload_entry() const override;
//
//        void set_timestamp(std::int64_t t) override {
//            m_timestamp = t;
//        }
//
//        bool operator<(const friend_info_request_entry &rhs) const {
//            return false;
//        }
//    };
//
//    struct TORRENT_EXPORT friend_info_entry final : communication_entry_base {
//        // data type id
//        static inline constexpr std::int64_t data_type_id = 53;
//
//        // @param Construct with entry
//        explicit friend_info_entry(const entry& e);
//
//        explicit friend_info_entry(aux::bytes mFriendInfo) : m_friend_info(std::move(mFriendInfo)) {
//            auto et = get_real_payload_entry();
//            std::string encode;
//            bencode(std::back_inserter(encode), et);
//            m_real_payload_hash = dht::item_target_id(encode);
//        }
//
//        friend_info_entry(aux::bytes mFriendInfo, int64_t mTimestamp) : m_friend_info(std::move(mFriendInfo)) {
//            m_timestamp = mTimestamp;
//
//            auto et = get_real_payload_entry();
//            std::string encode;
//            bencode(std::back_inserter(encode), et);
//            m_real_payload_hash = dht::item_target_id(encode);
//        }
//
//        std::int64_t get_data_type_id() const override { return data_type_id; }
//
//        // @returns the corresponding entry
//        entry get_entry() const override;
//
//        // @returns the corresponding entry
//        entry get_real_payload_entry() const override;
//
//        void set_timestamp(std::int64_t t) override {
//            m_timestamp = t;
//        }
//
//        bool operator<(const friend_info_entry &rhs) const {
//            return m_friend_info < rhs.m_friend_info;
//        }
//
//        aux::bytes m_friend_info;
//    };

    struct TORRENT_EXPORT event_entry final : communication_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 54;

        // @param Construct with entry
        explicit event_entry(const entry& e);

        explicit event_entry(aux::bytes mValue) : m_value(std::move(mValue)) {
            auto et = get_real_payload_entry();
            std::string encode;
            bencode(std::back_inserter(encode), et);
            m_real_payload_hash = hasher(encode).final();
        }

        event_entry(aux::bytes mValue, int64_t mTimestamp) : m_value(std::move(mValue)) {
            m_timestamp = mTimestamp;

            auto et = get_real_payload_entry();
            std::string encode;
            bencode(std::back_inserter(encode), et);
            m_real_payload_hash = hasher(encode).final();
        }

        std::int64_t get_data_type_id() const override { return data_type_id; }

        // @returns the corresponding entry
        entry get_entry() const override;

        // @returns the corresponding entry
        entry get_real_payload_entry() const override;

        void set_timestamp(std::int64_t t) override {
            m_timestamp = t;
        }

        aux::bytes m_value;
    };



    struct TORRENT_EXPORT block_request_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 61;

        // @param Construct with entry
        explicit block_request_entry(const entry& e);

        block_request_entry(aux::bytes mChainId, const sha1_hash &mHash) : m_hash(mHash) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        bool operator<(const block_request_entry &rhs) const {
            if (m_chain_id < rhs.m_chain_id)
                return true;
            if (rhs.m_chain_id < m_chain_id)
                return false;
            return m_hash < rhs.m_hash;
        }

        sha1_hash m_hash;
    };

    struct TORRENT_EXPORT block_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 62;

        // @param Construct with entry
        explicit block_entry(const entry& e);

        explicit block_entry(blockchain::block mBlk) : m_blk(std::move(mBlk)) {
            m_chain_id = m_blk.chain_id();

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        bool operator<(const block_entry &rhs) const {
            return m_blk < rhs.m_blk;
        }

        blockchain::block m_blk;
    };

    struct TORRENT_EXPORT transaction_request_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 63;

        // @param Construct with entry
        explicit transaction_request_entry(const entry& e);

        transaction_request_entry(aux::bytes mChainId, const sha1_hash &mHash) : m_hash(mHash) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        bool operator<(const transaction_request_entry &rhs) const {
            if (m_chain_id < rhs.m_chain_id)
                return true;
            if (rhs.m_chain_id < m_chain_id)
                return false;
            return m_hash < rhs.m_hash;
        }

        sha1_hash m_hash;
    };

    struct TORRENT_EXPORT transaction_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 64;

        // @param Construct with entry
        explicit transaction_entry(const entry& e);

        explicit transaction_entry(blockchain::transaction mTx) : m_tx(std::move(mTx)) {
            m_chain_id = m_tx.chain_id();

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        bool operator<(const transaction_entry &rhs) const {
            return m_tx < rhs.m_tx;
        }

        blockchain::transaction m_tx;
    };

//    struct TORRENT_EXPORT vote_request_entry final : blockchain_entry_base {
//        // data type id
//        static inline constexpr std::int64_t data_type_id = 305;
//
//        // @param Construct with entry
//        explicit vote_request_entry(const entry& e);
//
//        explicit vote_request_entry(aux::bytes mChainId) {
//            m_chain_id = std::move(mChainId);
//
//            m_entry = get_entry();
//        }
//
//        // @returns the corresponding entry
//        entry get_entry() const override;
//
//        bool operator<(const vote_request_entry &rhs) const {
//            return m_chain_id < rhs.m_chain_id;
//        }
//    };
//
//    struct TORRENT_EXPORT vote_entry final : blockchain_entry_base {
//        // data type id
//        static inline constexpr std::int64_t data_type_id = 306;
//
//        // @param Construct with entry
//        explicit vote_entry(const entry& e);
//
//        vote_entry(aux::bytes mChainId, const blockchain::vote &mVote) : m_vote(mVote) {
//            m_chain_id = std::move(mChainId);
//
//            m_entry = get_entry();
//        }
//
//        // @returns the corresponding entry
//        entry get_entry() const override;
//
//        bool operator<(const vote_entry &rhs) const {
//            if (m_chain_id < rhs.m_chain_id)
//                return true;
//            if (rhs.m_chain_id < m_chain_id)
//                return false;
//            return m_vote < rhs.m_vote;
//        }
//
//        blockchain::vote m_vote;
//    };

    struct TORRENT_EXPORT head_block_request_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 65;

        // @param Construct with entry
        explicit head_block_request_entry(const entry& e);

        explicit head_block_request_entry(aux::bytes mChainId) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        bool operator<(const head_block_request_entry &rhs) const {
            return m_chain_id < rhs.m_chain_id;
        }
    };

    struct TORRENT_EXPORT head_block_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 66;

        // @param Construct with entry
        explicit head_block_entry(const entry& e);

        explicit head_block_entry(blockchain::block mBlk) : m_blk(std::move(mBlk)) {
            m_chain_id = m_blk.chain_id();

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        bool operator<(const head_block_entry &rhs) const {
            return m_blk < rhs.m_blk;
        }

        blockchain::block m_blk;
    };

//    struct TORRENT_EXPORT tx_pool_request_entry final : blockchain_entry_base {
//        // data type id
//        static inline constexpr std::int64_t data_type_id = 209;
//
//        // @param Construct with entry
//        explicit tx_pool_request_entry(const entry& e);
//
//        tx_pool_request_entry(aux::bytes mChainId, aux::bytes mFeePooLLevenshteinArray, aux::bytes mTimePooLLevenshteinArray)
//                : m_fee_pooL_levenshtein_array(std::move(mFeePooLLevenshteinArray)),
//                  m_time_pooL_levenshtein_array(std::move(mTimePooLLevenshteinArray)) {
//            m_chain_id = std::move(mChainId);
//
//            m_entry = get_entry();
//        }
//
//        // @returns the corresponding entry
//        entry get_entry() const override;
//
//        // bytes consist of first byte of ordered messages hash
//        aux::bytes m_fee_pooL_levenshtein_array;
//
//        // bytes consist of first byte of ordered messages hash
//        aux::bytes m_time_pooL_levenshtein_array;
//    };

    struct TORRENT_EXPORT state_request_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 67;

        // @param Construct with entry
        explicit state_request_entry(const entry& e);

        explicit state_request_entry(aux::bytes mChainId) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        bool operator<(const state_request_entry &rhs) const {
            return m_chain_id < rhs.m_chain_id;
        }
    };

    struct TORRENT_EXPORT state_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 68;

        // @param Construct with entry
        explicit state_entry(const entry& e);

        state_entry(aux::bytes mChainId, const blockchain::account &mAct) : m_act(mAct) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        bool operator<(const state_entry &rhs) const {
            return m_chain_id < rhs.m_chain_id;
        }

        blockchain::account m_act;
    };

//    struct TORRENT_EXPORT transaction_reply_entry final : blockchain_entry_base {
//        // data type id
//        static inline constexpr std::int64_t data_type_id = 41;
//
//        // @param Construct with entry
//        explicit transaction_reply_entry(const entry& e);
//
//        transaction_reply_entry(aux::bytes mChainId, const sha256_hash &mHash) : m_hash(mHash) {
//            m_chain_id = std::move(mChainId);
//
//            m_entry = get_entry();
//        }
//
//        // @returns the corresponding entry
//        entry get_entry() const override;
//
//        bool operator<(const transaction_reply_entry &rhs) const {
//            if (m_chain_id < rhs.m_chain_id)
//                return true;
//            if (rhs.m_chain_id < m_chain_id)
//                return false;
//            return m_hash < rhs.m_hash;
//        }
//
//        sha256_hash m_hash;
//    };

//    struct TORRENT_EXPORT block_reply_entry final : blockchain_entry_base {
//        // data type id
//        static inline constexpr std::int64_t data_type_id = 42;
//
//        // @param Construct with entry
//        explicit block_reply_entry(const entry& e);
//
//        block_reply_entry(aux::bytes mChainId, const sha256_hash &mHash) : m_hash(mHash) {
//            m_chain_id = std::move(mChainId);
//
//            m_entry = get_entry();
//        }
//
//        // @returns the corresponding entry
//        entry get_entry() const override;
//
//        bool operator<(const block_reply_entry &rhs) const {
//            if (m_chain_id < rhs.m_chain_id)
//                return true;
//            if (rhs.m_chain_id < m_chain_id)
//                return false;
//            return m_hash < rhs.m_hash;
//        }
//
//        sha256_hash m_hash;
//    };

//    struct TORRENT_EXPORT tx_pool_entry final : blockchain_entry_base {
//        // data type id
//        static inline constexpr std::int64_t data_type_id = 313;
//
//        // @param Construct with entry
//        explicit tx_pool_entry(const entry& e);
//
//        explicit tx_pool_entry(aux::bytes mChainId) {
//            m_chain_id = std::move(mChainId);
//
//            m_entry = get_entry();
//        }
//
//        tx_pool_entry(aux::bytes mChainId, aux::bytes mFeePooLLevenshteinArray, aux::bytes mTimePooLLevenshteinArray)
//                : m_fee_pooL_levenshtein_array(std::move(mFeePooLLevenshteinArray)),
//                  m_time_pooL_levenshtein_array(std::move(mTimePooLLevenshteinArray)) {
//            m_chain_id = std::move(mChainId);
//
//            m_entry = get_entry();
//        }
//
//        // @returns the corresponding entry
//        entry get_entry() const override;
//
//        // bytes consist of first byte of ordered messages hash
//        aux::bytes m_fee_pooL_levenshtein_array;
//
//        // bytes consist of first byte of ordered messages hash
//        aux::bytes m_time_pooL_levenshtein_array;
//    };

    struct TORRENT_EXPORT gossip_peers_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 69;

        // @param Construct with entry
        explicit gossip_peers_entry(const entry& e);

        gossip_peers_entry(aux::bytes mChainId, std::set<dht::public_key> peers) : m_peers(std::move(peers)) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        gossip_peers_entry(aux::bytes mChainId, std::set<dht::public_key> mPeers, int64_t mBalance) :
            m_peers(std::move(mPeers)), m_balance(mBalance) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        std::set<dht::public_key> m_peers;

        std::int64_t m_balance{};
    };

    struct TORRENT_EXPORT fee_tx_pool_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 70;

        // @param Construct with entry
        explicit fee_tx_pool_entry(const entry& e);

        explicit fee_tx_pool_entry(aux::bytes mChainId) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        fee_tx_pool_entry(aux::bytes mChainId, aux::bytes mFeePooLLevenshteinArray)
                : m_fee_pooL_levenshtein_array(std::move(mFeePooLLevenshteinArray)) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        // bytes consist of first byte of ordered messages hash
        aux::bytes m_fee_pooL_levenshtein_array;
    };

    struct TORRENT_EXPORT time_tx_pool_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 71;

        // @param Construct with entry
        explicit time_tx_pool_entry(const entry& e);

        explicit time_tx_pool_entry(aux::bytes mChainId) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        time_tx_pool_entry(aux::bytes mChainId, aux::bytes mTimePooLLevenshteinArray)
                : m_time_pooL_levenshtein_array(std::move(mTimePooLLevenshteinArray)) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;

        // bytes consist of first byte of ordered messages hash
        aux::bytes m_time_pooL_levenshtein_array;
    };

    struct TORRENT_EXPORT stop_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 72;

        // @param Construct with entry
        explicit stop_entry(const entry& e);

        explicit stop_entry(aux::bytes mChainId) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;
    };

    struct TORRENT_EXPORT ping_entry final : blockchain_entry_base {
        // data type id
        static inline constexpr std::int64_t data_type_id = 77;

        // @param Construct with entry
        explicit ping_entry(const entry& e);

        explicit ping_entry(aux::bytes mChainId) {
            m_chain_id = std::move(mChainId);

            m_entry = get_entry();
        }

        // @returns the corresponding entry
        entry get_entry() const override;
    };

}


#endif //LIBTAU_ENTRY_TYPE_HPP
