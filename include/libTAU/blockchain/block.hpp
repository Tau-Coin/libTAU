/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BLOCK_HPP
#define LIBTAU_BLOCK_HPP

#include <utility>

#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"
#include "libTAU/blockchain/transaction.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"

namespace libTAU {
namespace blockchain {

    enum block_version {
        block_version1,
        block_unknown_version,
    };

    class TORRENT_EXPORT block {
    public:
        block() = default;

        // @param Construct with entry
        explicit block(const entry& e);

        // @param Construct with bencode
        explicit block(std::string encode): block(bdecode(encode)) {}

        block(aux::bytes mChainId, block_version mVersion, int64_t mTimestamp, int64_t mBlockNumber,
                sha256_hash mPreviousBlockHash, int64_t mBaseTarget, int64_t mCumulativeDifficulty,
                sha256_hash mGenerationSignature, transaction mTx, const dht::public_key &mMiner,
              int64_t mMinerBalance, int64_t mMinerNonce, int64_t mSenderBalance, int64_t mSenderNonce,
              int64_t mReceiverBalance, int64_t mReceiverNonce) : m_chain_id(std::move(mChainId)), m_version(mVersion),
              m_timestamp(mTimestamp), m_block_number(mBlockNumber), m_previous_block_hash(mPreviousBlockHash),
              m_base_target(mBaseTarget), m_cumulative_difficulty(mCumulativeDifficulty),
              m_generation_signature(mGenerationSignature), m_tx(std::move(mTx)), m_miner(mMiner),
              m_miner_balance(mMinerBalance), m_miner_nonce(mMinerNonce), m_sender_balance(mSenderBalance),
              m_sender_nonce(mSenderNonce), m_receiver_balance(mReceiverBalance), m_receiver_nonce(mReceiverNonce) {}

        const aux::bytes &chain_id() const { return m_chain_id; }

        block_version version() const { return m_version; }

        int64_t timestamp() const { return m_timestamp; }

        int64_t block_number() const { return m_block_number; }

        const sha256_hash &previous_block_hash() const { return m_previous_block_hash; }

        int64_t base_target() const { return m_base_target; }

        int64_t cumulative_difficulty() const { return m_cumulative_difficulty; }

        const sha256_hash &generation_signature() const { return m_generation_signature; }

        const transaction &tx() const { return m_tx; }

        const dht::public_key &miner() const { return m_miner; }

        int64_t miner_balance() const { return m_miner_balance; }

        int64_t miner_nonce() const { return m_miner_nonce; }

        int64_t sender_balance() const { return m_sender_balance; }

        int64_t sender_nonce() const { return m_sender_nonce; }

        int64_t receiver_balance() const { return m_receiver_balance; }

        int64_t receiver_nonce() const { return m_receiver_nonce; }

        const dht::signature &signature() const { return m_signature; }

        bool empty() { return sha256().is_all_zeros(); }

        entry get_entry() const;

        std::string get_encode() const;

        // @returns the SHA256 hash of this block
        const sha256_hash &sha256();

        void sign(dht::public_key const& pk, dht::secret_key const& sk);

        bool verify_signature() const;

        std::set<dht::public_key> get_block_peers() const;

    private:

        std::string get_encode_without_signature() const;

        entry get_entry_without_signature() const;

        // populate block data from entry
        void populate(const entry& e);

        // chain id
        aux::bytes m_chain_id;

        // block version
        block_version m_version = block_version1;

        // timestamp
        std::int64_t m_timestamp{};

        // block number
        std::int64_t m_block_number{};

        // previous block hash
        sha256_hash m_previous_block_hash;

        // base target
        std::int64_t m_base_target{};

        // cumulative difficulty
        std::int64_t m_cumulative_difficulty{};

        // generation signature
        sha256_hash m_generation_signature;

        // tx
        transaction m_tx;

        // miner
        dht::public_key m_miner{};

        // miner balance
        std::int64_t m_miner_balance{};

        // miner nonce
        std::int64_t m_miner_nonce{};

        // sender balance
        std::int64_t m_sender_balance{};

        // sender nonce
        std::int64_t m_sender_nonce{};

        // receiver balance
        std::int64_t m_receiver_balance{};

        // receiver nonce
        std::int64_t m_receiver_nonce{};

        // signature
        dht::signature m_signature{};

        // sha256 hash
        sha256_hash m_hash;
    };
}
}


#endif //LIBTAU_BLOCK_HPP
