/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BLOCK_HPP
#define LIBTAU_BLOCK_HPP

#include <utility>
#include <ostream>

#include "libTAU/address.hpp"
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"
#include "libTAU/blockchain/constants.hpp"
#include "libTAU/blockchain/transaction.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/hasher.hpp"
#include "libTAU/socket.hpp" // for tcp::endpoint

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
              const sha1_hash &mPreviousBlockHash, uint64_t mBaseTarget, uint64_t mCumulativeDifficulty,
              const sha1_hash &mGenerationSignature, const sha1_hash &mMultiplexHash, transaction mTx,
              const dht::public_key &mMiner) : m_chain_id(std::move(mChainId)), m_version(mVersion),
                                               m_timestamp(mTimestamp), m_block_number(mBlockNumber),
                                               m_previous_block_hash(mPreviousBlockHash), m_base_target(mBaseTarget),
                                               m_cumulative_difficulty(mCumulativeDifficulty),
                                               m_generation_signature(mGenerationSignature), m_multiplex_hash(mMultiplexHash),
                                               m_tx(std::move(mTx)), m_miner(mMiner) {}

        block(aux::bytes mChainId, block_version mVersion, int64_t mTimestamp, int64_t mBlockNumber,
              const sha1_hash &mPreviousBlockHash, uint64_t mBaseTarget, uint64_t mCumulativeDifficulty,
              const sha1_hash &mGenerationSignature, const sha1_hash &mMultiplexHash, transaction mTx,
              const dht::public_key &mMiner, const dht::signature &mSignature, const sha1_hash &mHash) :
                m_chain_id(std::move(mChainId)), m_version(mVersion), m_timestamp(mTimestamp),
                m_block_number(mBlockNumber), m_previous_block_hash(mPreviousBlockHash), m_base_target(mBaseTarget),
                m_cumulative_difficulty(mCumulativeDifficulty), m_generation_signature(mGenerationSignature),
                m_multiplex_hash(mMultiplexHash), m_tx(std::move(mTx)), m_miner(mMiner), m_signature(mSignature),
                m_hash(mHash) {}

//        block(aux::bytes mChainId, block_version mVersion, int64_t mTimestamp, int64_t mBlockNumber,
//              const sha1_hash &mPreviousBlockHash, uint64_t mBaseTarget, uint64_t mCumulativeDifficulty,
//              const sha1_hash &mGenerationSignature, const sha1_hash &mStateRoot, transaction mTx,
//              const dht::public_key &mMiner, udp::endpoint mEndpoint) : m_chain_id(std::move(mChainId)),
//              m_version(mVersion), m_timestamp(mTimestamp), m_block_number(mBlockNumber),
//              m_previous_block_hash(mPreviousBlockHash), m_base_target(mBaseTarget),
//              m_cumulative_difficulty(mCumulativeDifficulty), m_generation_signature(mGenerationSignature),
//              m_state_root(mStateRoot), m_tx(std::move(mTx)), m_miner(mMiner), m_endpoint(std::move(mEndpoint)) {}

        const aux::bytes &chain_id() const { return m_chain_id; }

        block_version version() const { return m_version; }

        int64_t timestamp() const { return m_timestamp; }

        int64_t block_number() const { return m_block_number; }

        const sha1_hash &previous_block_hash() const { return m_previous_block_hash; }

        uint64_t base_target() const { return m_base_target; }

        uint64_t cumulative_difficulty() const { return m_cumulative_difficulty; }

        const sha1_hash &generation_signature() const { return m_generation_signature; }

        const sha1_hash &state_root() const { return m_multiplex_hash; }

        const sha1_hash &multiplex_hash() const { return m_multiplex_hash; }

        const sha1_hash &genesis_block_hash() const;

        const transaction &tx() const { return m_tx; }

        const dht::public_key &miner() const { return m_miner; }

//        int64_t miner_balance() const { return m_miner_balance; }
//
//        int64_t miner_nonce() const { return m_miner_nonce; }
//
//        int64_t sender_balance() const { return m_sender_balance; }
//
//        int64_t sender_nonce() const { return m_sender_nonce; }
//
//        int64_t receiver_balance() const { return m_receiver_balance; }
//
//        int64_t receiver_nonce() const { return m_receiver_nonce; }

//        const udp::endpoint &end_point() const { return m_endpoint; }

        const dht::signature &signature() const { return m_signature; }

        bool empty() const { return m_hash.is_all_zeros(); }

        entry get_entry() const;

        std::string get_encode() const;

        // @returns the SHA1 hash of this block
        const sha1_hash &sha1() const { return m_hash; }

        void sign(dht::public_key const& pk, dht::secret_key const& sk);

        bool verify_signature() const;

        std::set<dht::public_key> get_block_peers() const;

        bool operator==(const block &rhs) const {
            return m_hash == rhs.m_hash;
        }

        bool operator!=(const block &rhs) const {
            return !(rhs == *this);
        }

        bool operator<(const block &rhs) const {
            return m_hash < rhs.m_hash;
        }

        // @returns a pretty-printed string representation of block structure
        std::string to_string() const;

        friend std::ostream &operator<<(std::ostream &os, const block &block);

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
        sha1_hash m_previous_block_hash;

        // base target
        std::uint64_t m_base_target{};

        // cumulative difficulty
        std::uint64_t m_cumulative_difficulty{};

        // generation signature
        sha1_hash m_generation_signature;

        // state root/genesis block hash
        sha1_hash m_multiplex_hash;

        // tx
        transaction m_tx;

        // miner
        dht::public_key m_miner{};

//        // miner balance
//        std::int64_t m_miner_balance{};
//
//        // miner nonce
//        std::int64_t m_miner_nonce{};
//
//        // sender balance
//        std::int64_t m_sender_balance{};
//
//        // sender nonce
//        std::int64_t m_sender_nonce{};
//
//        // receiver balance
//        std::int64_t m_receiver_balance{};
//
//        // receiver nonce
//        std::int64_t m_receiver_nonce{};

//        udp::endpoint m_endpoint;

        // signature
        dht::signature m_signature{};

        // sha1 hash
        sha1_hash m_hash;
    };
}
}


#endif //LIBTAU_BLOCK_HPP
