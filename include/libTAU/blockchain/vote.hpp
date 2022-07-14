/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_VOTE_HPP
#define LIBTAU_VOTE_HPP


#include <ostream>
#include <utility>

#include "libTAU/blockchain/block.hpp"

#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/sha1_hash.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/kademlia/types.hpp"


namespace libTAU {
    namespace blockchain {
        class TORRENT_EXPORT vote {
        public:
            vote() = default;

            // @param Construct with entry
//            explicit vote(const entry& e);

            // @param Construct with bencode
//            explicit vote(std::string encode): vote(bdecode(encode)) {}

            explicit vote(blockchain::block mBlock) : m_voting_block(std::move(mBlock)) {}

//            vote(const sha256_hash &mBlockHash, int64_t mBlockNumber) : m_block_hash(mBlockHash),
//            m_block_number(mBlockNumber) {}

//            vote(const sha256_hash &mBlockHash, uint64_t mCumulativeDifficulty, int64_t mBlockNumber) : m_block_hash(
//                    mBlockHash), m_cumulative_difficulty(mCumulativeDifficulty), m_block_number(mBlockNumber) {}

//            const sha256_hash &block_hash() const { return m_block_hash; }

//            void setBlockHash(const sha256_hash &mBlockHash) { m_block_hash = mBlockHash; }

//            int64_t block_number() const { return m_block_number; }

//            void setBlockNumber(int64_t mBlockNumber) { m_block_number = mBlockNumber; }

//            uint64_t cumulative_difficulty() const { return m_cumulative_difficulty; }

            const blockchain::block &voting_block() const { return m_voting_block; }

            int count() const { return m_count; }

            void vote_up() { m_count++; }

            bool empty() { return m_voting_block.sha1().is_all_zeros(); }

//            entry get_entry() const;
//
//            std::string get_encode() const;

            bool operator<(const vote &rhs) const {
                return m_voting_block < rhs.m_voting_block;
            }

            bool operator>(const vote &rhs) const {
                return rhs < *this;
            }

            bool operator<=(const vote &rhs) const {
                return !(rhs < *this);
            }

            bool operator>=(const vote &rhs) const {
                return !(*this < rhs);
            }

            // @returns a pretty-printed string representation of vote structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const vote &vote);

        private:
            // populate block chain signal info from entry
//            void populate(const entry& e);

//            sha256_hash m_block_hash;
//
//            // cumulative difficulty
//            std::uint64_t m_cumulative_difficulty{};
//
//            std::int64_t m_block_number{};

            blockchain::block m_voting_block;

            int m_count = 1;
        };
    }
}


#endif //LIBTAU_VOTE_HPP
