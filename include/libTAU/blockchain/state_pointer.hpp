/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_STATE_POINTER_HPP
#define LIBTAU_STATE_POINTER_HPP


#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/sha1_hash.hpp"

namespace libTAU::blockchain {
    class state_pointer {
    public:
        state_pointer() = default;

        // @param Construct with entry
        explicit state_pointer(const entry& e);

        // @param Construct with bencode
        explicit state_pointer(std::string encode): state_pointer(bdecode(encode)) {}

        explicit state_pointer(const sha256_hash &blockHash) :
                m_latest_block_hash(blockHash), m_oldest_block_hash(blockHash) {}

        state_pointer(const sha256_hash &mLatestBlockHash, const sha256_hash &mOldestBlockHash) :
                m_latest_block_hash(mLatestBlockHash), m_oldest_block_hash(mOldestBlockHash) {}

        void setInitialBlockHash(const sha256_hash &blockHash) {
            m_latest_block_hash = blockHash;
            m_oldest_block_hash = blockHash;
        }

        const sha256_hash &latest_block_hash() const {
            return m_latest_block_hash;
        }

        void setFirstBlockHash(const sha256_hash &mLatestBlockHash) {
            m_latest_block_hash = mLatestBlockHash;
        }

        const sha256_hash &oldest_block_hash() const {
            return m_oldest_block_hash;
        }

        void setLastBlockHash(const sha256_hash &mOldestBlockHash) {
            m_oldest_block_hash = mOldestBlockHash;
        }

        bool empty() { return m_latest_block_hash.is_all_zeros() && m_oldest_block_hash.is_all_zeros(); }

        entry get_entry() const;

        std::string get_encode() const;

    private:

        // populate state pointer data from entry
        void populate(const entry& e);

        // latest block hash
        sha256_hash m_latest_block_hash;

        // oldest block hash
        sha256_hash m_oldest_block_hash;
    };
}


#endif //LIBTAU_STATE_POINTER_HPP
