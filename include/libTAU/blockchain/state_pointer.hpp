/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_STATE_POINTER_HPP
#define LIBTAU_STATE_POINTER_HPP


#include "libTAU/sha1_hash.hpp"

namespace libTAU::blockchain {
    class state_pointer {
    public:
        explicit state_pointer(const sha256_hash &blockHash) :
                m_first_block_hash(blockHash), m_last_block_hash(blockHash) {}

        state_pointer(const sha256_hash &mFirstBlockHash, const sha256_hash &mLastBlockHash) :
        m_first_block_hash(mFirstBlockHash), m_last_block_hash(mLastBlockHash) {}

        const sha256_hash &first_block_hash() const {
            return m_first_block_hash;
        }

        void setFirstBlockHash(const sha256_hash &mFirstBlockHash) {
            m_first_block_hash = mFirstBlockHash;
        }

        const sha256_hash &last_block_hash() const {
            return m_last_block_hash;
        }

        void setLastBlockHash(const sha256_hash &mLastBlockHash) {
            m_last_block_hash = mLastBlockHash;
        }

    private:
        sha256_hash m_first_block_hash;

        sha256_hash m_last_block_hash;
    };
}


#endif //LIBTAU_STATE_POINTER_HPP
