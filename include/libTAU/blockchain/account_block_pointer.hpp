/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_ACCOUNT_BLOCK_POINTER_HPP
#define LIBTAU_ACCOUNT_BLOCK_POINTER_HPP


#include <ostream>

#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"
#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/sha1_hash.hpp"

namespace libTAU::blockchain {
    class account_block_pointer {
    public:
        account_block_pointer() = default;

        // @param Construct with entry
        explicit account_block_pointer(const entry& e);

        // @param Construct with bencode
        explicit account_block_pointer(std::string encode): account_block_pointer(bdecode(encode)) {}

        explicit account_block_pointer(const sha256_hash &blockHash) :
                m_latest_block_hash(blockHash), m_oldest_block_hash(blockHash) {}

        account_block_pointer(const sha256_hash &mLatestBlockHash, const sha256_hash &mOldestBlockHash) :
                m_latest_block_hash(mLatestBlockHash), m_oldest_block_hash(mOldestBlockHash) {}

        void set_initial_block_hash(const sha256_hash &blockHash) {
            m_latest_block_hash = blockHash;
            m_oldest_block_hash = blockHash;
        }

        const sha256_hash &latest_block_hash() const {
            return m_latest_block_hash;
        }

        void set_latest_block_hash(const sha256_hash &mLatestBlockHash) {
            m_latest_block_hash = mLatestBlockHash;
        }

        const sha256_hash &oldest_block_hash() const {
            return m_oldest_block_hash;
        }

        void set_oldest_block_hash(const sha256_hash &mOldestBlockHash) {
            m_oldest_block_hash = mOldestBlockHash;
        }

        bool empty() { return m_latest_block_hash.is_all_zeros() && m_oldest_block_hash.is_all_zeros(); }

        entry get_entry() const;

        std::string get_encode() const;

        // @returns a pretty-printed string representation of block structure
        std::string to_string() const;

        friend std::ostream &operator<<(std::ostream &os, const account_block_pointer &pointer);

    private:

        // populate state pointer data from entry
        void populate(const entry& e);

        // the latest block hash
        sha256_hash m_latest_block_hash;

        // the oldest block hash
        sha256_hash m_oldest_block_hash;
    };
}


#endif //LIBTAU_ACCOUNT_BLOCK_POINTER_HPP
