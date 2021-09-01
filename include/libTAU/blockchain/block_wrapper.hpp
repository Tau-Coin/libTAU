/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BLOCK_WRAPPER_HPP
#define LIBTAU_BLOCK_WRAPPER_HPP


#include <utility>

#include "libTAU/blockchain/block.hpp"


namespace libTAU::blockchain {
    class TORRENT_EXPORT block_wrapper {

    public:

        block_wrapper() = default;

        // @param Construct with entry
        explicit block_wrapper(entry e);

        // @param Construct with bencode
        explicit block_wrapper(std::string encode): block_wrapper(bdecode(encode)) {}

        const sha256_hash &block_hash() const { return m_block_hash; }

        entry get_entry() const;

        std::string get_encode() const;

        // @returns the SHA256 hash of this block
        const sha256_hash &sha256();

    private:

        // populate block wrapper data from entry
        void populate(const entry& e);

        // block hash
        sha256_hash m_block_hash;

        sha256_hash m_miner_last_change_block_hash;

        sha256_hash m_sender_last_change_block_hash;

        sha256_hash m_receiver_last_change_block_hash;

        sha256_hash m_hash;
    };
}

#endif //LIBTAU_BLOCK_WRAPPER_HPP
