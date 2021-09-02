/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_STATE_LINKER_HPP
#define LIBTAU_STATE_LINKER_HPP


#include <utility>
#include "libTAU/kademlia/item.hpp"
#include "libTAU/blockchain/block.hpp"


namespace libTAU::blockchain {
    class TORRENT_EXPORT state_linker {

    public:

        state_linker() = default;

        // @param Construct with entry
        explicit state_linker(const entry& e);

        // @param Construct with bencode
        explicit state_linker(std::string encode): state_linker(bdecode(encode)) {}

        bool empty() { return m_block_hash.is_all_zeros(); }

        const sha256_hash &block_hash() const { return m_block_hash; }

        entry get_entry() const;

        std::string get_encode() const;

    private:

        // populate state linker data from entry
        void populate(const entry& e);

        // block hash
        sha256_hash m_block_hash;

        sha256_hash m_miner_last_change_block_hash;

        sha256_hash m_sender_last_change_block_hash;

        sha256_hash m_receiver_last_change_block_hash;
    };
}

#endif //LIBTAU_STATE_LINKER_HPP
