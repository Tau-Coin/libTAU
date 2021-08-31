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

        block_wrapper(block mBlock, int64_t mMinerLastChangeBlockNumber, int64_t mSenderLastChangeBlockNumber,
                      int64_t mReceiverLastChangeBlockNumber) : m_block(std::move(mBlock)), m_miner_last_change_block_number(
                mMinerLastChangeBlockNumber), m_sender_last_change_block_number(mSenderLastChangeBlockNumber),
                m_receiver_last_change_block_number(mReceiverLastChangeBlockNumber) {}

        const block &get_block() const { return m_block; }

        int64_t miner_last_change_block_number() const { return m_miner_last_change_block_number; }

        int64_t sender_last_change_block_number() const { return m_sender_last_change_block_number; }

        int64_t receiver_last_change_block_number() const { return m_receiver_last_change_block_number; }

        entry get_entry() const;

        std::string get_encode() const;

    private:

        // populate block wrapper data from entry
        void populate(const entry& e);

        // block
        block m_block;

        std::int64_t m_miner_last_change_block_number{};

        std::int64_t m_sender_last_change_block_number{};

        std::int64_t m_receiver_last_change_block_number{};
    };
}

#endif //LIBTAU_BLOCK_WRAPPER_HPP
