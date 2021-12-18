/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_ENTRY_TYPE_HPP
#define LIBTAU_ENTRY_TYPE_HPP

#include <utility>

#include "libTAU/aux_/export.hpp"
#include "libTAU/blockchain/block.hpp"
#include "libTAU/communication/message.hpp"
#include "libTAU/entry.hpp"

namespace libTAU::common {

    const std::string entry_type_id = "tid";

    struct TORRENT_EXPORT message_entry {
        // data type id
        static const std::int64_t data_type_id = 0;

        // @param Construct with entry
        explicit message_entry(const entry& e);

        explicit message_entry(communication::message mMsg) : m_msg(std::move(mMsg)) {}

        // @returns the corresponding entry
        entry get_entry() const;

        communication::message m_msg;
    };

    struct TORRENT_EXPORT message_levenshtein_array_entry {
        // data type id
        static const std::int64_t data_type_id = 1;

        // @param Construct with entry
        explicit message_levenshtein_array_entry(const entry& e);

        explicit message_levenshtein_array_entry(aux::bytes mLevenshteinArray) : m_levenshtein_array(std::move(mLevenshteinArray)) {}

        // @returns the corresponding entry
        entry get_entry() const;

        // bytes consist of first byte of ordered messages hash
        aux::bytes m_levenshtein_array;
    };

    struct TORRENT_EXPORT block_entry {
        // data type id
        static const std::int64_t data_type_id = 2;

        // @param Construct with entry
        explicit block_entry(const entry& e);

        explicit block_entry(blockchain::block mBlk) : m_blk(std::move(mBlk)) {}

        // @returns the corresponding entry
        entry get_entry() const;

        blockchain::block m_blk;
    };

    struct TORRENT_EXPORT transaction_entry {
        // data type id
        static const std::int64_t data_type_id = 3;

        // @param Construct with entry
        explicit transaction_entry(const entry& e);

        explicit transaction_entry(blockchain::transaction mTx) : m_tx(std::move(mTx)) {}

        // @returns the corresponding entry
        entry get_entry() const;

        blockchain::transaction m_tx;
    };

}


#endif //LIBTAU_ENTRY_TYPE_HPP
