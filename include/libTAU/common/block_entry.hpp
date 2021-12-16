/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BLOCK_ENTRY_HPP
#define LIBTAU_BLOCK_ENTRY_HPP


#include "libTAU/aux_/export.hpp"
#include "libTAU/blockchain/block.hpp"
#include "libTAU/entry.hpp"

#include <utility>

namespace libTAU::common {
    struct TORRENT_EXPORT block_entry {
        // data type id
        static const std::int64_t data_type_id;

        // @param Construct with entry
        explicit block_entry(const entry& e);

        explicit block_entry(blockchain::block mBlk) : m_blk(std::move(mBlk)) {}

        // @returns the corresponding entry
        entry get_entry() const;

        blockchain::block m_blk;
    };
}


#endif //LIBTAU_BLOCK_ENTRY_HPP
