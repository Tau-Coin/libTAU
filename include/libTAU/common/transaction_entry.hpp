/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_TRANSACTION_ENTRY_HPP
#define LIBTAU_TRANSACTION_ENTRY_HPP


#include "libTAU/aux_/export.hpp"
#include "libTAU/blockchain/transaction.hpp"
#include "libTAU/entry.hpp"

#include <utility>

namespace libTAU::common {
    struct TORRENT_EXPORT transaction_entry {
        // data type id
        static const std::int64_t data_type_id;

        // @param Construct with entry
        explicit transaction_entry(const entry& e);

        explicit transaction_entry(blockchain::transaction mTx) : m_tx(std::move(mTx)) {}

        // @returns the corresponding entry
        entry get_entry() const;

        blockchain::transaction m_tx;
    };
}


#endif //LIBTAU_TRANSACTION_ENTRY_HPP
