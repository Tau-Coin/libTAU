/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_ACCOUNT_HPP
#define LIBTAU_ACCOUNT_HPP

#include "libTAU/aux_/common.h"

namespace libTAU::blockchain {
    class account {
    public:
        account(int64_t mBalance, int64_t mNonce, int64_t mBlockNumber) : m_balance(mBalance), m_nonce(mNonce),
                                                                          m_block_number(mBlockNumber) {}

        bool empty() const { return m_balance == 0 && m_nonce == 0; }

        int64_t balance() const { return m_balance; }

        int64_t nonce() const { return m_nonce; }

        int64_t block_number() const { return m_block_number; }

    private:
        // balance
        std::int64_t m_balance;

        // nonce
        std::int64_t m_nonce;

        // block number
        std::int64_t m_block_number;
    };
}


#endif //LIBTAU_ACCOUNT_HPP
