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
        account() = default;

        account(int64_t mBalance, int64_t mNonce) : m_balance(mBalance), m_nonce(mNonce) {}

        int64_t balance() const { return m_balance; }

        int64_t nonce() const { return m_nonce; }

    private:
        // balance
        std::int64_t m_balance;

        // nonce
        std::int64_t m_nonce;
    };
}


#endif //LIBTAU_ACCOUNT_HPP
