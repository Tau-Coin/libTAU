/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/repository_impl.hpp"

namespace libTAU::blockchain {

    bool repository_impl::init() {
        return false;
    }

    account repository_impl::get_account(aux::bytes chain_id, aux::bytes pubKey) {
        return account(0, 0);
    }

    account repository_impl::get_account_without_verification(aux::bytes chain_id, aux::bytes pubKey) {
        return account(0, 0);
    }

    bool repository_impl::save_block(block b, bool main_chain) {
        return false;
    }
}
