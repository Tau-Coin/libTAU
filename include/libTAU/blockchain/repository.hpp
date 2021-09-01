/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_REPOSITORY_HPP
#define LIBTAU_REPOSITORY_HPP

#include "libTAU/blockchain/account.hpp"
#include "libTAU/blockchain/block.hpp"

namespace libTAU::blockchain {
    struct TORRENT_EXPORT repository {

        // init db
        virtual bool init() = 0;

        /**
         * check if account exist
         * @return true if account exist, false otherwise
         */
        virtual bool is_exist(aux::bytes chain_id, dht::public_key pubKey) = 0;

        virtual account get_account(aux::bytes chain_id, dht::public_key pubKey) = 0;

        virtual account get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) = 0;

        /**
         * check if block exist
         * @return true if block exist, false otherwise
         */
        virtual bool is_block_exist(aux::bytes chain_id, sha256_hash hash) = 0;

        virtual block get_block_by_hash(aux::bytes chain_id, sha256_hash hash) = 0;

        virtual bool save_block(block b, bool main_chain) = 0;
    };
}
#endif //LIBTAU_REPOSITORY_HPP
