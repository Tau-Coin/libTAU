/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_TX_POOL_HPP
#define LIBTAU_TX_POOL_HPP


#include <set>
#include <map>
#include <queue>
#include <utility>

#include "libTAU/blockchain/repository.hpp"
#include "libTAU/blockchain/transaction.hpp"

namespace libTAU::blockchain {
    class tx_pool {
    public:
        tx_pool(std::shared_ptr<repository> mRepository) : m_repository(std::move(mRepository)) {}

//        tx_pool(std::shared_ptr<repository> mRepository, int64_t mExpirationBlockNumber) :
//        m_repository(std::move(mRepository)), m_expiration_block_number(mExpirationBlockNumber) {}
//
//        void update_expiration_block_number(const std::shared_ptr<repository> &mRepository) { m_repository = mRepository; }

        transaction get_best_transaction() const;

        aux::bytes get_hash_prefix_array() const;

        bool add_tx(transaction tx);

        void clear();

    private:
        // blockchain db
        std::shared_ptr<repository> m_repository;

//        std::int64_t m_expiration_block_number = 0;

        std::set<transaction> m_all_txs;

        std::map<dht::public_key, transaction> m_account_tx;
    };
}


#endif //LIBTAU_TX_POOL_HPP
