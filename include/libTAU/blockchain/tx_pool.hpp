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
#include <vector>

#include "libTAU/blockchain/repository.hpp"
#include "libTAU/blockchain/transaction.hpp"
#include "libTAU/blockchain/tx_entry.hpp"

namespace libTAU::blockchain {

    class tx_pool {
    public:

        tx_pool() = default;

        tx_pool(std::shared_ptr<repository> mRepository) : m_repository(std::move(mRepository)) {}

//        tx_pool(std::shared_ptr<repository> mRepository, int64_t mExpirationBlockNumber) :
//        m_repository(std::move(mRepository)), m_expiration_block_number(mExpirationBlockNumber) {}
//
//        void update_expiration_block_number(const std::shared_ptr<repository> &mRepository) { m_repository = mRepository; }

        transaction get_best_transaction() const;

        aux::bytes get_hash_prefix_array() const;

        std::vector<transaction> get_top_ten_transactions();

        bool add_tx(transaction tx);

        transaction get_transaction_by_account(const dht::public_key& pubKey) const;

        void delete_transaction_by_account(const dht::public_key& pubKey);

        bool process_block_peers(const block& b);

        std::set<dht::public_key> get_active_peers();

        void clear();

    private:

        // blockchain db
        std::shared_ptr<repository> m_repository;

//        std::int64_t m_expiration_block_number = 0;

        std::map<sha256_hash, transaction> m_all_txs;

        std::set<tx_entry> m_ordered_txs;

        std::map<dht::public_key, sha256_hash> m_account_tx;

        std::queue<dht::public_key> m_active_peers;
    };
}


#endif //LIBTAU_TX_POOL_HPP
