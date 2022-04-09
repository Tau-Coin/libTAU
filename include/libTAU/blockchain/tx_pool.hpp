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
#include "libTAU/blockchain/tx_entry_with_fee.hpp"
#include "libTAU/blockchain/tx_entry_with_timestamp.hpp"

namespace libTAU::blockchain {

    constexpr int tx_pool_max_size_by_fee = 200;

    // todo:comments
    constexpr int tx_pool_max_size_by_timestamp = 10;

    constexpr int tx_pool_max_active_friends_size = 10;

    class tx_pool {
    public:

        tx_pool() = default;

        explicit tx_pool(repository *mRepository) : m_repository(mRepository) {}

        transaction get_best_transaction() const;

        aux::bytes get_hash_prefix_array_by_fee() const;

        std::vector<transaction> get_top_ten_fee_transactions();

        aux::bytes get_hash_prefix_array_by_timestamp() const;

        std::vector<transaction> get_top_ten_timestamp_transactions();

        bool add_tx(const transaction& tx);

        bool send_back_block_tx_to_pool(const block& blk);

        transaction get_transaction_by_account(const dht::public_key& pubKey) const;

        void delete_transaction_by_account(const dht::public_key& pubKey);

        bool recheck_account_txs(const std::set<dht::public_key> &peers);

        bool is_transaction_in_pool(const sha256_hash& txid) const;

        std::int64_t get_min_allowed_fee();

        std::int64_t get_oldest_allowed_timestamp();

        std::set<dht::public_key> get_active_peers();

        void clear();

        void recheck_account_tx(const dht::public_key& pubKey);

        void recheck_all_transactions();

        std::set<transaction> get_all_transactions();

    private:

        bool add_tx_to_fee_pool(const transaction& tx);

        bool add_tx_to_time_pool(const transaction& tx);

        void remove_min_fee_tx();

        void remove_oldest_tx();

        // blockchain db
        repository* m_repository{};

        // tx set
        std::map<sha256_hash, transaction> m_all_txs_by_fee;

        // ordered by fee
        std::set<tx_entry_with_fee> m_ordered_txs_by_fee;

        // one account one tx
        std::map<dht::public_key, sha256_hash> m_account_tx_by_fee;

        // tx set
        std::map<sha256_hash, transaction> m_all_txs_by_timestamp;

        // ordered by timestamp
        std::set<tx_entry_with_timestamp> m_ordered_txs_by_timestamp;

        // one account one tx
        std::map<dht::public_key, sha256_hash> m_account_tx_by_timestamp;

        // active peers found from tx
        std::queue<dht::public_key> m_active_peers;
    };
}


#endif //LIBTAU_TX_POOL_HPP
