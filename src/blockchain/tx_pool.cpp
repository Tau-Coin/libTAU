/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/tx_pool.hpp"


namespace libTAU::blockchain {

    transaction tx_pool::get_best_transaction() const {
        auto it = m_ordered_txs_by_fee.rbegin();
        if (it != m_ordered_txs_by_fee.rend()) {
            auto it_tx = m_all_txs_by_fee.find(it->txid());
            if (it_tx != m_all_txs_by_fee.end())
                return it_tx->second;
        }

        return transaction();
    }

    aux::bytes tx_pool::get_hash_prefix_array_by_fee() const {
        libTAU::aux::bytes hash_prefix_array;
        int count = 0;
        for (auto it = m_ordered_txs_by_fee.rbegin(); it != m_ordered_txs_by_fee.rend(); ++it) {
            count++;
            hash_prefix_array.push_back(it->txid()[0]);

            if (10 == count) {
                break;
            }
        }

        return hash_prefix_array;
    }

    std::vector<transaction> tx_pool::get_top_ten_fee_transactions() {
        std::vector<transaction> txs;
        int count = 0;
        for (auto it = m_ordered_txs_by_fee.rbegin(); it != m_ordered_txs_by_fee.rend(); ++it) {
            count++;
            auto &tx = m_all_txs_by_fee[it->txid()];
            txs.push_back(tx);

            if (10 == count) {
                break;
            }
        }

        return txs;
    }

    aux::bytes tx_pool::get_hash_prefix_array_by_timestamp() const {
        libTAU::aux::bytes hash_prefix_array;
        int count = 0;
        for (auto it = m_ordered_txs_by_timestamp.rbegin(); it != m_ordered_txs_by_timestamp.rend(); ++it) {
            count++;
            hash_prefix_array.push_back(it->txid()[0]);

            if (10 == count) {
                break;
            }
        }

        return hash_prefix_array;
    }

    std::vector<transaction> tx_pool::get_top_ten_timestamp_transactions() {
        std::vector<transaction> txs;
        int count = 0;
        for (auto it = m_ordered_txs_by_timestamp.rbegin(); it != m_ordered_txs_by_timestamp.rend(); ++it) {
            count++;
            auto &tx = m_all_txs_by_timestamp[it->txid()];
            txs.push_back(tx);

            if (10 == count) {
                break;
            }
        }

        return txs;
    }

    bool tx_pool::add_tx_to_fee_pool(const transaction &tx) {
        if (tx.fee() <= get_min_allowed_fee())
            return false;

        // validate tx state
        auto sender_account = m_repository->get_account(tx.chain_id(), tx.sender());
        if (tx.type() == tx_type::type_transfer) {
            if (sender_account.nonce() + 1 != tx.nonce() || sender_account.balance() < tx.cost())
                return false;
        } else if (tx.type() == tx_type::type_note) {
            if (tx.timestamp() <= sender_account.note_timestamp() || sender_account.balance() < tx.cost())
                return false;
        } else {
            return false;
        }

        auto it_txid = m_account_tx_by_fee.find(tx.sender());
        // find in local
        if (it_txid != m_account_tx_by_fee.end()) { // has in local
            auto it_tx = m_all_txs_by_fee.find(it_txid->second);
            if (it_tx != m_all_txs_by_fee.end()) {
                auto old_tx = it_tx->second;
                if (tx.fee() > old_tx.fee()) {
                    // replace old tx with new one
                    m_all_txs_by_fee[tx.sha256()] = tx;
                    m_account_tx_by_fee[tx.sender()] = tx.sha256();
                    m_ordered_txs_by_fee.erase(tx_entry_with_fee(old_tx.sha256(), old_tx.fee()));
                    m_ordered_txs_by_fee.insert(tx_entry_with_fee(tx.sha256(), tx.fee()));
                } else {
                    return false;
                }
            }
        }

        // insert if cannot find in local
        m_all_txs_by_fee[tx.sha256()] = tx;
        m_account_tx_by_fee[tx.sender()] = tx.sha256();
        m_ordered_txs_by_fee.insert(tx_entry_with_fee(tx.sha256(), tx.fee()));

        if (m_all_txs_by_fee.size() > tx_pool_max_size_by_fee) {
            remove_min_fee_tx();
        }

        return true;
    }

    bool tx_pool::add_tx_to_time_pool(const transaction &tx) {
        if (tx.timestamp() <= get_oldest_allowed_timestamp())
            return false;

        auto it_txid = m_account_tx_by_timestamp.find(tx.sender());
        // find in local
        if (it_txid != m_account_tx_by_timestamp.end()) { // has in local
            auto it_tx = m_all_txs_by_timestamp.find(it_txid->second);
            if (it_tx != m_all_txs_by_timestamp.end()) {
                auto old_tx = it_tx->second;
                if (tx.timestamp() > old_tx.timestamp()) {
                    // replace old tx with new one
                    m_all_txs_by_timestamp[tx.sha256()] = tx;
                    m_account_tx_by_timestamp[tx.sender()] = tx.sha256();
                    m_ordered_txs_by_timestamp.erase(tx_entry_with_timestamp(old_tx.sha256(), old_tx.timestamp()));
                    m_ordered_txs_by_timestamp.insert(tx_entry_with_timestamp(tx.sha256(), tx.timestamp()));
                } else {
                    return false;
                }
            }
        }

        // insert if cannot find in local
        m_all_txs_by_timestamp[tx.sha256()] = tx;
        m_account_tx_by_timestamp[tx.sender()] = tx.sha256();
        m_ordered_txs_by_timestamp.insert(tx_entry_with_timestamp(tx.sha256(), tx.timestamp()));

        if (m_all_txs_by_timestamp.size() > tx_pool_max_size_by_timestamp) {
            remove_oldest_tx();
        }

        return true;
    }

    bool tx_pool::add_tx(const transaction& tx) {
        if (tx.empty())
            return false;

        if (!tx.verify_signature())
            return false;

        m_active_peers.push(tx.sender());
        if (m_active_peers.size() > tx_pool_max_active_friends_size) {
            m_active_peers.pop();
        }

        auto ret1 = add_tx_to_time_pool(tx);
        auto ret2 = add_tx_to_fee_pool(tx);

        if (!ret1 && !ret2)
            return false;

        return true;
    }

    bool tx_pool::send_back_block_tx_to_pool(const block &blk) {
        auto &tx = blk.tx();
        if (tx.empty())
            return false;

        // validate tx state
        auto sender_account = m_repository->get_account(tx.chain_id(), tx.sender());
        if (sender_account.nonce() + 1 != tx.nonce() || sender_account.balance() < tx.cost())
            return false;


        auto it_txid = m_account_tx_by_fee.find(tx.sender());
        // find in local
        if (it_txid != m_account_tx_by_fee.end()) { // has in local
            auto it_tx = m_all_txs_by_fee.find(it_txid->second);
            if (it_tx != m_all_txs_by_fee.end()) {
                auto old_tx = it_tx->second;
                if (!old_tx.empty()) {
                    if (tx.fee() >= old_tx.fee()) {
                        // replace old tx with new one
                        m_all_txs_by_fee[tx.sha256()] = tx;
                        m_account_tx_by_fee[tx.sender()] = tx.sha256();
                        m_ordered_txs_by_fee.erase(tx_entry_with_fee(old_tx.sha256(), old_tx.fee()));
                        m_ordered_txs_by_fee.insert(tx_entry_with_fee(tx.sha256(), tx.fee()));
                    }
                }
            }
        } else { // insert if cannot find in local
            m_all_txs_by_fee[tx.sha256()] = tx;
            m_account_tx_by_fee[tx.sender()] = tx.sha256();
            m_ordered_txs_by_fee.insert(tx_entry_with_fee(tx.sha256(), tx.fee()));
        }

        if (m_all_txs_by_fee.size() > tx_pool_max_size_by_fee) {
            remove_min_fee_tx();
        }

        return true;
    }

    void tx_pool::remove_min_fee_tx() {
        auto it = m_ordered_txs_by_fee.begin();
        auto it_tx = m_all_txs_by_fee.find(it->txid());
        if (it_tx != m_all_txs_by_fee.end()) {
            m_all_txs_by_fee.erase(it_tx);
            m_account_tx_by_fee.erase(it_tx->second.sender());
        }
        m_ordered_txs_by_fee.erase(it);
    }

    void tx_pool::remove_oldest_tx() {
        auto it = m_ordered_txs_by_timestamp.begin();
        auto it_tx = m_all_txs_by_timestamp.find(it->txid());
        if (it_tx != m_all_txs_by_timestamp.end()) {
            m_all_txs_by_timestamp.erase(it_tx);
            m_account_tx_by_timestamp.erase(it_tx->second.sender());
        }
        m_ordered_txs_by_timestamp.erase(it);
    }

    transaction tx_pool::get_transaction_by_account(const dht::public_key& pubKey) const {
        auto it_txid = m_account_tx_by_fee.find(pubKey);
        if (it_txid != m_account_tx_by_fee.end()) {
            auto it_tx = m_all_txs_by_fee.find(it_txid->second);
            if (it_tx != m_all_txs_by_fee.end()) {
                return it_tx->second;
            }
        }

        return transaction();
    }

    void tx_pool::delete_transaction_by_account(const dht::public_key &pubKey) {
        auto it_txid = m_account_tx_by_fee.find(pubKey);
        if (it_txid != m_account_tx_by_fee.end()) {
            auto it = m_all_txs_by_fee.find(it_txid->second);
            if (it != m_all_txs_by_fee.end()) {
                m_ordered_txs_by_fee.erase(tx_entry_with_fee(it->second.sha256(), it->second.fee()));
                m_all_txs_by_fee.erase(it);
            }

            m_account_tx_by_fee.erase(it_txid);
        }
    }

    bool tx_pool::recheck_account_txs(const std::set<dht::public_key> &peers) {
        for (auto const& peer: peers) {
            recheck_account_tx(peer);
            auto local_tx = get_transaction_by_account(peer);
            if (!local_tx.empty()) {
                delete_transaction_by_account(peer);
                add_tx(local_tx);
            }
        }

        return true;
    }

    bool tx_pool::is_transaction_in_pool(const sha256_hash &txid) const {
        auto it = m_all_txs_by_fee.find(txid);
        if (it != m_all_txs_by_fee.end()) {
            return true;
        }

        it = m_all_txs_by_timestamp.find(txid);
        if (it != m_all_txs_by_timestamp.end()) {
            return true;
        }

        return false;
    }

    std::int64_t tx_pool::get_min_allowed_fee() {
        auto it = m_ordered_txs_by_fee.begin();
        if (it != m_ordered_txs_by_fee.end()) {
            return it->fee();
        }

        return 0;
    }

    std::int64_t tx_pool::get_oldest_allowed_timestamp() {
        auto it = m_ordered_txs_by_timestamp.begin();
        if (it != m_ordered_txs_by_timestamp.end()) {
            return it->timestamp();
        }

        return 0;
    }

    std::set<dht::public_key> tx_pool::get_active_peers() {
        std::set<dht::public_key> peers;
        auto size = m_active_peers.size();
        for (auto i = 0; i < size; i++) {
            peers.insert(m_active_peers.front());
            m_active_peers.push(m_active_peers.front());
            m_active_peers.pop();
        }

        return peers;
    }

    void tx_pool::clear() {
        m_all_txs_by_fee.clear();
        m_ordered_txs_by_fee.clear();
        m_account_tx_by_fee.clear();
        m_all_txs_by_timestamp.clear();
        m_ordered_txs_by_timestamp.clear();
        m_account_tx_by_timestamp.clear();
    }

    void tx_pool::recheck_account_tx(const dht::public_key &pubKey) {
        auto it_txid = m_account_tx_by_fee.find(pubKey);
        if (it_txid != m_account_tx_by_fee.end()) {
            auto it = m_all_txs_by_fee.find(it_txid->second);
            if (it != m_all_txs_by_fee.end()) {
                auto tx = it->second;
                // validate tx state
                auto sender_account = m_repository->get_account(tx.chain_id(), tx.sender());
                if (sender_account.nonce() + 1 != tx.nonce() || sender_account.balance() < tx.cost()) {
                    m_ordered_txs_by_fee.erase(tx_entry_with_fee(tx.sha256(), tx.fee()));
                    m_all_txs_by_fee.erase(it);
                    m_account_tx_by_fee.erase(it_txid);
                }
            }
        }
    }

    // todo
    void tx_pool::recheck_all_transactions() {
        std::set<transaction> txs;
        for (auto const &item: m_all_txs_by_fee) {
            txs.insert(item.second);
        }
        for (auto const &item: m_all_txs_by_timestamp) {
            txs.insert(item.second);
        }

        clear();

        for (auto const &tx: txs) {
            add_tx(tx);
        }
    }

    std::set<transaction> tx_pool::get_all_transactions() {
        std::set<transaction> txs;
        for (auto const &item: m_all_txs_by_fee) {
            txs.insert(item.second);
        }

        return txs;
    }

}
