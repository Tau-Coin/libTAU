/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/tx_pool.hpp"


namespace libTAU::blockchain {

    transaction tx_pool::get_best_fee_transaction() const {
        auto it = m_ordered_txs_by_fee.rbegin();
        if (it != m_ordered_txs_by_fee.rend()) {
            auto it_tx = m_all_txs_by_fee.find(it->txid());
            if (it_tx != m_all_txs_by_fee.end())
                return it_tx->second;
        }

        return transaction();
    }

    transaction tx_pool::get_latest_note_transaction() const {
        for (auto it = m_ordered_txs_by_timestamp.rbegin(); it != m_ordered_txs_by_timestamp.rend(); it++) {
            auto it_tx = m_all_txs_by_timestamp.find(it->txid());
            if (it_tx != m_all_txs_by_timestamp.end() && it_tx->second.type() == tx_type::type_note)
                return it_tx->second;
        }
//        auto it = m_ordered_txs_by_timestamp.rbegin();
//        if (it != m_ordered_txs_by_timestamp.rend()) {
//            auto it_tx = m_all_txs_by_timestamp.find(it->txid());
//            if (it_tx != m_all_txs_by_timestamp.end())
//                return it_tx->second;
//        }

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

    std::set<sha1_hash> tx_pool::get_top_40_note_txid() {
        std::set<sha1_hash> txid_set;
        int count = 0;
        for (auto it = m_ordered_txs_by_timestamp.rbegin(); it != m_ordered_txs_by_timestamp.rend(); ++it) {
            count++;
            auto &tx = m_all_txs_by_timestamp[it->txid()];
            txid_set.insert(tx.sha1());

            if (40 == count) {
                break;
            }
        }

        return txid_set;
    }

    std::set<sha1_hash> tx_pool::get_all_note_txid() {
        std::set<sha1_hash> txid_set;
        for (auto it = m_ordered_txs_by_timestamp.rbegin(); it != m_ordered_txs_by_timestamp.rend(); ++it) {
            auto &tx = m_all_txs_by_timestamp[it->txid()];
            txid_set.insert(tx.sha1());
        }

        return txid_set;
    }

    bool tx_pool::add_tx_to_fee_pool(const transaction &tx) {
        if (tx.fee() < get_min_allowed_fee())
            return false;

        // validate tx state
        auto sender_account = m_repository->get_account(tx.chain_id(), tx.sender());
//        if (tx.type() == tx_type::type_transfer) {
            if (sender_account.nonce() + 1 != tx.nonce() || sender_account.balance() < tx.cost())
                return false;
//        } else if (tx.type() == tx_type::type_note) {
//            if (tx.timestamp() <= sender_account.note_timestamp() || sender_account.balance() < tx.cost())
//                return false;
//        } else {
//            return false;
//        }

        auto it_txid = m_account_tx_by_fee.find(tx.sender());
        // find in local
        if (it_txid != m_account_tx_by_fee.end()) { // has in local
            auto it_tx = m_all_txs_by_fee.find(it_txid->second);
            if (it_tx != m_all_txs_by_fee.end()) {
                auto old_tx = it_tx->second;
                if (tx.fee() > old_tx.fee()) {
                    // remove old tx
                    m_all_txs_by_fee.erase(old_tx.sha1());
                    m_account_tx_by_fee.erase(old_tx.sender());
                    m_ordered_txs_by_fee.erase(tx_entry_with_fee(old_tx.sha1(), old_tx.fee()));
                } else {
                    return false;
                }
            }
        }

        // insert new tx
        m_all_txs_by_fee[tx.sha1()] = tx;
        m_account_tx_by_fee[tx.sender()] = tx.sha1();
        m_ordered_txs_by_fee.insert(tx_entry_with_fee(tx.sha1(), tx.fee()));

        if (m_all_txs_by_fee.size() > tx_pool_max_size_by_fee) {
            remove_min_fee_tx();
        }

        return true;
    }

    bool tx_pool::add_tx_to_time_pool(const transaction &tx) {
        if (tx.timestamp() <= get_oldest_allowed_timestamp())
            return false;

        auto it_account_txid_set = m_account_tx_by_timestamp.find(tx.sender());
        // find in local
        if (it_account_txid_set != m_account_tx_by_timestamp.end() &&
            it_account_txid_set->second.size() >= time_pool_max_size_of_same_account) { // has in local
            auto it_oldest_txid = it_account_txid_set->second.begin();
            auto it_oldest_tx = m_all_txs_by_timestamp.find(*it_oldest_txid);
            if (it_oldest_tx != m_all_txs_by_timestamp.end()) {
                auto oldest_tx = it_oldest_tx->second;

                // find oldest tx
                for (auto const& txid: it_account_txid_set->second) {
                    auto it_tx = m_all_txs_by_timestamp.find(txid);
                    if (it_tx != m_all_txs_by_timestamp.end()) {
                        if (it_tx->second.timestamp() < oldest_tx.timestamp()) {
                            oldest_tx = it_tx->second;
                        }
                    }
                }

                // remove oldest tx
                if (tx.timestamp() > oldest_tx.timestamp()) {
                    // remove oldest tx
                    m_all_txs_by_timestamp.erase(oldest_tx.sha1());
                    it_account_txid_set->second.erase(oldest_tx.sha1());
                    m_ordered_txs_by_timestamp.erase(tx_entry_with_timestamp(oldest_tx.sha1(), oldest_tx.timestamp()));
                } else {
                    return false;
                }
            }
        }

        // insert new tx
        m_all_txs_by_timestamp[tx.sha1()] = tx;
        m_account_tx_by_timestamp[tx.sender()].insert(tx.sha1());
        m_ordered_txs_by_timestamp.insert(tx_entry_with_timestamp(tx.sha1(), tx.timestamp()));

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

        if (tx.type() == tx_type::type_transfer) {
            return add_tx_to_fee_pool(tx);
        } else if (tx.type() == tx_type::type_note) {
            return add_tx_to_time_pool(tx);
        } else {
            return false;
        }
    }

//    bool tx_pool::rollback_block(const block &blk) {
//        return add_tx(blk.tx());
//        auto &tx = blk.tx();
//        if (tx.empty())
//            return false;
//
//        // validate tx state
//        auto sender_account = m_repository->get_account(tx.chain_id(), tx.sender());
//        if (sender_account.nonce() + 1 != tx.nonce() || sender_account.balance() < tx.cost())
//            return false;
//
//
//        auto it_txid = m_account_tx_by_fee.find(tx.sender());
//        // find in local
//        if (it_txid != m_account_tx_by_fee.end()) { // has in local
//            auto it_tx = m_all_txs_by_fee.find(it_txid->second);
//            if (it_tx != m_all_txs_by_fee.end()) {
//                auto old_tx = it_tx->second;
//                if (!old_tx.empty()) {
//                    if (tx.fee() >= old_tx.fee()) {
//                        // replace old tx with new one
//                        m_all_txs_by_fee[tx.sha256()] = tx;
//                        m_account_tx_by_fee[tx.sender()] = tx.sha256();
//                        m_ordered_txs_by_fee.erase(tx_entry_with_fee(old_tx.sha256(), old_tx.fee()));
//                        m_ordered_txs_by_fee.insert(tx_entry_with_fee(tx.sha256(), tx.fee()));
//                    }
//                }
//            }
//        } else { // insert if cannot find in local
//            m_all_txs_by_fee[tx.sha256()] = tx;
//            m_account_tx_by_fee[tx.sender()] = tx.sha256();
//            m_ordered_txs_by_fee.insert(tx_entry_with_fee(tx.sha256(), tx.fee()));
//        }
//
//        if (m_all_txs_by_fee.size() > tx_pool_max_size_by_fee) {
//            remove_min_fee_tx();
//        }
//
//        return true;
//    }

//    bool tx_pool::connect_block(const block &blk) {
//        auto& tx = blk.tx();
//        if (!tx.empty()) {
//            if (tx.type() == tx_type::type_transfer) {
//                return recheck_account_txs(blk.get_block_peers());
//            } else if (tx.type() == tx_type::type_note) {
//                delete_tx_from_time_pool(tx);
//            } else {
//                return false;
//            }
//        }
//
//        return true;
//    }

    void tx_pool::delete_tx_from_time_pool(const transaction &tx) {
        if (tx.empty())
            return;

        m_all_txs_by_timestamp.erase(tx.sha1());
        m_ordered_txs_by_timestamp.erase(tx_entry_with_timestamp(tx.sha1(), tx.timestamp()));
        auto it = m_account_tx_by_timestamp.find(tx.sender());
        if (it != m_account_tx_by_timestamp.end()) {
            it->second.erase(tx.sha1());
            if (it->second.empty()) {
                m_account_tx_by_timestamp.erase(it);
            }
        }
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

            m_account_tx_by_timestamp[it_tx->second.sender()].erase(it_tx->first);
            if (m_account_tx_by_timestamp[it_tx->second.sender()].empty()) {
                m_account_tx_by_timestamp.erase(it_tx->second.sender());
            }
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
                m_ordered_txs_by_fee.erase(tx_entry_with_fee(it->second.sha1(), it->second.fee()));
                m_all_txs_by_fee.erase(it);
            }

            m_account_tx_by_fee.erase(it_txid);
        }
    }

    bool tx_pool::recheck_account_txs(const std::set<dht::public_key> &peers) {
        for (auto const& peer: peers) {
            recheck_account_tx(peer);
//            auto local_tx = get_transaction_by_account(peer);
//            if (!local_tx.empty()) {
//                delete_transaction_by_account(peer);
//                add_tx(local_tx);
//            }
        }

        return true;
    }

    bool tx_pool::is_transaction_in_fee_pool(const sha1_hash &txid) const {
        auto it = m_all_txs_by_fee.find(txid);
        if (it != m_all_txs_by_fee.end()) {
            return true;
        }

        return false;
    }

    bool tx_pool::is_transaction_in_time_pool(const sha1_hash &txid) const {
        auto it = m_all_txs_by_timestamp.find(txid);
        if (it != m_all_txs_by_timestamp.end()) {
            return true;
        }

        return false;
    }

    bool tx_pool::is_transaction_in_pool(const sha1_hash &txid) const {
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
        if (m_ordered_txs_by_fee.size() >= tx_pool_max_size_by_fee) {
            auto it = m_ordered_txs_by_fee.begin();
            if (it != m_ordered_txs_by_fee.end()) {
                return it->fee();
            }
        }

        return 0;
    }

    std::int64_t tx_pool::get_oldest_allowed_timestamp() {
        if (m_ordered_txs_by_timestamp.size() >= tx_pool_max_size_by_timestamp) {
            auto it = m_ordered_txs_by_timestamp.begin();
            if (it != m_ordered_txs_by_timestamp.end()) {
                return it->timestamp();
            }
        }

        return 0;
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
                    m_ordered_txs_by_fee.erase(tx_entry_with_fee(tx.sha1(), tx.fee()));
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
