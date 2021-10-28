/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/tx_pool.hpp"


namespace libTAU::blockchain {

    transaction tx_pool::get_best_transaction() const {
        auto it = m_ordered_txs.rbegin();
        if (it != m_ordered_txs.rend()) {
            auto it_tx = m_all_txs.find(it->txid());
            if (it_tx != m_all_txs.end())
                return it_tx->second;
        }

        return transaction();
    }

    aux::bytes tx_pool::get_hash_prefix_array() const {
        libTAU::aux::bytes hash_prefix_array;
        int count = 0;
        for (auto it = m_ordered_txs.rbegin(); it != m_ordered_txs.rend(); ++it) {
            count++;
            hash_prefix_array.push_back(it->txid()[0]);

            if (10 == count) {
                break;
            }
        }

        return hash_prefix_array;
    }

    bool tx_pool::add_tx(transaction tx) {
        if (tx.empty())
            return false;

        if (!tx.verify_signature())
            return false;

        auto sender_account = m_repository->get_account(tx.chain_id(), tx.sender());
        if (sender_account.nonce() + 1 != tx.nonce() || sender_account.balance() < tx.cost())
            return false;

        auto it_txid = m_account_tx.find(tx.sender());
        if (it_txid != m_account_tx.end()) {
            auto it_tx = m_all_txs.find(it_txid->second);
            if (it_tx != m_all_txs.end()) {
                auto old_tx = it_tx->second;
                if (!old_tx.empty()) {
                    // +offset?
                    if (tx.fee() > old_tx.fee()) {
                        // replace old tx with new one
                        m_all_txs[tx.sha256()] = tx;
                        m_account_tx[tx.sender()] = tx.sha256();
                        m_ordered_txs.erase(tx_entry(old_tx.sha256(), old_tx.fee()));
                        m_ordered_txs.insert(tx_entry(tx.sha256(), tx.fee()));
                    }
                }
            }
        }

        return true;
    }

    transaction tx_pool::get_transaction_by_account(const dht::public_key& pubKey) const {
        auto it_txid = m_account_tx.find(pubKey);
        if (it_txid != m_account_tx.end()) {
            auto it_tx = m_all_txs.find(it_txid->second);
            if (it_tx != m_all_txs.end()) {
                return it_tx->second;
            }
        }

        return transaction();
    }

    void tx_pool::delete_transaction_by_account(const dht::public_key &pubKey) {
        auto it_txid = m_account_tx.find(pubKey);
        if (it_txid != m_account_tx.end()) {
            m_all_txs.erase(it_txid->second);
            m_account_tx.erase(it_txid);
        }
    }

    bool tx_pool::process_block(const block& b) {
        std::set<dht::public_key> peers;
        peers.insert(b.miner());
        auto tx = b.tx();
        if (!tx.empty()) {
            peers.insert(tx.sender());
            peers.insert(tx.receiver());
        }

        for (auto const& peer: peers) {
            auto local_tx = get_transaction_by_account(peer);
            if (!local_tx.empty()) {
                delete_transaction_by_account(peer);
                add_tx(local_tx);
            }
        }
    }

    dht::public_key tx_pool::select_active_sender_randomly() {
        return dht::public_key();
    }

    void tx_pool::clear() {
        m_all_txs.clear();
        m_account_tx.clear();
    }

}
