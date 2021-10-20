/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/tx_pool.hpp"


namespace libTAU::blockchain {

    transaction tx_pool::get_best_transaction() const {
        return transaction();
    }

    aux::bytes tx_pool::get_hash_prefix_array() const {
        return libTAU::aux::bytes();
    }

    bool tx_pool::add_tx(transaction tx) {
        if (tx.empty())
            return false;

        if (!tx.verify_signature())
            return false;

        auto sender_account = m_repository->get_account(tx.chain_id(), tx.sender());
        if (sender_account.nonce() + 1 != tx.nonce() || sender_account.balance() < tx.cost())
            return false;

        auto it = m_account_tx.find(tx.sender());
        if (it != m_account_tx.end() && tx.fee() > it->second.fee()) {
        }

        return true;
    }

    void tx_pool::clear() {
        m_all_txs.clear();
        m_account_tx.clear();
    }

}
