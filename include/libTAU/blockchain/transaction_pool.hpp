/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_TRANSACTION_POOL_HPP
#define LIBTAU_TRANSACTION_POOL_HPP


#include <set>
#include <map>
#include <queue>

#include "libTAU/blockchain/repository.hpp"
#include "libTAU/blockchain/transaction.hpp"

namespace libTAU::blockchain {
    class transaction_pool {
    public:
    private:
        // blockchain db
        std::shared_ptr<repository> m_repository;

        std::map<sha256_hash, transaction> m_all_txs;

        std::priority_queue<transaction> m_all_txss;

        std::map<dht::public_key, std::priority_queue<transaction>> m_txs;
    };
}


#endif //LIBTAU_TRANSACTION_POOL_HPP
