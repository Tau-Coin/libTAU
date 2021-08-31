/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_REPOSITORY_IMPL_HPP
#define LIBTAU_REPOSITORY_IMPL_HPP


#include <sqlite3.h>
#include <leveldb/db.h>
#include "libTAU/blockchain/repository.hpp"

namespace libTAU::blockchain {
    struct repository_impl final : repository {

        repository_impl(sqlite3 *mSqlite, leveldb::DB *mLeveldb) : m_sqlite(mSqlite), m_leveldb(mLeveldb) {}

        bool init() override;

        account get_account(aux::bytes chain_id, aux::bytes pubKey) override;

        account get_account_without_verification(aux::bytes chain_id, aux::bytes pubKey) override;

        bool save_block(block b, bool main_chain) override;

    private:
        // sqlite3 instance
        sqlite3 *m_sqlite;

        // level db instance
        leveldb::DB* m_leveldb;
    };
}

#endif //LIBTAU_REPOSITORY_IMPL_HPP
