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
#include <leveldb/write_batch.h>
#include "libTAU/blockchain/repository.hpp"
#include "libTAU/blockchain/repository_track.hpp"

namespace libTAU::blockchain {
    struct repository_impl final : repository {

        repository_impl(sqlite3 *mSqlite, leveldb::DB *mLeveldb) : m_sqlite(mSqlite), m_leveldb(mLeveldb) {}

        bool init() override;

        bool create_user_state_db(aux::bytes chain_id) override;

        bool delete_user_state_db(aux::bytes chain_id) override;

        std::set<dht::public_key> get_all_peers(aux::bytes chain_id) override;

        bool delete_peer(aux::bytes chain_id, dht::public_key pubKey) override;

        bool is_account_exist(aux::bytes chain_id, dht::public_key pubKey) override;

        account get_account(aux::bytes chain_id, dht::public_key pubKey) override;

//        account get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) override;

        bool is_block_exist(sha256_hash hash) override;

        block get_block_by_hash(sha256_hash hash) override;

        bool save_block(block b, bool main_chain) override;

        bool connect_tip_block(block b) override;

        bool connect_tail_block(block b) override;

        bool rollback_block(block b) override;

        bool delete_block(sha256_hash hash) override;

        sha256_hash get_best_tip_block_hash(aux::bytes chain_id) override;

        bool set_best_tip_block_hash(aux::bytes chain_id, sha256_hash hash) override;

        bool delete_best_tip_block_hash(aux::bytes chain_id) override;

        sha256_hash get_best_tail_block_hash(aux::bytes chain_id) override;

        bool set_best_tail_block_hash(aux::bytes chain_id, sha256_hash hash) override;

        bool delete_best_tail_block_hash(aux::bytes chain_id) override;

        repository *start_tracking() override;

        void update_batch(std::map<std::string, std::string> cache, std::vector<block> main_chain_blocks) override;

        bool flush() override;

        bool commit() override;

        void rollback() override;

//        account get_account_from_user_db(aux::bytes chain_id, dht::public_key pubKey) override;

        bool update_user_state_db(block b) override;

        bool update_user_state_db(aux::bytes chain_id, dht::public_key pubKey) override;

        sha256_hash get_account_block_hash(aux::bytes chain_id, dht::public_key pubKey) override;

        bool save_account_block_hash(aux::bytes chain_id, dht::public_key pubKey, sha256_hash hash) override;

        account find_state_from_block(dht::public_key pubKey, block b) override;

        state_linker get_state_linker(sha256_hash block_hash) override;

        bool save_state_linker(state_linker stateLinker) override;

        bool save_block(block b) override;

    private:

        // sqlite3 instance
        sqlite3 *m_sqlite;

        // leveldb instance
        leveldb::DB* m_leveldb;

        // leveldb write batch
        leveldb::WriteBatch m_write_batch;

        // main chain blocks
        std::vector<block> m_main_chain_blocks;
    };
}

#endif //LIBTAU_REPOSITORY_IMPL_HPP
