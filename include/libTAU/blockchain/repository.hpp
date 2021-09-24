/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_REPOSITORY_HPP
#define LIBTAU_REPOSITORY_HPP


#include <map>
#include "libTAU/blockchain/index_key_info.hpp"
#include "libTAU/blockchain/account.hpp"
#include "libTAU/blockchain/block.hpp"
#include "libTAU/blockchain/state_linker.hpp"

namespace libTAU::blockchain {


    // repository: 存储账户、区块、状态链接器以及相应高度的索引数据，每个账户的状态是一个通过状态链接器链接起来的一个链式结构。
    // 每个账户会指向一个block hash，通过block hash可以到区块里面查找到对应该账户的状态，同时，通过block hash也能获得对应
    // 的状态链接器，状态链接器通过previous change指针，可以完整回溯该账户的变化历史。
    struct TORRENT_EXPORT repository {

        const std::string key_separator = "_";
        const std::string key_suffix_state_linker = "linker";
        const std::string key_suffix_best_tip_block_hash = "tip";
        const std::string key_suffix_best_tail_block_hash = "tail";

        // init db
        virtual bool init() = 0;

        virtual bool create_user_state_db(aux::bytes chain_id) = 0;

        virtual bool delete_user_state_db(aux::bytes chain_id) = 0;

        virtual std::set<dht::public_key> get_all_peers(aux::bytes chain_id) = 0;

        virtual bool delete_peer(aux::bytes chain_id, dht::public_key pubKey) = 0;

        /**
         * check if account exist
         * @return true if account exist, false otherwise
         */
        virtual bool is_account_exist(aux::bytes chain_id, dht::public_key pubKey) = 0;

        virtual account get_account(aux::bytes chain_id, dht::public_key pubKey) = 0;

//        virtual account get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) = 0;

        /**
         * check if block exist
         * @return true if block exist, false otherwise
         */
        virtual bool is_block_exist(sha256_hash hash) = 0;

        virtual block get_block_by_hash(sha256_hash hash) = 0;

//        virtual bool save_block(block b, bool main_chain) = 0;

        virtual bool forward_update_last_change_block_hash(aux::bytes chain_id, const dht::public_key& pubKey,
                                                           state_linker& stateLinker, sha256_hash current_block_hash) = 0;

        virtual bool backward_update_last_change_block_hash(aux::bytes chain_id, const dht::public_key& pubKey,
                                                            state_linker& stateLinker, sha256_hash current_block_hash) = 0;

        virtual bool connect_tip_block(block b) = 0;

        virtual bool connect_tail_block(block b) = 0;

        virtual bool rollback_block(block b) = 0;

        virtual bool delete_block(sha256_hash hash) = 0;

        virtual sha256_hash get_best_tip_block_hash(aux::bytes chain_id) = 0;

        virtual bool set_best_tip_block_hash(aux::bytes chain_id, sha256_hash hash) = 0;

        virtual bool delete_best_tip_block_hash(aux::bytes chain_id) = 0;

        virtual sha256_hash get_best_tail_block_hash(aux::bytes chain_id) = 0;

        virtual bool set_best_tail_block_hash(aux::bytes chain_id, sha256_hash hash) = 0;

        virtual bool delete_best_tail_block_hash(aux::bytes chain_id) = 0;

        /**
         * Save a snapshot and start tracking future changes
         *
         * @return the tracker repository
         */
        virtual repository* start_tracking() = 0;

        virtual void update_batch(std::map<std::string, std::string> cache, std::vector<block> main_chain_blocks) = 0;

        virtual bool flush() = 0;

        /**
         * Store all the temporary changes made
         * to the repository in the actual database
         */
        virtual bool commit() = 0;

        /**
         * Undo all the changes made so far
         * to a snapshot of the repository
         */
        virtual void rollback() = 0;

//        virtual account get_account_from_user_db(aux::bytes chain_id, dht::public_key pubKey) = 0;

        virtual bool update_user_state_db(block b) = 0;

        virtual bool update_user_state_db(aux::bytes chain_id, dht::public_key pubKey) = 0;

        virtual sha256_hash get_account_block_hash(aux::bytes chain_id, dht::public_key pubKey) = 0;

        virtual bool save_account_block_hash(aux::bytes chain_id, dht::public_key pubKey, sha256_hash hash) = 0;

        virtual bool delete_account_block_hash(aux::bytes chain_id, dht::public_key pubKey) = 0;

        virtual account find_state_from_block(dht::public_key pubKey, block b) = 0;

        virtual state_linker get_state_linker(sha256_hash block_hash) = 0;

        virtual bool save_state_linker(state_linker stateLinker) = 0;

        virtual bool delete_state_linker(sha256_hash block_hash) = 0;

        virtual bool save_block(block b) = 0;

        virtual bool save_non_main_chain_block(block b) = 0;

        virtual bool delete_index_info(aux::bytes chain_id, std::int64_t block_number) = 0;

        virtual index_key_info get_index_info(aux::bytes chain_id, std::int64_t block_number) = 0;

        virtual bool save_index_info(aux::bytes chain_id, std::int64_t block_number, index_key_info indexKeyInfo) = 0;

        virtual bool delete_outdated_data_by_height(aux::bytes chain_id, std::int64_t block_number) = 0;
    };
}
#endif //LIBTAU_REPOSITORY_HPP
