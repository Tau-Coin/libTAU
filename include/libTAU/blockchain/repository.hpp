/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_REPOSITORY_HPP
#define LIBTAU_REPOSITORY_HPP


#include <map>
#include <set>

#include "libTAU/blockchain/index_key_info.hpp"
#include "libTAU/blockchain/account.hpp"
#include "libTAU/blockchain/block.hpp"
#include "libTAU/blockchain/state_linker.hpp"
#include "libTAU/blockchain/account_block_pointer.hpp"

namespace libTAU::blockchain {


    // repository: 存储账户、区块、状态链接器以及相应高度的索引数据，每个账户的状态是一个通过状态链接器链接起来的一个链式结构。
    // 每个账户会指向一个block hash，通过block hash可以到区块里面查找到对应该账户的状态，同时，通过block hash也能获得对应
    // 的状态链接器，状态链接器通过previous change指针，可以完整回溯该账户的变化历史。
    struct TORRENT_EXPORT repository {

        const std::string key_chains = "chains";
        const std::string key_separator = "_";
        const std::string key_suffix_state_linker = "linker";
        const std::string key_suffix_head_block_hash = "head";
        const std::string key_suffix_tail_block_hash = "tail";
        const std::string key_suffix_consensus_point_block_hash = "consensus";

        // init db
        virtual bool init() = 0;

        /**
         * Save a snapshot and start tracking future changes
         *
         * @return the tracker repository
         */
        virtual std::shared_ptr<repository> start_tracking() = 0;

//        virtual void
//        update_batch(const std::map<std::string, std::string> &cache, const std::vector<block> &connected_blocks,
//                     const std::vector<block> &discarded_blocks) = 0;

        virtual bool flush(const aux::bytes &chain_id) = 0;

        /**
         * Store all the temporary changes made
         * to the repository in the actual database
         */
        virtual bool commit(const aux::bytes &chain_id) = 0;

        /**
         * Undo all the changes made so far
         * to a snapshot of the repository
         */
        virtual void rollback(const aux::bytes &chain_id) = 0;

        // chain set api
        virtual bool add_new_chain(const aux::bytes &chain_id) = 0;

        virtual bool delete_chain(const aux::bytes &chain_id) = 0;

        // key point
        virtual sha256_hash get_head_block_hash(const aux::bytes &chain_id) = 0;

        virtual bool set_head_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) = 0;

        virtual bool delete_head_block_hash(const aux::bytes &chain_id) = 0;

        // state db api
        virtual bool create_state_db(const aux::bytes &chain_id) = 0;

        virtual bool delete_state_db(const aux::bytes &chain_id) = 0;

        virtual account get_account(const aux::bytes &chain_id, const dht::public_key &pubKey) = 0;

        virtual bool save_account(const aux::bytes &chain_id, const account &act) = 0;

        virtual bool delete_account(const aux::bytes &chain_id, const dht::public_key &pubKey) = 0;

        // block db api
        virtual bool create_block_db(const aux::bytes &chain_id) = 0;

        virtual bool delete_block_db(const aux::bytes &chain_id) = 0;

        virtual block get_block_by_hash(const aux::bytes &chain_id, const sha256_hash &hash) = 0;

        virtual block get_block_by_number(const aux::bytes &chain_id, int64_t block_number) = 0;

        virtual bool save_block(const block &blk, bool is_main_chain) = 0;

        bool save_main_chain_block(const block &blk);

        bool save_non_main_chain_block(const block &blk);

        virtual bool delete_block_by_hash(const aux::bytes &chain_id, const sha256_hash &hash) = 0;




//        virtual bool create_peer_db(const aux::bytes &chain_id) = 0;
//
//        virtual bool delete_peer_db(const aux::bytes &chain_id) = 0;
//
//        virtual std::set<dht::public_key> get_all_peers(const aux::bytes &chain_id) = 0;
//
//        virtual dht::public_key get_peer_randomly(const aux::bytes &chain_id) = 0;
//
//        virtual bool delete_peer_in_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) = 0;

        //        virtual account get_account_from_user_db(aux::bytes chain_id, dht::public_key pubKey) = 0;

//        bool add_block_peer_in_peer_db(const block &b);

//        virtual bool add_peer_in_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) = 0;
//
//        virtual bool create_gossip_peer_db(const aux::bytes &chain_id) = 0;
//
//        virtual bool delete_gossip_peer_db(const aux::bytes &chain_id) = 0;
//
//        virtual std::set<dht::public_key> get_all_gossip_peers(const aux::bytes &chain_id) = 0;
//
//        virtual dht::public_key get_gossip_peer_randomly(const aux::bytes &chain_id) = 0;
//
//        virtual bool delete_peer_in_gossip_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) = 0;
//
//        virtual bool delete_all_peers_in_gossip_peer_db(const aux::bytes &chain_id) = 0;
//
//        virtual bool add_peer_in_gossip_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) = 0;

        /**
         * check if account exist
         * @return true if account exist, false otherwise
         */
//        virtual bool is_account_exist(const aux::bytes &chain_id, const dht::public_key &pubKey) = 0;
//
//        std::int64_t get_effective_power(const aux::bytes &chain_id, const dht::public_key &pubKey);
//
//        account get_account(const aux::bytes &chain_id, const dht::public_key &pubKey);
//
//        account get_account_with_effective_power(const aux::bytes &chain_id, const dht::public_key &pubKey);

//        virtual account get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) = 0;

        /**
         * check if block exist
         * @return true if block exist, false otherwise
         */
//        virtual bool is_block_exist(const sha256_hash &hash) = 0;
//
//        virtual block get_block_by_hash(const sha256_hash &hash) = 0;

//        block get_main_chain_block_by_number(const aux::bytes &chain_id, std::int64_t block_number);
//
//        sha256_hash get_main_chain_block_hash_by_number(const aux::bytes &chain_id, std::int64_t block_number);
//
////        virtual bool save_block(block b, bool main_chain) = 0;
//
//        bool forward_update_state_linker(const aux::bytes &chain_id, const dht::public_key& pubKey,
//                                                 state_linker& stateLinker, const sha256_hash &current_block_hash);
//
//        bool backward_update_state_linker(const aux::bytes &chain_id, const dht::public_key& pubKey,
//                                                  state_linker& stateLinker, const sha256_hash &current_block_hash);

//        virtual bool connect_head_block(const block &b) = 0;
//
//        virtual bool connect_tail_block(const block &b) = 0;
//
//        virtual bool rollback_block(const block &b) = 0;
//
//        virtual bool expire_block(const block &b) = 0;

//        virtual bool delete_block(const sha256_hash &hash) = 0;
//
//        virtual sha256_hash get_head_block_hash(const aux::bytes &chain_id) = 0;
//
//        virtual bool set_head_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) = 0;
//
//        virtual bool delete_head_block_hash(const aux::bytes &chain_id) = 0;
//
//        virtual sha256_hash get_tail_block_hash(const aux::bytes &chain_id) = 0;
//
//        virtual bool set_tail_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) = 0;
//
//        virtual bool delete_tail_block_hash(const aux::bytes &chain_id) = 0;
//
//        virtual sha256_hash get_consensus_point_block_hash(const aux::bytes &chain_id) = 0;
//
//        virtual bool set_consensus_point_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) = 0;
//
//        virtual bool delete_consensus_point_block_hash(const aux::bytes &chain_id) = 0;

        /**
         * Save a snapshot and start tracking future changes
         *
         * @return the tracker repository
         */
//        virtual std::shared_ptr<repository> start_tracking() = 0;
//
//        virtual void
//        update_batch(const std::map<std::string, std::string> &cache, const std::vector<block> &connected_blocks,
//                     const std::vector<block> &discarded_blocks) = 0;
//
//        virtual bool flush(const aux::bytes &chain_id) = 0;
//
//        /**
//         * Store all the temporary changes made
//         * to the repository in the actual database
//         */
//        virtual bool commit() = 0;
//
//        /**
//         * Undo all the changes made so far
//         * to a snapshot of the repository
//         */
//        virtual void rollback() = 0;

//        virtual account_block_pointer get_account_block_pointer(const aux::bytes &chain_id, const dht::public_key &pubKey) = 0;
//
//        virtual bool save_account_block_pointer(const aux::bytes &chain_id, const dht::public_key &pubKey, const account_block_pointer &accountBlockPointer) = 0;
//
//        virtual bool delete_account_block_pointer(const aux::bytes &chain_id, const dht::public_key &pubKey) = 0;

//        static account find_state_from_block(const dht::public_key &pubKey, const block &b);

//        virtual state_linker get_state_linker(const sha256_hash &block_hash) = 0;
//
//        virtual bool save_state_linker(const state_linker &stateLinker) = 0;
//
//        virtual bool delete_state_linker(const sha256_hash &block_hash) = 0;

//        virtual bool save_block(const block &b) = 0;

//        bool save_non_main_chain_block(const block &b);

//        virtual bool delete_index_info(const aux::bytes &chain_id, std::int64_t block_number) = 0;
//
//        virtual index_key_info get_index_info(const aux::bytes &chain_id, std::int64_t block_number) = 0;
//
//        virtual bool save_index_info(const aux::bytes &chain_id, std::int64_t block_number, const index_key_info &indexKeyInfo) = 0;

//        bool delete_expired_data_by_height(const aux::bytes &chain_id, std::int64_t block_number);

//        virtual bool delete_all_outdated_data(const aux::bytes &chain_id, std::int64_t block_number) = 0;

//        virtual std::set<aux::bytes> get_all_chains() = 0;
//
//        virtual bool save_chains(const std::set<aux::bytes> &chains) = 0;
//
//        bool add_new_chain(const aux::bytes &chain_id);
//
//        bool delete_chain(const aux::bytes &chain_id);
//
//        virtual bool delete_all_chain_data(const aux::bytes &chain_id) = 0;
//
//        virtual std::string get_all_cache() = 0;
    };
}
#endif //LIBTAU_REPOSITORY_HPP
