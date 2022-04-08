/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_REPOSITORY_TRACK_HPP
#define LIBTAU_REPOSITORY_TRACK_HPP

#include <utility>
#include <map>
#include "libTAU/blockchain/repository.hpp"

namespace libTAU::blockchain {

    struct repository_track final : repository {

        explicit repository_track(repository *mRepository) : m_repository(mRepository) {}

        bool init() override;

        bool create_peer_db(const aux::bytes &chain_id) override;

        bool delete_peer_db(const aux::bytes &chain_id) override;

        std::set<dht::public_key> get_all_peers(const aux::bytes &chain_id) override;

        dht::public_key get_peer_randomly(const aux::bytes &chain_id) override;

        bool delete_peer_in_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) override;

        //        account get_account_from_user_db(aux::bytes chain_id, dht::public_key pubKey) override;

//        bool update_user_state_db(const block &b) override;

        bool add_peer_in_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) override;

        bool create_gossip_peer_db(const aux::bytes &chain_id) override;

        bool delete_gossip_peer_db(const aux::bytes &chain_id) override;

        std::set<dht::public_key> get_all_gossip_peers(const aux::bytes &chain_id) override;

        dht::public_key get_gossip_peer_randomly(const aux::bytes &chain_id) override;

        bool delete_peer_in_gossip_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) override;

        bool add_peer_in_gossip_peer_db(const aux::bytes &chain_id, const dht::public_key &pubKey) override;

        bool is_account_exist(const aux::bytes &chain_id, const dht::public_key &pubKey) override;

//        std::int64_t get_effective_power(const aux::bytes &chain_id, const dht::public_key &pubKey) override;
//
//        account get_account(const aux::bytes &chain_id, const dht::public_key &pubKey) override;
//
//        account get_account_with_effective_power(const aux::bytes &chain_id, const dht::public_key &pubKey) override;

//        account get_account_without_verification(aux::bytes chain_id, dht::public_key pubKey) override;

        bool is_block_exist(const sha256_hash &hash) override;

        block get_block_by_hash(const sha256_hash &hash) override;

//        block get_main_chain_block_by_number(const aux::bytes &chain_id, std::int64_t block_number) override;
//
//        sha256_hash get_main_chain_block_hash_by_number(const aux::bytes &chain_id, std::int64_t block_number) override;

//        bool save_block(block b, bool main_chain) override;

//        bool forward_update_state_linker(const aux::bytes &chain_id, const dht::public_key& pubKey,
//                                         state_linker& stateLinker, const sha256_hash &current_block_hash) override;
//
//        bool backward_update_state_linker(const aux::bytes &chain_id, const dht::public_key& pubKey,
//                                          state_linker& stateLinker, const sha256_hash &current_block_hash) override;

        bool connect_head_block(block &b) override;

        bool connect_tail_block(block &b) override;

        bool rollback_block(block &b) override;

        bool expire_block(block &b) override;

        bool delete_block(const sha256_hash &hash) override;

        sha256_hash get_head_block_hash(const aux::bytes &chain_id) override;

        bool set_head_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) override;

        bool delete_head_block_hash(const aux::bytes &chain_id) override;

        sha256_hash get_tail_block_hash(const aux::bytes &chain_id) override;

        bool set_tail_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) override;

        bool delete_tail_block_hash(const aux::bytes &chain_id) override;

        sha256_hash get_consensus_point_block_hash(const aux::bytes &chain_id) override;

        bool set_consensus_point_block_hash(const aux::bytes &chain_id, const sha256_hash &hash) override;

        bool delete_consensus_point_block_hash(const aux::bytes &chain_id) override;

        std::shared_ptr<repository> start_tracking() override;

        void update_batch(const std::map<std::string, std::string> &cache, const std::vector<block> &connected_blocks,
                          const std::vector<block> &discarded_blocks) override;

        bool flush(const aux::bytes &chain_id) override;

        bool commit() override;

        void rollback() override;

        account_block_pointer get_account_block_pointer(const aux::bytes &chain_id, const dht::public_key &pubKey) override;

        bool save_account_block_pointer(const aux::bytes &chain_id, const dht::public_key &pubKey, const account_block_pointer &accountBlockPointer) override;

        bool delete_account_block_pointer(const aux::bytes &chain_id, const dht::public_key &pubKey) override;

//        account find_state_from_block(const dht::public_key &pubKey, const block &b) override;

        state_linker get_state_linker(const sha256_hash &block_hash) override;

        bool save_state_linker(const state_linker &stateLinker) override;

        bool delete_state_linker(const sha256_hash &block_hash) override;

        bool save_block(block &b) override;

//        bool save_non_main_chain_block(block &b) override;

        bool delete_index_info(const aux::bytes &chain_id, std::int64_t block_number) override;

        index_key_info get_index_info(const aux::bytes &chain_id, std::int64_t block_number) override;

        bool save_index_info(const aux::bytes &chain_id, std::int64_t block_number, const index_key_info &indexKeyInfo) override;

//        bool delete_expired_data_by_height(const aux::bytes &chain_id, std::int64_t block_number) override;

        std::set<aux::bytes> get_all_chains() override;

        bool save_chains(const std::set<aux::bytes> &chains) override;

//        bool add_new_chain(const aux::bytes &chain_id) override;
//
//        bool delete_chain(const aux::bytes &chain_id) override;

        std::string get_all_cache() override;

    private:

        repository *m_repository;

        std::map<std::string, std::string> m_cache;

        // main chain connected blocks
        std::vector<block> m_connected_blocks;

        // main chain discarded blocks
        std::vector<block> m_discarded_blocks;
    };
}

#endif //LIBTAU_REPOSITORY_TRACK_HPP
