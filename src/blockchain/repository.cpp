/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/


#include <libTAU/blockchain/repository.hpp>

namespace libTAU::blockchain {

    std::string repository::chains_db_name() {
        return "t" + table_chains;
    }

    std::string repository::blocks_db_name(const aux::bytes &chain_id) {
        // prevent SQL injection
        sha1_hash hash = hasher(chain_id).final();
        // 't' + hex(sha1(chain id))
        return "t" + aux::toHex(hash) + table_blocks;
    }

    std::string repository::state_db_name(const aux::bytes &chain_id) {
        // prevent SQL injection
        sha1_hash hash = hasher(chain_id).final();
        // 't' + hex(sha1(chain id))
        return "t" + aux::toHex(hash) + table_state;
    }

    std::string repository::state_array_db_name(const aux::bytes &chain_id) {
        // prevent SQL injection
        sha1_hash hash = hasher(chain_id).final();
        // 't' + hex(sha1(chain id))
        return "t" + aux::toHex(hash) + table_state_array;
    }

    std::string repository::peer_db_name(const aux::bytes &chain_id) {
        // prevent SQL injection
        sha1_hash hash = hasher(chain_id).final();
        // 't' + hex(sha1(chain id))
        return "t" + aux::toHex(hash) + table_peer;
    }

    std::string repository::acl_db_name(const aux::bytes &chain_id) {
        // prevent SQL injection
        sha1_hash hash = hasher(chain_id).final();
        // 't' + hex(sha1(chain id))
        return "t" + aux::toHex(hash) + table_acl;
    }

//    bool repository::save_main_chain_block(const block &blk) {
//        return save_block(blk, true);
//    }

//    bool repository::save_non_main_chain_block(const block &blk) {
//        return save_block(blk, false);
//    }

//    bool repository::add_block_peer_in_peer_db(const block &b) {
//        auto peers = b.get_block_peers();
//        for (auto const& peer: peers) {
//            add_peer_in_peer_db(b.chain_id(), peer);
//        }
//
//        return true;
//    }

//    std::int64_t repository::get_effective_power(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        account_block_pointer accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
//
//        if (!accountBlockPointer.empty()) {
//            if (accountBlockPointer.latest_block_hash() == accountBlockPointer.oldest_block_hash()) {
//                return 1;
//            } else {
//                block latest_block = get_block_by_hash(accountBlockPointer.latest_block_hash());
//                block oldest_block = get_block_by_hash(accountBlockPointer.oldest_block_hash());
//                if (!latest_block.empty() && !oldest_block.empty()) {
//                    account account1 = find_state_from_block(pubKey, latest_block);
//                    account account2 = find_state_from_block(pubKey, oldest_block);
//
//                    return account1.nonce() - account2.nonce() + 1;
//                }
//            }
//        }
//
//        return 0;
//    }
//
//    account repository::get_account(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        account_block_pointer accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
//
//        if (!accountBlockPointer.empty() && !accountBlockPointer.latest_block_hash().is_all_zeros()) {
//            block b = get_block_by_hash(accountBlockPointer.latest_block_hash());
//            if (!b.empty()) {
//                return find_state_from_block(pubKey, b);
//            }
//        }
//
//        return account(0, 0, 0);
//    }
//
//    account repository::get_account_with_effective_power(const aux::bytes &chain_id, const dht::public_key &pubKey) {
//        account acct(0, 0, 0, 0);
//        account_block_pointer accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
//
//        if (!accountBlockPointer.empty() && !accountBlockPointer.latest_block_hash().is_all_zeros()) {
//            block latest_block = get_block_by_hash(accountBlockPointer.latest_block_hash());
//            if (!latest_block.empty()) {
//                acct = find_state_from_block(pubKey, latest_block);
//
//                if (accountBlockPointer.latest_block_hash() == accountBlockPointer.oldest_block_hash()) {
//                    acct.set_effective_power(1);
//                } else {
//                    block oldest_block = get_block_by_hash(accountBlockPointer.oldest_block_hash());
//                    if (!oldest_block.empty()) {
//                        account account2 = find_state_from_block(pubKey, oldest_block);
//                        acct.set_effective_power(acct.nonce() - account2.nonce() + 1);
//                    }
//                }
//            }
//        }
//
//        return acct;
//    }

//    block repository::get_main_chain_block_by_number(const aux::bytes &chain_id, std::int64_t block_number) {
//        auto index_info = get_index_info(chain_id, block_number);
//        if (!index_info.empty() && !index_info.main_chain_block_hash().is_all_zeros()) {
//            return get_block_by_hash(index_info.main_chain_block_hash());
//        }
//
//        return block();
//    }
//
//    sha256_hash repository::get_main_chain_block_hash_by_number(const aux::bytes &chain_id, std::int64_t block_number) {
//        auto index_info = get_index_info(chain_id, block_number);
//        if (!index_info.empty() && !index_info.main_chain_block_hash().is_all_zeros()) {
//            return index_info.main_chain_block_hash();
//        }
//
//        return libTAU::sha256_hash();
//    }

//    account repository::find_state_from_block(const dht::public_key &pubKey, const block &b) {
//        if (pubKey == b.miner()) {
//            return account(b.miner_balance(), b.miner_nonce(), b.block_number());
//        } else if (pubKey == b.tx().sender()) {
//            return account(b.sender_balance(), b.sender_nonce(), b.block_number());
//        } else if (pubKey == b.tx().receiver()) {
//            return account(b.receiver_balance(), b.receiver_nonce(), b.block_number());
//        }
//
//        return account(0, 0, 0);
//    }

//    bool repository::save_non_main_chain_block(const block &b) {
//        // save block
//        if (!save_block(b))
//            return false;
//
//        index_key_info indexKeyInfo = get_index_info(b.chain_id(), b.block_number());
//        indexKeyInfo.add_non_main_chain_block_hash(b.sha256());
//        if (!save_index_info(b.chain_id(), b.block_number(), indexKeyInfo))
//            return false;
//
//        return true;
//    }

//    bool repository::forward_update_state_linker(const aux::bytes &chain_id, const dht::public_key &pubKey,
//                                                 state_linker &stateLinker, const sha256_hash &current_block_hash) {
//        account_block_pointer accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
//        if (!accountBlockPointer.empty()) {
//            auto linker = get_state_linker(accountBlockPointer.latest_block_hash());
//            linker.update_next_change_block_hash(pubKey, current_block_hash);
//            stateLinker.update_previous_change_block_hash(pubKey, accountBlockPointer.latest_block_hash());
//            if (!save_state_linker(linker))
//                return false;
//        }
//
//        return true;
//    }
//
//    bool repository::backward_update_state_linker(const aux::bytes &chain_id, const dht::public_key &pubKey,
//                                                  state_linker &stateLinker, const sha256_hash &current_block_hash) {
//        account_block_pointer accountBlockPointer = get_account_block_pointer(chain_id, pubKey);
//        if (!accountBlockPointer.empty()) {
//            auto linker = get_state_linker(accountBlockPointer.oldest_block_hash());
//            linker.update_previous_change_block_hash(pubKey, current_block_hash);
//            stateLinker.update_next_change_block_hash(pubKey, accountBlockPointer.oldest_block_hash());
//            if (!save_state_linker(linker))
//                return false;
//        }
//
//        return true;
//    }

//    bool repository::delete_expired_data_by_height(const aux::bytes &chain_id, std::int64_t block_number) {
//        index_key_info indexKeyInfo = get_index_info(chain_id, block_number);
//        auto& main_chain_block_hash = indexKeyInfo.main_chain_block_hash();
//        if (!main_chain_block_hash.is_all_zeros()) {
//            if (!delete_block(main_chain_block_hash))
//                return false;
//            if (!delete_state_linker(main_chain_block_hash))
//                return false;
//        }
//
//        auto& non_main_chain_block_hash_set = indexKeyInfo.non_main_chain_block_hash_set();
//        for (auto const& hash: non_main_chain_block_hash_set) {
//            if (!delete_block(hash))
//                return false;
//            if (!delete_state_linker(hash))
//                return false;
//        }
//
//        auto& associated_peers = indexKeyInfo.associated_peers();
//        for (auto const& peer: associated_peers) {
//            auto s = get_account(chain_id, peer);
//            if (!s.empty() && s.block_number() <= block_number) {
//                if (!delete_account_block_pointer(chain_id, peer))
//                    return false;
//            }
//        }
//
//        return delete_index_info(chain_id, block_number);
//    }

//    bool repository::add_new_chain(const aux::bytes &chain_id) {
//        std::set<aux::bytes> chains = get_all_chains();
//        chains.insert(chain_id);
//
//        return save_chains(chains);
//    }
//
//    bool repository::delete_chain(const aux::bytes &chain_id) {
//        std::set<aux::bytes> chains = get_all_chains();
//        chains.erase(chain_id);
//
//        return save_chains(chains);
//    }

}
