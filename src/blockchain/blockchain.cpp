/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <utility>

#include "libTAU/blockchain/blockchain.hpp"
#include "libTAU/blockchain/consensus.hpp"
#include "libTAU/common/entry_type.hpp"
#include "libTAU/kademlia/dht_tracker.hpp"


using namespace std::placeholders;

namespace libTAU::blockchain {

    bool blockchain::init() {
        try {
            // get all chains
            auto chains = m_repository->get_all_chains();
            m_chains.insert(m_chains.end(), chains.begin(), chains.end());

            // load all chains
            bool has_tau = false;
            for (auto const &chain_id: m_chains) {
                if (chain_id == TAU_CHAIN_ID) {
                    has_tau = true;
                }
                load_chain(chain_id);
            }

            // create tau chain
//            if (!has_tau) {
//                create_TAU_chain();
//            }
        } catch (std::exception &e) {
            log("Exception init [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            return false;
        }

        return true;
    }

    bool blockchain::start()
    {
        log("INFO: Start BlockChain...");
        if (!init()) {
            log("ERROR: Init fail.");
            return false;
        }

        m_stop = false;

        m_refresh_timer.expires_after(milliseconds(m_refresh_time));
        m_refresh_timer.async_wait(std::bind(&blockchain::refresh_timeout, self(), _1));

        m_vote_timer.expires_after(seconds(DEFAULT_BLOCK_TIME));
        m_vote_timer.async_wait(std::bind(&blockchain::refresh_vote_timeout, self(), _1));

        m_exchange_tx_timer.expires_after(seconds(EXCHANGE_TX_TIME));
        m_exchange_tx_timer.async_wait(std::bind(&blockchain::refresh_tx_timeout, self(), _1));

        return true;
    }

    bool blockchain::stop()
    {
        m_stop = true;

        clear_all_cache();

        log("INFO: Stop BlockChain...");

        return true;
    }

    bool blockchain::followChain(const chain_url &url) {
        return followChain(url.chain_id(), url.peers());
    }

    bool blockchain::followChain(const aux::bytes &chain_id, const std::set<dht::public_key>& peers) {
        if (!chain_id.empty()) {
            log("INFO: Follow chain:%s", aux::toHex(chain_id).c_str());

            // create sqlite peer db
            if (!m_repository->create_peer_db(chain_id)) {
                log("INFO: chain:%s, create peer db fail.", aux::toHex(chain_id).c_str());
            }
            if (!m_repository->create_gossip_peer_db(chain_id)) {
                log("INFO: chain:%s, create gossip peer db fail.", aux::toHex(chain_id).c_str());
            }

            // add peer into db
            for (auto const &peer: peers) {
                log("INFO: chain:%s, initial peer:%s", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                if (!m_repository->add_peer_in_peer_db(chain_id, peer)) {
                    log("INFO: chain:%s, insert peer:%s fail in peer db.", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                }
                if (!m_repository->add_peer_in_gossip_peer_db(chain_id, peer)) {
                    log("INFO: chain:%s, insert gossip peer:%s fail in gossip db.", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                }
            }

            // try to load chain info
            load_chain(chain_id);

            // follow chain id in memory and db
            m_repository->add_new_chain(chain_id);
            m_chains.push_back(chain_id);

            return true;
        } else {
            return false;
        }
    }

    bool blockchain::unfollowChain(const aux::bytes &chain_id) {
        log("INFO: Unfollow chain:%s", aux::toHex(chain_id).c_str());

        // remove chain id from memory
        for (auto it = m_chains.begin(); it != m_chains.end(); ++it) {
            if (chain_id == *it) {
                m_chains.erase(it);
                break;
            }
        }

        // remove chain id from db
        m_repository->delete_chain(chain_id);
        // remove chain cache
        clear_chain_cache(chain_id);
        // todo: clear data in db?

        return true;
    }

    bool blockchain::load_chain(const aux::bytes &chain_id) {
        log("INFO: load chain[%s]", aux::toHex(chain_id).c_str());
        // create tx pool
        m_tx_pools[chain_id] = tx_pool(m_repository.get());

        // get all peers
//        m_chain_peers[chain_id] = m_repository->get_all_peers(chain_id);
//        m_chain_gossip_peers[chain_id] = m_repository->get_all_gossip_peers(chain_id);

        // load key point block in memory
        // load head/tail/consensus block
        auto head_block_hash = m_repository->get_head_block_hash(chain_id);
        auto tail_block_hash = m_repository->get_tail_block_hash(chain_id);
        auto consensus_point_block_hash = m_repository->get_consensus_point_block_hash(chain_id);
        log("INFO chain id[%s], head block hash[%s], tail block hash[%s], consensus point block hash[%s]",
            aux::toHex(chain_id).c_str(), aux::toHex(head_block_hash.to_string()).c_str(),
            aux::toHex(tail_block_hash.to_string()).c_str(), aux::toHex(consensus_point_block_hash.to_string()).c_str());
        if (!head_block_hash.is_all_zeros() && !tail_block_hash.is_all_zeros() && !consensus_point_block_hash.is_all_zeros()) {
            auto head_block = m_repository->get_block_by_hash(head_block_hash);
            auto tail_block = m_repository->get_block_by_hash(tail_block_hash);
            auto consensus_point_block = m_repository->get_block_by_hash(consensus_point_block_hash);
            if (!head_block.empty() && !tail_block.empty() && !consensus_point_block.empty()) {
                m_head_blocks[chain_id] = head_block;
                m_tail_blocks[chain_id] = tail_block;
                m_consensus_point_blocks[chain_id] = consensus_point_block;
                log("INFO: Head block: %s", head_block.to_string().c_str());
                log("INFO: Tail block: %s", tail_block.to_string().c_str());
                log("INFO: Consensus point block: %s", consensus_point_block.to_string().c_str());

                // try to update voting point block
                try_to_update_voting_point_block(chain_id);
            }
        }

        return true;
    }

    std::int64_t blockchain::get_total_milliseconds() {
        return total_milliseconds(system_clock::now().time_since_epoch());
    }

    void blockchain::clear_all_cache() {
        m_chains.clear();
        m_tx_pools.clear();
//        m_chain_peers.clear();
//        m_chain_gossip_peers.clear();
//        m_unchoked_peers.clear();
//        m_unchoked_peer_signal.clear();
//        m_update_peer_time.clear();
        m_last_got_data_time.clear();
        m_blocks.clear();
        m_head_blocks.clear();
        m_tail_blocks.clear();
        m_consensus_point_blocks.clear();
        m_voting_point_blocks.clear();
        m_best_votes.clear();
        m_votes.clear();
        m_latest_signal_time.clear();
    }

    void blockchain::clear_chain_cache(const aux::bytes &chain_id) {
//        m_chains.erase(chain_id);
        m_tx_pools[chain_id].clear();
//        m_chain_peers[chain_id].clear();
//        m_chain_gossip_peers[chain_id].clear();
//        m_unchoked_peers[chain_id].clear();
//        m_unchoked_peer_signal[chain_id].clear();
//        m_update_peer_time.erase(chain_id);
        m_last_got_data_time.erase(chain_id);
        m_blocks[chain_id].clear();
        m_head_blocks.erase(chain_id);
        m_tail_blocks.erase(chain_id);
        m_consensus_point_blocks.erase(chain_id);
        m_voting_point_blocks.erase(chain_id);
        m_best_votes.erase(chain_id);
        m_votes[chain_id].clear();
        m_latest_signal_time[chain_id].clear();
    }

    void blockchain::refresh_timeout(const error_code &e) {
        if (e || m_stop) return;

        try {
            // 随机挑选一条
            aux::bytes chain_id = select_chain_randomly();
            if (!chain_id.empty()) {
                log("INFO: Select chain:%s", aux::toHex(chain_id).c_str());

                auto &block_map = m_blocks[chain_id];

                // 1. if empty chain, init chain with the best voting block
                if (is_empty_chain(chain_id)) {
                    auto &best_vote = m_best_votes[chain_id];
                    if (!best_vote.empty()) {
                        auto blk = get_block_from_cache_or_db(chain_id, best_vote.block_hash());
                        if (!blk.empty()) {
                            process_block(chain_id, blk);
                        }
                    }
                }

                if (!is_empty_chain(chain_id)) {
                    // 2. try to connect head/tail block
                    auto &head_block = m_head_blocks[chain_id];
                    auto &tail_block = m_tail_blocks[chain_id];
                    for (auto it = block_map.begin(); it != block_map.end();) {
                        if (head_block.empty() || it->second.previous_block_hash() == head_block.sha256() ||
                            it->second.sha256() == tail_block.previous_block_hash()) {
                            process_block(chain_id, it->second);
                            block_map.erase(it);

                            it = block_map.begin();
                            continue;
                        }

                        ++it;
                    }

                    // 3. try to re-branch to a more difficult chain
                    for (auto it = block_map.begin(); it != block_map.end();) {
                        // todo: do it in callback? O(n)
                        auto blk = it->second;
                        if (!blk.empty() && blk.cumulative_difficulty() > head_block.cumulative_difficulty()) {
                            auto result = try_to_rebranch(chain_id, blk);
                            // clear block cache if re-branch success/fail
                            if (result == FAIL) {
                                // clear all blocks on the same chain
                                remove_all_same_chain_blocks_from_cache(blk);

                                it = block_map.begin();
                                continue;
                            } else if (result == SUCCESS) {
                                // clear all ancestor blocks
                                remove_all_ancestor_blocks_from_cache(blk);

                                it = block_map.begin();
                                continue;
                            }
                        }

                        ++it;
                    }

                    // 4. check if need to re-branch to the best vote
                    auto &best_vote = m_best_votes[chain_id];
                    if (!best_vote.empty()) {
                        log("INFO chain[%s] current best vote[%s]", aux::toHex(chain_id).c_str(), best_vote.to_string().c_str());

                        auto &consensus_point_block = m_consensus_point_blocks[chain_id];
                        if (consensus_point_block.sha256() != best_vote.block_hash()) {
                            auto hash = m_repository->get_main_chain_block_hash_by_number(chain_id,
                                                                                          best_vote.block_number());
                            // if current main chain block hash and voting block hash mismatch
                            if (hash != best_vote.block_hash()) {
                                log("INFO chain[%s] main chain block[%s] mismatch the best vote",
                                    aux::toHex(chain_id).c_str(), aux::toHex(hash.to_string()).c_str());
                                // re-branch
                                auto vote_block = get_block_from_cache_or_db(chain_id, best_vote.block_hash());
                                if (!vote_block.empty()) {
                                    log("INFO chain[%s] try to re-branch to voting block[%s]",
                                        aux::toHex(chain_id).c_str(), vote_block.to_string().c_str());
                                    auto result = try_to_rebranch(chain_id, vote_block);
                                    // clear block cache if re-branch success/fail
                                    if (result == SUCCESS) {
                                        // clear all ancestor blocks
                                        remove_all_same_chain_blocks_from_cache(vote_block);

                                        // update consensus point block hash as best voting block
                                        auto blk = m_repository->get_block_by_hash(best_vote.block_hash());
                                        m_consensus_point_blocks[chain_id] = vote_block;
                                        m_repository->set_consensus_point_block_hash(chain_id, best_vote.block_hash());

                                        m_ses.alerts().emplace_alert<blockchain_new_consensus_point_block_alert>(vote_block);
                                    } else if (result == FAIL) {
                                        remove_all_ancestor_blocks_from_cache(vote_block);
                                    }
                                }
                            } else {
                                // update consensus point block hash as main chain hash
                                auto blk = m_repository->get_block_by_hash(hash);
                                m_consensus_point_blocks[chain_id] = blk;
                                m_repository->set_consensus_point_block_hash(chain_id, hash);

                                m_ses.alerts().emplace_alert<blockchain_new_consensus_point_block_alert>(blk);
                            }
                        }
                    }

                    // 5. try to mine on the best chain
                    if (is_sync_completed(chain_id)) {
                        block blk = try_to_mine_block(chain_id);

                        if (!blk.empty()) {
                            // process mined block
                            log("INFO chain[%s] process mined block[%s]",
                                aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                            process_block(chain_id, blk);

                            common::block_entry blockEntry(blk);
                            common::entry_task task(common::block_entry::data_type_id, blockEntry.get_entry(), get_total_milliseconds());
                            add_entry_task_to_queue(chain_id, task);
                        }
                    }
                }

                // 6. exchange chain info with others
                // check if need to refresh unchoed peers
//                try_to_refresh_unchoked_peers(chain_id);

                // get four unchoked peers
//                auto& unchoked_peers = m_unchoked_peers[chain_id];
//                std::vector<dht::public_key> peers(unchoked_peers.begin(), unchoked_peers.end());
//                // get one peer from gossip db
////                auto p = select_peer_randomly(chain_id);
//                auto p = m_repository->get_gossip_peer_randomly(chain_id);
//                if (!(p == dht::public_key())) {
//                    log("gossip peer:%s", aux::toHex(p.bytes).c_str());
//                    peers.push_back(p);
//                }
//                // get one peer from tx pool
//                std::set<dht::public_key> tx_active_peers = m_tx_pools[chain_id].get_active_peers();
//                std::vector<dht::public_key> active_peers(tx_active_peers.begin(), tx_active_peers.end());
//                if (!active_peers.empty()) {
//                    // 产生随机数
//                    srand(get_total_milliseconds());
//                    auto index = rand() % active_peers.size();
//                    peers.push_back(active_peers[index]);
//                }
//
//                log("peer size: %zu", peers.size());
//                // select one randomly from 6 peers to get
//                if (!peers.empty())
//                {
//                    // 产生随机数
//                    srand(get_total_milliseconds());
//                    auto index = rand() % peers.size();
//                    request_signal(chain_id, peers[index]);
//                }

                // current time
                auto now = get_total_milliseconds();
//                if (now > m_last_got_data_time[chain_id] + blockchain_max_access_peer_interval) {
//                    // publish signal
//                    auto peer = select_peer_randomly(chain_id);
//                    publish_signal(chain_id, peer);
//                }

                if (now - m_visiting_time[chain_id].second > 60 * 1000) {
                    auto peer = select_peer_randomly(chain_id);

                    if (peer != *m_ses.pubkey()) {
                        common::vote_request_entry voteRequestEntry(chain_id);
                        send_to(chain_id, peer, voteRequestEntry.get_entry());

                        common::head_block_request_entry headBlockRequestEntry(chain_id);
                        send_to(chain_id, peer, headBlockRequestEntry.get_entry());

                        m_visiting_history[chain_id].insert(peer);
                    }
                }

                if (m_tasks[chain_id].empty()) {
                    auto &head_block = m_head_blocks[chain_id];
                    // get my demand
                    std::set<sha256_hash> demand_block_hash_set;
                    auto &best_vote = m_best_votes[chain_id];
                    // voting demand block first
                    if (is_empty_chain(chain_id)) {
                        if (!best_vote.empty()) {
                            demand_block_hash_set.insert(best_vote.block_hash());
                        } else {
                            // select one randomly if voting has no result
                            auto &votes = m_votes[chain_id];
                            auto it = votes.begin();
                            if (it != votes.end()) {
                                // select one randomly as the best vote
                                m_best_votes[chain_id] = it->second;
                                // request the best voting block
                                demand_block_hash_set.insert(it->second.block_hash());
                            }
                        }
                    } else {
                        // not empty chain

                        if (!best_vote.empty()) {
                            // check if best vote match main chain block
                            auto hash = m_repository->get_main_chain_block_hash_by_number(chain_id, best_vote.block_number());
                            if (hash != best_vote.block_hash()) {
                                // if not match, request blocks on best vote branch
                                auto previous_hash = best_vote.block_hash();
                                while (true) {
                                    // search until found absent or fork point block
                                    auto blk = get_block_from_cache_or_db(chain_id, previous_hash);
                                    if (blk.empty()) {
                                        log("INFO chain[%s] Cannot find demanding block[%s] in db/cache",
                                            aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                                        demand_block_hash_set.insert(previous_hash);
                                        break;
                                    } else {
                                        auto main_chain_hash = m_repository->get_main_chain_block_hash_by_number(chain_id, blk.block_number());
                                        if (main_chain_hash == blk.sha256()) {
                                            break;
                                        }
                                        previous_hash = blk.previous_block_hash();
                                    }
                                }
                            } else {
                                auto &block_map = m_blocks[chain_id];
                                for (auto & item: block_map) {
                                    auto b = item.second;
                                    // find a more difficult block
                                    if (b.cumulative_difficulty() > head_block.cumulative_difficulty()) {
                                        // find absent block
                                        auto previous_hash = b.previous_block_hash();
                                        bool found_absent = false;
                                        while (true) {
                                            // search until found absent or fork point block
                                            b = get_block_from_cache_or_db(chain_id, previous_hash);
                                            if (b.empty()) {
                                                log("INFO: ----chain[%s] Cannot find demanding block hash[%s] in db/cache",
                                                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                                                demand_block_hash_set.insert(previous_hash);
                                                found_absent = true;
                                                break;
                                            } else {
                                                auto main_chain_hash = m_repository->get_main_chain_block_hash_by_number(chain_id, b.block_number());
                                                if (main_chain_hash == b.sha256()) {
                                                    break;
                                                }
                                                log("INFO: ----chain[%s] Got block [%s] in local",
                                                    aux::toHex(chain_id).c_str(),  b.to_string().c_str());
                                                previous_hash = b.previous_block_hash();
                                            }
                                        }
                                        // if found absent, stop to search; otherwise continue to find more difficult in cache
                                        if (found_absent)
                                            break;
                                    }
                                }
                            }
                        } else {
                            // not empty chain, but no best vote
                            auto &block_map = m_blocks[chain_id];
                            for (auto & item: block_map) {
                                auto b = item.second;
                                if (b.cumulative_difficulty() > head_block.cumulative_difficulty()) {
                                    // find absent block
                                    auto previous_hash = b.previous_block_hash();
                                    bool found_absent = false;
                                    while (true) {
                                        // search until found absent or fork point block
                                        b = get_block_from_cache_or_db(chain_id, previous_hash);
                                        if (b.empty()) {
                                            log("INFO chain[%s] Cannot find demanding block[%s] in db/cache",
                                                aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                                            demand_block_hash_set.insert(previous_hash);
                                            found_absent = true;
                                            break;
                                        } else {
                                            auto main_chain_hash = m_repository->get_main_chain_block_hash_by_number(chain_id, b.block_number());
                                            if (main_chain_hash == b.sha256()) {
                                                break;
                                            }
                                            previous_hash = b.previous_block_hash();
                                        }
                                    }
                                    // if found absent, stop to search; otherwise continue to find more difficult in cache
                                    if (found_absent)
                                        break;
                                }
                            }
                        }

                        // if sync no completed, request tail block too
                        if (!is_sync_completed(chain_id)) {
                            auto &tail_block = m_tail_blocks[chain_id];
                            if (!tail_block.empty()) {
                                demand_block_hash_set.insert(tail_block.previous_block_hash());
                            }
                        }
                    }

                    for (auto const& hash: demand_block_hash_set) {
                        common::block_request_entry blockRequestEntry(hash);
                        common::entry_task task(common::block_request_entry::data_type_id, blockRequestEntry.get_entry(),
                                                get_total_milliseconds());
                        add_entry_task_to_queue(chain_id, task);
                    }
                }

                auto &tasks = m_tasks[chain_id];
                auto size = tasks.size();
                if (!tasks.empty()) {
                    auto it = tasks.begin();
//                    if (it->m_timestamp <= now) {
                        if (it->m_peer.is_all_zeros()) {
                            if (now - m_visiting_time[chain_id].second < 60 * 1000) {
                                send_to(chain_id, m_visiting_time[chain_id].first, it->m_entry);
                                tasks.erase(it);
                            }
                        } else {
                            send_to(chain_id, it->m_peer, it->m_entry);
                            tasks.erase(it);
                        }
//                    }
                }
                log("-----------tasks size:%lu, after size:%lu", size, tasks.size());
            }

            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(std::bind(&blockchain::refresh_timeout, self(), _1));
        } catch (std::exception &e) {
            log("Exception init [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    void blockchain::refresh_vote_timeout(const error_code &e) {
        if (e || m_stop) return;

        try {
            // refresh all chain votes
            for (auto const& chain_id: m_chains) {
                refresh_vote(chain_id);
            }

            m_vote_timer.expires_after(seconds(DEFAULT_BLOCK_TIME));
            m_vote_timer.async_wait(std::bind(&blockchain::refresh_vote_timeout, self(), _1));
        } catch (std::exception &e) {
            log("Exception vote [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    void blockchain::refresh_tx_timeout(const error_code &e) {
        if (e || m_stop) return;

        try {
            // refresh all chain votes
            for (auto const& chain_id: m_chains) {
                auto tx = m_tx_pools[chain_id].get_best_transaction();
                if (!tx.empty()) {
                    common::transaction_entry txEntry(tx);
                    common::entry_task task(common::transaction_entry::data_type_id, txEntry.get_entry(), get_total_milliseconds());
                    add_entry_task_to_queue(chain_id, task);
                }
            }

            m_exchange_tx_timer.expires_after(seconds(EXCHANGE_TX_TIME));
            m_exchange_tx_timer.async_wait(std::bind(&blockchain::refresh_tx_timeout, self(), _1));
        } catch (std::exception &e) {
            log("Exception exchange tx [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    void blockchain::add_entry_task_to_queue(const aux::bytes &chain_id, const common::entry_task &task) {
        if (m_tasks[chain_id].size() > blockchain_max_task_size) {
            m_tasks[chain_id].erase(m_tasks[chain_id].begin());
        }

        m_tasks[chain_id].insert(task);
    }

//    void blockchain::try_to_refresh_unchoked_peers(const aux::bytes &chain_id) {
//        std::int64_t now = get_total_milliseconds() / 1000; // second
//        // check if has been updated during this 5 min
//        if (now / DEFAULT_BLOCK_TIME != m_update_peer_time[chain_id]) {
//            auto peers = select_unchoked_peers(chain_id);
//            m_unchoked_peers[chain_id] = peers;
//
//            m_update_peer_time[chain_id] = now / DEFAULT_BLOCK_TIME;
//
//            m_unchoked_peer_signal[chain_id].clear();
//        }
//    }

    aux::bytes blockchain::select_chain_randomly() {
        aux::bytes chain_id;

        if (!m_chains.empty())
        {
            // 产生随机数
            srand(get_total_milliseconds());
            auto index = rand() % m_chains.size();
            chain_id = m_chains[index];
        }

        return chain_id;
    }

    dht::public_key blockchain::select_peer_randomly(const aux::bytes &chain_id) {
//        dht::public_key peer{};
//        auto& chain_peers = m_chain_peers[chain_id];
//        std::vector<dht::public_key> peers(chain_peers.begin(), chain_peers.end());
//
//        if (!peers.empty())
//        {
//            // 产生随机数
//            srand(get_current_time());
//            auto index = rand() % peers.size();
//            peer = peers[index];
//        }
//
//        return peer;
        return m_repository->get_peer_randomly(chain_id);
    }

//    dht::public_key blockchain::select_unchoked_peer_randomly(const aux::bytes &chain_id) {
//        dht::public_key peer{};
//        auto& unchoked_peers = m_unchoked_peers[chain_id];
//        std::vector<dht::public_key> peers(unchoked_peers.begin(), unchoked_peers.end());
//
//        if (!peers.empty())
//        {
//            // 产生随机数
//            srand(get_total_milliseconds());
//            auto index = rand() % peers.size();
//            peer = peers[index];
//        }
//
//        return peer;
//    }

    std::set<dht::public_key> blockchain::select_unchoked_peers(const aux::bytes &chain_id) {
        std::set<dht::public_key> peers;
        auto chain_peers = m_repository->get_all_peers(chain_id);

        dht::public_key *pk = m_ses.pubkey();
        // insert me into peer set and make sure that I am in the set
        chain_peers.insert(*pk);

        if (chain_peers.size() > 1) {
            std::map<sha256_hash, dht::public_key> hash_peer_map;
            std::set<sha256_hash> hashes;
            // second
            std::int64_t now = get_total_milliseconds() / (DEFAULT_BLOCK_TIME * 1000);
            for (auto const& peer: chain_peers) {
                // connect public key with time
                std::string spk(peer.bytes.begin(), peer.bytes.end());
                std::stringstream data;
                data << spk << now;
                // calc hash
                sha256_hash hash = dht::item_target_id(data.str());

                hashes.insert(hash);
                hash_peer_map[hash] = peer;
            }

            // calc myself hash to look for neighbors
            std::string spk(pk->bytes.begin(), pk->bytes.end());
            std::stringstream data;
            data << spk << now;
            sha256_hash my_hash = dht::item_target_id(data.str());

            // look for two neighbors on the left and right
            auto r_iterator = hashes.find(my_hash);
            auto l_iterator = r_iterator;
//            for (auto i = 0; i < 2; i++) {
                // get peers adjacent to the first location
                r_iterator++;
                if (r_iterator == hashes.end()) {
                    r_iterator = hashes.begin();
                }
                log("INFO chain[%s] right unchoked peer[%s]",
                    aux::toHex(chain_id).c_str(), aux::toHex(hash_peer_map[*r_iterator].bytes).c_str());
                peers.insert(hash_peer_map[*r_iterator]);

                if (l_iterator == hashes.begin()) {
                    l_iterator = hashes.end();
                }
                l_iterator--;
                log("INFO chain[%s] left unchoked peer[%s]",
                    aux::toHex(chain_id).c_str(), aux::toHex(hash_peer_map[*l_iterator].bytes).c_str());
                peers.insert(hash_peer_map[*l_iterator]);
//            }
            // get peers adjacent to the third location
            r_iterator++;
            if (r_iterator == hashes.end()) {
                r_iterator = hashes.begin();
            }
            r_iterator++;
            if (r_iterator == hashes.end()) {
                r_iterator = hashes.begin();
            }
            log("INFO chain[%s] right third unchoked peer[%s]",
                aux::toHex(chain_id).c_str(), aux::toHex(hash_peer_map[*r_iterator].bytes).c_str());
            peers.insert(hash_peer_map[*r_iterator]);

            if (l_iterator == hashes.begin()) {
                l_iterator = hashes.end();
            }
            l_iterator--;
            if (l_iterator == hashes.begin()) {
                l_iterator = hashes.end();
            }
            l_iterator--;
            log("INFO chain[%s] left third unchoked peer[%s]",
                aux::toHex(chain_id).c_str(), aux::toHex(hash_peer_map[*l_iterator].bytes).c_str());
            peers.insert(hash_peer_map[*l_iterator]);

//            auto r_iterator = chain_peers.find(*pk);
//            auto l_iterator = r_iterator;
//            std::int64_t now = get_current_time() / 1000;
//            auto offset = (now / DEFAULT_BLOCK_TIME) % chain_peers.size();
//            for (auto i = 0; i < offset; i++) {
//                r_iterator++;
//                if (r_iterator == chain_peers.end()) {
//                    r_iterator = chain_peers.begin();
//                }
//
//                if (l_iterator == chain_peers.begin()) {
//                    l_iterator = chain_peers.end();
//                }
//                l_iterator--;
//            }
//
//            peers.insert(*r_iterator);
//            peers.insert(*l_iterator);
//            r_iterator++;
//            if (r_iterator == chain_peers.end()) {
//                r_iterator = chain_peers.begin();
//            }
//
//            if (l_iterator == chain_peers.begin()) {
//                l_iterator = chain_peers.end();
//            }
//            l_iterator--;
//
//            peers.insert(*r_iterator);
//            peers.insert(*l_iterator);
        }

        return peers;
    }

    block blockchain::try_to_mine_block(const aux::bytes &chain_id) {
        dht::secret_key *sk = m_ses.serkey();
        dht::public_key *pk = m_ses.pubkey();

        block b;
        auto &head_block = m_head_blocks[chain_id];
        if (!head_block.empty()) {
            if (head_block.block_number() < 0) {
                log("INFO chain[%s] Negative and genesis block cannot be mined", aux::toHex(chain_id).c_str());
                return b;
            }

            block ancestor;
            auto previous_hash = head_block.previous_block_hash();
            if (head_block.block_number() > 3) {
                int i = 3;
                while (i > 0) {
                    ancestor = m_repository->get_block_by_hash(previous_hash);
                    if (ancestor.empty()) {
                        log("INFO chain[%s] Cannot find block[%s] in db",
                            aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                        return b;
                    }
                    previous_hash = ancestor.previous_block_hash();

                    i--;
                }
            }

            auto base_target = consensus::calculate_required_base_target(head_block, ancestor);
            std::int64_t power = m_repository->get_effective_power(chain_id, *pk);
            log("INFO: chain id[%s] public key[%s] power[%ld]", aux::toHex(chain_id).c_str(), aux::toHex(pk->bytes).c_str(), power);
            if (power <= 0) {
                return b;
            }
            auto genSig = consensus::calculate_generation_signature(head_block.generation_signature(), *pk);
            auto hit = consensus::calculate_random_hit(genSig);
            auto interval = static_cast<std::int64_t>(consensus::calculate_mining_time_interval(hit, base_target, power));
            log("INFO: chain id[%s] generation signature[%s], base target[%lu], hit[%lu]",
                aux::toHex(chain_id).c_str(), aux::toHex(genSig.to_string()).c_str(), base_target, hit);

            std::int64_t now = get_total_milliseconds() / 1000; // second
            if (now >= head_block.timestamp() + interval) {
//                log("1-----------------------------------hit:%lu, base target:%lu, interval:%lu", hit, base_target, interval);
                transaction tx;
                if (is_sync_completed(chain_id)) {
                    tx = m_tx_pools[chain_id].get_best_transaction();
                }

                auto cumulative_difficulty = consensus::calculate_cumulative_difficulty(head_block.cumulative_difficulty(), base_target);

                std::map<dht::public_key, std::int64_t> peers_balance;
                std::map<dht::public_key, std::int64_t> peers_nonce;

                // get miner state
                auto miner_account = m_repository->get_account(chain_id, *pk);
                peers_balance[*pk] = miner_account.balance();
                peers_nonce[*pk] = miner_account.nonce();

                if (!tx.empty()) {
                    // get state
                    auto sender_account = m_repository->get_account(chain_id, tx.sender());
                    peers_balance[tx.sender()] = sender_account.balance();
                    peers_nonce[tx.sender()] = sender_account.nonce();
                    auto receiver_account = m_repository->get_account(chain_id, tx.receiver());
                    peers_balance[tx.receiver()] = receiver_account.balance();
                    peers_nonce[tx.receiver()] = receiver_account.nonce();

                    // adjust state
                    // miner earns fee
                    peers_balance[*pk] += tx.fee();
                    // sender balance - cost(fee + amount)
                    peers_balance[tx.sender()] -= tx.cost();
                    // sender nonce+1
                    peers_nonce[tx.sender()] += 1;
                    // receiver balance + amount
                    peers_balance[tx.receiver()] += tx.amount();
                }
                b = block(chain_id, block_version::block_version1, (head_block.timestamp() + interval),
                          head_block.block_number() + 1, head_block.sha256(), base_target,
                          cumulative_difficulty, genSig, tx, *pk, peers_balance[*pk], peers_nonce[*pk],
                          peers_balance[tx.sender()], peers_nonce[tx.sender()],
                          peers_balance[tx.receiver()], peers_nonce[tx.receiver()]);
                b.sign(*pk, *sk);
            }
        }

        return b;
    }

    RESULT blockchain::verify_block(const aux::bytes &chain_id, block &b, block &previous_block, repository *repo) {
        if (b.empty()) {
            log("INFO chain[%s] block is empty", aux::toHex(chain_id).c_str());
            return FAIL;
        }

        if (previous_block.block_number() + 1 != b.block_number()) {
            log("INFO chain[%s] block number error.", aux::toHex(chain_id).c_str());
            return FAIL;
        }

        if (b.block_number() <= 0) {
            log("INFO chain[%s] Negative and genesis block is always true", aux::toHex(chain_id).c_str());
            return SUCCESS;
        }

        if (b.timestamp() <= previous_block.timestamp()) {
            log("INFO chain[%s] block timestamp error.", aux::toHex(chain_id).c_str());
            return FAIL;
        }

        if (!b.verify_signature()) {
            log("INFO chain[%s] block[%s] has bad signature",
                aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
            return FAIL;
        }

        block ancestor;
        auto previous_hash = previous_block.previous_block_hash();
        if (previous_block.block_number() > 3) {
            int i = 3;
            while (i > 0) {
                ancestor = repo->get_block_by_hash(previous_hash);
                if (ancestor.empty()) {
                    log("INFO chain[%s] Cannot find block[%s] in db",
                        aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                    return MISSING;
                }
                previous_hash = ancestor.previous_block_hash();

                i--;
            }
        }

        auto base_target = consensus::calculate_required_base_target(previous_block, ancestor);
        std::int64_t power = repo->get_effective_power(chain_id, b.miner());
        if (power <= 0) {
            log("INFO chain[%s] Cannot get account[%s] state in db",
                aux::toHex(chain_id).c_str(), aux::toHex(b.miner().bytes).c_str());
            return MISSING;
        }

        auto genSig = consensus::calculate_generation_signature(previous_block.generation_signature(), b.miner());
        auto hit = consensus::calculate_random_hit(genSig);
        auto interval = b.timestamp() - previous_block.timestamp();
//        log("++++++++++++++++++++++++++++++++++++++++hit:%lu, base target:%ld, interval:%ld", hit, base_target, interval);
        if (!consensus::verify_hit(hit, base_target, power, interval)) {
            log("INFO chain[%s] block[%s] verify hit fail",
                aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
            return FAIL;
        }

        auto miner_account = repo->get_account(chain_id, b.miner());
        std::int64_t miner_balance = miner_account.balance();
        std::int64_t miner_nonce = miner_account.nonce();
        std::int64_t sender_balance = 0;
        std::int64_t sender_nonce = 0;
        std::int64_t receiver_balance = 0;
        std::int64_t receiver_nonce = 0;
        auto const& tx = b.tx();
        if (!tx.empty()) {
            miner_balance += tx.fee();

            auto sender_account = repo->get_account(chain_id, tx.sender());
            sender_balance = sender_account.balance() - tx.cost();
            sender_nonce = sender_account.nonce() + 1;

            auto receiver_account = repo->get_account(chain_id, tx.receiver());
            receiver_balance = receiver_account.balance() + tx.amount();
            receiver_nonce = receiver_account.nonce();
        }
        if (miner_balance != b.miner_balance() || miner_nonce != b.miner_nonce() ||
        sender_balance != b.sender_balance() || sender_nonce != b.sender_nonce() ||
        receiver_balance != b.receiver_balance() || receiver_nonce != b.receiver_nonce()) {
            log("INFO chain[%s] block[%s] state error!",
                aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
            return FAIL;
        }

        return SUCCESS;
    }

    void blockchain::try_to_update_consensus_point_block(const aux::bytes &chain_id) {
//        auto &consensus_point_block = m_consensus_point_blocks[chain_id];
//        auto &best_vote = m_best_votes[chain_id];
//        auto &blocks = m_blocks[chain_id];
//        if (!best_vote.empty()) {
//            get_block_from_cache_or_db(chain_id, best_vote.block_hash());
//            auto it = blocks.find(best_vote.block_hash());
//            if (it != blocks.end()) {
//                m_consensus_point_blocks[chain_id] = it->second;
//                blocks.erase(it);
//            }
//        }
    }

    void blockchain::try_to_update_voting_point_block(const aux::bytes &chain_id) {
        auto& head_block = m_head_blocks[chain_id];
        auto& tail_block = m_tail_blocks[chain_id];

        // calc voting point block number
        auto block_number = (head_block.block_number() / 100 - 1) * 100;
        // make sure that consensus block number>=0
        if (block_number < 0) {
            block_number = 0;
        }

        auto& voting_point_block = m_voting_point_blocks[chain_id];
        if (voting_point_block.empty() || voting_point_block.block_number() != block_number) {
            auto blk = m_repository->get_main_chain_block_by_number(chain_id, block_number);
            if (!blk.empty()) {
                log("INFO chain[%s] Voting point block[%s]", aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                m_voting_point_blocks[chain_id] = blk;
            } else {
                log("INFO chain[%s] Cannot find voting point block", aux::toHex(chain_id).c_str());
            }
        }
    }

    void blockchain::try_to_update_visiting_peer(const aux::bytes &chain_id, const dht::public_key &peer) {
        auto now = get_total_milliseconds();
        if (peer != m_visiting_time[chain_id].first) {
            if (m_visiting_history[chain_id].find(peer) != m_visiting_history[chain_id].end()) {
                m_visiting_history[chain_id].clear();
                m_visiting_time[chain_id] = std::make_pair(peer, now);
            }
        } else {
            if (now - m_visiting_time[chain_id].second > 60 * 1000) {
                m_visiting_history[chain_id].clear();
                m_visiting_time[chain_id] = std::make_pair(peer, now);
            }
        }
    }

    RESULT blockchain::process_block(const aux::bytes &chain_id, block &b) {
        if (b.empty())
            return FAIL;
//        log("=================== block length:%lu, tx length:%lu, block:%s",
//            b.get_encode().length(), b.tx().get_encode().length(), b.to_string().c_str());

        auto &head_block  = m_head_blocks[chain_id];
        if (head_block.empty()) {
            auto track = m_repository->start_tracking();

            if (!track->connect_head_block(b)) {
                log("INFO chain[%s] connect head block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
                return FAIL;
            }
            if (!track->set_head_block_hash(chain_id, b.sha256())) {
                log("INFO chain[%s] set head block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
                return FAIL;
            }
            if (!track->set_tail_block_hash(chain_id, b.sha256())) {
                log("INFO chain[%s] set tail block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
                return FAIL;
            }
            if (!track->set_consensus_point_block_hash(chain_id, b.sha256())) {
                log("INFO chain[%s] set consensus point block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
                return FAIL;
            }

            if (!track->commit()) {
                log("INFO chain[%s] commit fail", aux::toHex(chain_id).c_str());
                return FAIL;
            }
            if (!m_repository->flush(chain_id)) {
                log("INFO chain[%s] flush fail", aux::toHex(chain_id).c_str());
                return FAIL;
            }

            // chain changed, re-check tx pool
            m_tx_pools[chain_id].recheck_account_txs(b.get_block_peers());

            m_head_blocks[chain_id] = b;
            m_tail_blocks[chain_id] = b;
            m_consensus_point_blocks[chain_id] = b;

            m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(b);
            m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(b);
            m_ses.alerts().emplace_alert<blockchain_new_consensus_point_block_alert>(b);
        } else {
            if (b.previous_block_hash() == head_block.sha256()) {
                std::set<dht::public_key> peers = b.get_block_peers();

                auto track = m_repository->start_tracking();

                // no need to verify block if not sync completed
                if (!is_sync_completed(chain_id)) {
                    auto result = verify_block(chain_id, b, head_block, track.get());
                    if (result != SUCCESS)
                        return result;
                }

                if (!track->connect_head_block(b)) {
                    log("INFO chain[%s] connect head block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
                    return FAIL;
                }

                if (!track->set_head_block_hash(chain_id, b.sha256())) {
                    log("INFO chain[%s] set head block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
                    return FAIL;
                }

                auto &tail_block = m_tail_blocks[chain_id];
                // seek tail block
                while (b.block_number() - tail_block.block_number() > EFFECTIVE_BLOCK_NUMBER) {

                    if (!track->expire_block(tail_block)) {
                        log("INFO chain[%s] expire block[%s] fail",
                            aux::toHex(chain_id).c_str(), aux::toHex(tail_block.sha256().to_string()).c_str());
                        return FAIL;
                    }

                    // chain changed, re-check block peer in pool
                    auto tail_peers = tail_block.get_block_peers();
                    peers.insert(tail_peers.begin(), tail_peers.end());

                    // get previous main chain block to be expired one by one
                    tail_block = track->get_main_chain_block_by_number(chain_id, tail_block.block_number() + 1);

                    // set tail
                    track->set_tail_block_hash(chain_id, tail_block.sha256());
                }

                if (!track->commit()) {
                    log("INFO chain[%s] commit fail", aux::toHex(chain_id).c_str());
                    return FAIL;
                }
                m_repository->flush(chain_id);

                m_head_blocks[chain_id] = b;
                if (!tail_block.empty()) {
                    m_tail_blocks[chain_id] = tail_block;
                    m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(tail_block);
                }

                // chain changed, re-check tx pool
                m_tx_pools[chain_id].recheck_account_txs(peers);

                m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(b);
            }

            if (m_head_blocks[chain_id].block_number() - m_tail_blocks[chain_id].block_number() < EFFECTIVE_BLOCK_NUMBER &&
                b.sha256() == m_tail_blocks[chain_id].previous_block_hash()) {
                auto track = m_repository->start_tracking();

                if (!track->connect_tail_block(b)) {
                    log("INFO chain[%s] connect tail block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
                    return FAIL;
                }
                if (!track->set_tail_block_hash(chain_id, b.sha256())) {
                    log("INFO chain[%s] set tail block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
                    return FAIL;
                }

                if (!track->commit()) {
                    log("INFO chain[%s] commit fail", aux::toHex(chain_id).c_str());
                    return FAIL;
                }
                m_repository->flush(chain_id);

                m_tail_blocks[chain_id] = b;

                // chain changed, re-check tx pool
                m_tx_pools[chain_id].recheck_account_txs(b.get_block_peers());

                m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(b);
            }
        }

        // re-locate consensus point block
        try_to_update_voting_point_block(chain_id);

        return SUCCESS;
    }

    bool blockchain::is_empty_chain(const aux::bytes &chain_id) {
        // check if head block empty
        auto &head_block = m_head_blocks[chain_id];

        return head_block.empty();
    }

    bool blockchain::is_block_immutable_certainly(const aux::bytes &chain_id, const block &blk) {
        if (blk.block_number() <= 0) {
            return true;
        }

        auto &consensus_point_block = m_consensus_point_blocks[chain_id];
        if (consensus_point_block.sha256() == blk.sha256())
            return true;

        return false;
    }

    bool blockchain::is_voting_point_immutable(const aux::bytes &chain_id) {
        // check if best vote and voting point block match, true if matched, false otherwise
        auto &best_vote = m_best_votes[chain_id];
        auto &voting_point_block = m_voting_point_blocks[chain_id];
        if (voting_point_block.empty())
            return false;
        if (!best_vote.empty() && best_vote.block_hash() != voting_point_block.sha256())
            return false;

        return true;
    }

    bool blockchain::is_sync_completed(const aux::bytes &chain_id) {
        auto &head_block = m_head_blocks[chain_id];
        auto &tail_block = m_tail_blocks[chain_id];

        if (head_block.empty() || tail_block.empty())
            return false;

        // if block number<=0, previous hash is all zeros, sync is completed
        if (tail_block.block_number() <= 0 && tail_block.previous_block_hash().is_all_zeros())
            return true;

        // if chain length = effective block number, sync is completed
        if (head_block.block_number() - tail_block.block_number() >= EFFECTIVE_BLOCK_NUMBER)
            return true;

        return false;
    }

    bool blockchain::is_block_in_cache_or_db(const aux::bytes &chain_id, const sha256_hash &hash) {
        auto &block_map = m_blocks[chain_id];
        auto it = block_map.find(hash);
        if (it != block_map.end() && !it->second.empty()) {
            return true;
        }

        return m_repository->is_block_exist(hash);
    }

    block blockchain::get_block_from_cache_or_db(const aux::bytes &chain_id, const sha256_hash &hash) {
        auto &block_map = m_blocks[chain_id];
        auto it = block_map.find(hash);
        if (it != block_map.end() && !it->second.empty()) {
            return it->second;
        }

        return m_repository->get_block_by_hash(hash);
    }

    void blockchain::remove_all_same_chain_blocks_from_cache(const block &blk) {
        auto& block_map = m_blocks[blk.chain_id()];
        auto previous_hash = blk.previous_block_hash();
        auto it = block_map.find(previous_hash);
        while (it != block_map.end()) {
            previous_hash = it->second.previous_block_hash();
            block_map.erase(it);
            it = block_map.find(previous_hash);
        }

        previous_hash = blk.sha256();
        for (it = block_map.begin(); it != block_map.end();) {
            if (it->second.previous_block_hash() == previous_hash) {
                previous_hash = it->second.sha256();
                block_map.erase(it);

                it = block_map.begin();
                continue;
            }

            ++it;
        }

        block_map.erase(blk.sha256());
    }

    void blockchain::remove_all_ancestor_blocks_from_cache(const block &blk) {
        auto& block_map = m_blocks[blk.chain_id()];
        auto previous_hash = blk.previous_block_hash();
        auto it = block_map.find(previous_hash);
        while (it != block_map.end()) {
            previous_hash = it->second.previous_block_hash();
            block_map.erase(it);
            it = block_map.find(previous_hash);
        }

        block_map.erase(blk.sha256());
    }

    void blockchain::try_to_slim_down_cache(const aux::bytes &chain_id) {
        // todo
    }

    RESULT blockchain::try_to_rebranch(const aux::bytes &chain_id, const block &target) {
        log("INFO chain[%s] try to rebranch to block[%s]",
            aux::toHex(chain_id).c_str(), target.to_string().c_str());

        auto &head_block = m_head_blocks[chain_id];
        auto &block_maps = m_blocks[chain_id];

        // re-branch, try to find out fork point block
        std::vector<block> rollback_blocks;
        std::vector<block> connect_blocks;

        // todo:: rollback until to tail?
        // align main chain and branch block number
        block main_chain_block = head_block;
        while (main_chain_block.block_number() > target.block_number()) {
            // check if try to rollback voting point block
            if (is_block_immutable_certainly(chain_id, main_chain_block)) {
                log("INFO chain[%s] block[%s] is immutable.",
                    aux::toHex(chain_id).c_str(), main_chain_block.to_string().c_str());
//                m_blocks[chain_id].clear();
                return FAIL;
            }

            rollback_blocks.push_back(main_chain_block);

            auto previous_hash = main_chain_block.previous_block_hash();
            main_chain_block = m_repository->get_block_by_hash(previous_hash);
            if (main_chain_block.empty()) {
                log("INFO chain[%s] Cannot find block[%s] in db",
                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                return MISSING;
            }
        }

        block reference_block = target;
        while (head_block.block_number() < reference_block.block_number()) {
            connect_blocks.push_back(reference_block);

            // find branch block from cache and db
            auto previous_hash = reference_block.previous_block_hash();
            reference_block = get_block_from_cache_or_db(chain_id, previous_hash);

            if (reference_block.empty()) {
                log("INFO chain[%s] Cannot find block[%s]",
                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                return MISSING;
            }
        }

//        log("----1. main chain block:%s, reference block:%s", main_chain_block.to_string().c_str(), reference_block.to_string().c_str());
        // find out common ancestor
        while (main_chain_block.sha256() != reference_block.sha256()) {
            if (is_block_immutable_certainly(chain_id, main_chain_block)) {
                log("INFO chain[%s] block[%s] is immutable",
                    aux::toHex(chain_id).c_str(), main_chain_block.to_string().c_str());
//                m_blocks[chain_id].clear();
                return FAIL;
            }

            rollback_blocks.push_back(main_chain_block);

            main_chain_block = m_repository->get_block_by_hash(main_chain_block.previous_block_hash());
            if (main_chain_block.empty())
                return MISSING;

            connect_blocks.push_back(reference_block);

            // find branch block from cache and db
            auto &previous_hash = reference_block.previous_block_hash();
            reference_block = get_block_from_cache_or_db(chain_id, previous_hash);

            if (reference_block.empty()) {
                log("INFO chain[%s] Cannot find block[%s]",
                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                return MISSING;
            }
        }
//        log("----2. main chain block:%s, reference block:%s", main_chain_block.to_string().c_str(), reference_block.to_string().c_str());

        // reference block is fork point block
        connect_blocks.push_back(reference_block);

        std::set<dht::public_key> peers;

        auto track = m_repository->start_tracking();

        auto &tail_block = m_tail_blocks[chain_id];
        bool tail_missing = false;
        // rollback blocks
        for (auto &blk: rollback_blocks) {
            if (!track->rollback_block(blk)) {
                log("INFO chain[%s] rollback block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                return FAIL;
            }

            if (!tail_missing) {
                // in order to maintain the effective length of the chain,
                // re-connect old tail block when rollback a head block
                // if tail missing, block verification will be ignored
                auto previous_block = track->get_block_by_hash(tail_block.previous_block_hash());
                if (!previous_block.empty()) {
                    tail_block = previous_block;
                    if (!track->connect_tail_block(previous_block)) {
                        log("INFO chain[%s] connect tail block[%s] fail",
                            aux::toHex(chain_id).c_str(), aux::toHex(previous_block.sha256().to_string()).c_str());
                        return FAIL;
                    }

                    // chain changed, re-check tx pool
                    auto tail_peers = tail_block.get_block_peers();
                    peers.insert(tail_peers.begin(), tail_peers.end());
                } else {
                    tail_missing = true;
                }
            }

            // chain changed, re-check tx pool
            auto block_peers = blk.get_block_peers();
            peers.insert(block_peers.begin(), block_peers.end());
        }

        // connect new branch blocks
        for (auto i = connect_blocks.size(); i > 1; i--) {
            auto &blk = connect_blocks[i - 2];
            auto &previous_block = connect_blocks[i - 1];

            if (!tail_missing) {
                auto result = verify_block(chain_id, blk, previous_block, track.get());
                if (result != SUCCESS)
                    return result;
            }

            if (!track->connect_head_block(blk)) {
                log("INFO chain[%s] connect head block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                return FAIL;
            }

            // seek tail block
            while (blk.block_number() - tail_block.block_number() > EFFECTIVE_BLOCK_NUMBER) {
                if (!track->expire_block(tail_block)) {
                    log("INFO chain[%s] expire block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(tail_block.sha256().to_string()).c_str());
                    return FAIL;
                }
                // get previous main chain block to be expired one by one
                tail_block = track->get_main_chain_block_by_number(chain_id, tail_block.block_number() + 1);

                // chain changed, re-check tx pool
                auto tail_peers = tail_block.get_block_peers();
                peers.insert(tail_peers.begin(), tail_peers.end());
            }

            auto block_peers = blk.get_block_peers();
            peers.insert(block_peers.begin(), block_peers.end());
        }

        if (!track->set_tail_block_hash(chain_id, tail_block.sha256())) {
            log("INFO chain[%s] set tail block[%s] fail",
                aux::toHex(chain_id).c_str(), aux::toHex(tail_block.sha256().to_string()).c_str());
            return FAIL;
        }
        if (!track->set_head_block_hash(chain_id, target.sha256())) {
            log("INFO chain[%s] set head block[%s] fail",
                aux::toHex(chain_id).c_str(), aux::toHex(target.sha256().to_string()).c_str());
            return FAIL;
        }

        if (!track->commit()) {
            log("INFO chain[%s] commit fail", aux::toHex(chain_id).c_str());
            return FAIL;
        }
        m_repository->flush(chain_id);

        // after all above is success
        m_head_blocks[chain_id] = target;
        m_tail_blocks[chain_id] = tail_block;

        for (auto &blk: rollback_blocks) {
            // send back rollback block tx to pool
            m_tx_pools[chain_id].send_back_block_tx_to_pool(blk);
            // notify rollback block
            m_ses.alerts().emplace_alert<blockchain_rollback_block_alert>(blk);
        }
//        for (auto i = connect_blocks.size(); i > 1; i--) {
//            auto &blk = connect_blocks[i - 2];
//            auto &previous_block = connect_blocks[i - 1];
//        }
        m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(target);
        m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(tail_block);
        m_ses.alerts().emplace_alert<blockchain_fork_point_block_alert>(reference_block);

        // chain changed, re-check tx pool
        m_tx_pools[chain_id].recheck_account_txs(peers);

        // re-locate consensus point block
        try_to_update_voting_point_block(chain_id);

        return SUCCESS;
    }

    void blockchain::refresh_vote(const aux::bytes &chain_id) {
        std::set<vote> votes;
        auto & peer_votes = m_votes[chain_id];
        // count votes
        for (auto const& v: peer_votes) {
            auto it = votes.find(v.second);
            if (it != votes.end()) {
                auto cv = *it;
                cv.vote_up();
                votes.insert(cv);
            } else {
                votes.insert(v.second);
            }
        }

        vote best_vote;
        if (!votes.empty() || is_sync_completed(chain_id)) {
            // if no voting result or best vote count is 1, use local voting point block
            if (votes.empty() || votes.rbegin()->count() == 1) {
                auto &voting_point_block = m_voting_point_blocks[chain_id];
                best_vote = vote(voting_point_block.sha256(), voting_point_block.block_number());
            } else {
                // use the best vote
                best_vote = *votes.rbegin();
            }

            m_best_votes[chain_id] = best_vote;
            log("INFO chain[%s] best vote[%s]",
                aux::toHex(chain_id).c_str(), best_vote.to_string().c_str());

            // select top three votes
            std::vector<vote> top_three_votes;
            int i = 0;
            for (auto it = votes.rbegin(); it != votes.rend(); ++it) {
                if (i >= 3)
                    break;

                log("INFO chain[%s] top three vote[%s]",
                    aux::toHex(chain_id).c_str(), it->to_string().c_str());

                top_three_votes.push_back(*it);
                i++;
            }

            if (!top_three_votes.empty()) {
                m_ses.alerts().emplace_alert<blockchain_top_three_votes_alert>(chain_id, top_three_votes);
            }
        }

        // clear history votes for next round
        m_votes[chain_id].clear();
    }

    namespace {

//        void on_dht_put_immutable_item(aux::alert_manager& alerts, sha256_hash target, int num)
//        {
//        }

        void put_mutable_data(entry& e, std::array<char, 64>& sig
                , std::int64_t& ts
                , std::string const& salt
                , std::array<char, 32> const& pk
                , std::array<char, 64> const& sk
                , entry const& data)
        {
            using lt::dht::sign_mutable_item;

            e = data;
            std::vector<char> buf;
            // bencode要发布的mutable data
            bencode(std::back_inserter(buf), e);
            dht::signature sign;
            // get unix timestamp
            ts = libTAU::aux::utcTime();
            // 对编码完成之后的数据(data + salt + ts)进行签名
            sign = sign_mutable_item(buf, salt, dht::timestamp(ts)
                    , dht::public_key(pk.data())
                    , dht::secret_key(sk.data()));
            sig = sign.bytes;
        }

        void on_dht_put_mutable_item(aux::alert_manager& alerts, dht::item const& i, int num)
        {
        }

        void put_mutable_callback(dht::item& i
                , std::function<void(entry&, std::array<char, 64>&
                , std::int64_t&, std::string const&)> cb)
        {
            entry value = i.value();
            dht::signature sig = i.sig();
            dht::public_key pk = i.pk();
            dht::timestamp ts = i.ts();
            std::string salt = i.salt();
            // 提取item信息，交给cb处理
            cb(value, sig.bytes, ts.value, salt);
            // 使用新生成的item信息替换旧的item
            i.assign(std::move(value), salt, ts, pk, sig);
        }
    } // anonymous namespace

    namespace {
        /**
         * 选用编辑代价最小的，并返回该操作代表的操作数
         * @param swap 替换的代价
         * @param insert 插入的代价
         * @param del 删除的代价
         * @return 0:替换，1：插入，2：删除
         */
        size_t optCode(size_t swap, size_t insert, size_t del) {
            // 如果替换编辑距离最少，则返回0标识，
            // 即使三种操作距离一样，优先选择替换操作
            if (swap <= insert && swap <= del) {
                return 0;
            }

            // 如果插入操作编辑最少，返回1标识，如果插入和删除距离一样，优先选择插入
            if (insert < swap && insert <= del) {
                return 1;
            }

            // 如果删除操作编辑最少，返回2标识
            return 2;
        }
    }

    void blockchain::find_best_solution(std::vector<transaction> &txs, const aux::bytes &hash_prefix_array,
                                        std::vector<transaction> &missing_txs) {
        // 如果对方没有信息，则本地消息全为缺失消息
        if (hash_prefix_array.empty()) {
            log("INFO: Hash prefix array is empty");
            missing_txs.insert(missing_txs.end(), txs.begin(), txs.end());
            return;
        }

        if (!txs.empty()) {
            auto size = txs.size();
            // 对方数组为source
            const aux::bytes& source = hash_prefix_array;
            // 本地消息数组为target
            aux::bytes target;
            for (auto const&tx: txs) {
                target.push_back(tx.sha256()[0]);
            }

            const size_t sourceLength = source.size();
            const size_t targetLength = size;

            log("INFO: tx array: source array[%s], target array[%s]", aux::toHex(source).c_str(), aux::toHex(target).c_str());
            // 如果source和target一样，则直接跳过Levenshtein数组匹配计算
            if (source == target) {
//                for (auto const&tx: txs) {
//                        log("INFO: Confirm message hash[%s]", aux::toHex(msg.sha256().to_string()).c_str());
//                    confirmation_roots.push_back(tx.sha256());
//                }
                return;
            }

            // 状态转移矩阵
            size_t dist[sourceLength + 1][targetLength + 1];
            // 操作矩阵
            size_t operations[sourceLength + 1][targetLength + 1];

            // 初始化，[i, 0]转换到空，需要编辑的距离，也即删除的数量
            for (size_t i = 0; i < sourceLength + 1; i++) {
                dist[i][0] = i;
                if (i > 0) {
                    operations[i][0] = 2;
                }
            }

            // 初始化，空转换到[0, j]，需要编辑的距离，也即增加的数量
            for (size_t j = 0; j < targetLength + 1; j++) {
                dist[0][j] = j;
                if (j > 0) {
                    operations[0][j] = 1;
                }
            }

            // 开始填充状态转移矩阵，第0位为空，所以从1开始有数据，[i, j]为当前子串最小编辑操作
            for (size_t i = 1; i < sourceLength + 1; i++) {
                for (size_t j = 1; j < targetLength + 1; j++) {
                    // 第i个数据，实际的index需要i-1，替换的代价，相同无需替换，代价为0，不同代价为1
                    size_t cost = source[i - 1] == target[j - 1] ? 0 : 1;
                    // [i, j]在[i, j-1]的基础上，最小的编辑操作为增加1
                    size_t insert = dist[i][j - 1] + 1;
                    // [i, j]在[i-1, j]的基础上，最小的编辑操作为删除1
                    size_t del = dist[i - 1][j] + 1;
                    // [i, j]在[i-1, j-1]的基础上，最大的编辑操作为1次替换
                    size_t swap = dist[i - 1][j - 1] + cost;

                    // 在[i-1, j]， [i, j-1]， [i-1, j-1]三种转换到[i, j]的最小操作中，取最小值
                    dist[i][j] = std::min(std::min(insert, del), swap);

                    // 选择一种最少编辑的操作
                    operations[i][j] = optCode(swap, insert, del);
                }
            }

            // 回溯编辑路径，统计中间信息
            auto i = sourceLength;
            auto j = targetLength;
            while (0 != dist[i][j]) {
                if (0 == operations[i][j]) {
                    // 如果是替换操作，则将target对应的替换消息加入列表
                    if (source[i - 1] != target[j - 1]) {
                        missing_txs.push_back(txs[j - 1]);
                    }
                    i--;
                    j--;
                } else if (1 == operations[i][j]) {
                    // 如果是插入操作，则将target对应的插入消息加入列表
                    // 注意由于消息是按照时间戳从小到大排列，如果缺第一个，并且此时双方满载，则判定为被挤出去而产生的差异，并非真的缺少
                    if (1 != j || targetLength != blockchain_max_tx_list_size ||
                        sourceLength != blockchain_max_tx_list_size) {
                        missing_txs.push_back(txs[j - 1]);

                        // 如果是插入操作，则将邻近哈希前缀一样的消息也当作缺失的消息
                        auto k = j - 1;
                        while (k + 1 < targetLength && target[k] == target[k + 1]) {
                            missing_txs.push_back(txs[k + 1]);
                            k++;
                        }
                    }

                    j--;
                } else if (2 == operations[i][j]) {
                    // 如果是删除操作，可能是对方新消息，忽略
                    i--;
                }
            }

            // 找到距离为0可能仍然不够，可能有前缀相同的情况，这时dist[i][j]很多为0的情况，
            // 因此，需要把剩余的加入confirmation root集合即可
//            for(; j > 0; j--) {
//                    log("INFO: Confirm message hash[%s]", aux::toHex(messages[j - 1].sha256().to_string()).c_str());
//                confirmation_roots.push_back(txs[j - 1].sha256());
//            }

            // reverse missing messages
//                std::reverse(missing_messages.begin(), missing_messages.end());
        }
    }

    std::string blockchain::make_salt(const aux::bytes &chain_id) {
        auto offset = chain_id.size() > blockchain_salt_length ? blockchain_salt_length : chain_id.size();
        std::string salt(chain_id.begin(), chain_id.begin() + offset);
        if (salt.length() < blockchain_salt_length) {
            salt.append('\0', (blockchain_salt_length - salt.length()));
        }

        return salt;
    }

    void blockchain::send_to(const aux::bytes &chain_id, const dht::public_key &peer, const entry &data) {
        dht::public_key * pk = m_ses.pubkey();
        dht::secret_key * sk = m_ses.serkey();

        auto salt = make_salt(chain_id);

        log("INFO: Send to peer[%s], salt[%s], data[%s]", aux::toHex(peer.bytes).c_str(),
            aux::toHex(salt).c_str(), data.to_string().c_str());

        dht_put_mutable_item(pk->bytes, std::bind(&put_mutable_data, _1, _2, _3, _4
                , pk->bytes, sk->bytes, data), salt, peer);
    }

//    void blockchain::request_signal(const aux::bytes &chain_id, const dht::public_key &peer) {
//        // salt is x pubkey when request signal
//        auto salt = make_salt(chain_id);
//
//        log("INFO: Request signal from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
//            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
//        dht_get_mutable_item(chain_id, peer.bytes, salt, m_latest_item_timestamp[chain_id][peer]);
//    }

//    void blockchain::publish_signal(const aux::bytes &chain_id, const dht::public_key& peer,
//                                    const blockchain_signal &peer_signal) {
//        log("INFO: ----chain[%s] publish to peer[%s], signal[%s]", aux::toHex(chain_id).c_str(),
//            aux::toHex(peer.bytes).c_str(), peer_signal.to_string().c_str());
//        // current time(ms)
//        auto now = get_total_milliseconds();
//
//        // vote for voting point
//        auto &voting_point_block = m_voting_point_blocks[chain_id];
//        vote consensus_point_vote;
//        if (is_sync_completed(chain_id) && !voting_point_block.empty()) {
//            consensus_point_vote.setBlockHash(voting_point_block.sha256());
//            consensus_point_vote.setBlockNumber(voting_point_block.block_number());
//        }
//
//        // offer the head block
//        auto &head_block = m_head_blocks[chain_id];
//        immutable_data_info head_block_info;
//        if (!head_block.empty()) {
//            std::vector<dht::node_entry> entries;
//            m_ses.dht()->find_live_nodes(head_block.sha256(), entries);
//            if (entries.size() > blockchain_immutable_payload_put_node_size) {
//                entries.resize(blockchain_immutable_payload_put_node_size);
//            }
//            log("INFO: Put immutable head block target[%s], entries[%zu]",
//                aux::toHex(head_block.sha256().to_string()).c_str(), entries.size());
//            dht_put_immutable_item(head_block.get_entry(), entries, head_block.sha256());
//
//            head_block_info = immutable_data_info(head_block.sha256(), entries);
//        }
//
//        // offer the consensus point block
//        immutable_data_info voting_point_block_info;
//        if (!voting_point_block.empty()) {
//            std::vector<dht::node_entry> entries;
//            m_ses.dht()->find_live_nodes(voting_point_block.sha256(), entries);
//            if (entries.size() > blockchain_immutable_payload_put_node_size) {
//                entries.resize(blockchain_immutable_payload_put_node_size);
//            }
//            log("INFO: Put immutable voting point block target[%s], entries[%zu]",
//                aux::toHex(voting_point_block.sha256().to_string()).c_str(), entries.size());
//            dht_put_immutable_item(voting_point_block.get_entry(), entries, voting_point_block.sha256());
//
//            voting_point_block_info = immutable_data_info(voting_point_block.sha256(), entries);
//        }
//
//        std::set<immutable_data_info> block_set;
//        std::set<immutable_data_info> tx_set;
//
//        if (!peer_signal.empty()) {
//            // select a signal from an unchoked peer randomly
////        dht::public_key peer;
////        auto &peer_signals = m_unchoked_peer_signal[chain_id];
////        if (!peer_signals.empty()) {
////            // 产生随机数
////            srand(now);
////            auto index = rand() % peer_signals.size();
////            auto itor = peer_signals.begin();
////            for (int i = 0; i < index && itor != peer_signals.end(); i++) {
////                ++itor;
////            }
////            peer = itor->first;
////            auto peer_signal = itor->second;
//
//            if (!peer_signal.demand_block_hash_set().empty()) {
//                // select one demand randomly to response to for selected peer
//                auto &demand_block_hash_set = peer_signal.demand_block_hash_set();
//                std::vector<sha256_hash> block_hashes(demand_block_hash_set.begin(), demand_block_hash_set.end());
//                // 产生随机数
//                srand(now);
//                auto index = rand() % block_hashes.size();
//                auto demand_block_hash = block_hashes[index];
//                auto demand_block = m_repository->get_block_by_hash(demand_block_hash);
//                if (!demand_block.empty()) {
//                    std::vector<dht::node_entry> entries;
//                    m_ses.dht()->find_live_nodes(demand_block.sha256(), entries);
//                    if (entries.size() > blockchain_immutable_payload_put_node_size) {
//                        entries.resize(blockchain_immutable_payload_put_node_size);
//                    }
//                    log("INFO: Put immutable block target[%s], entries[%zu]",
//                        aux::toHex(demand_block.sha256().to_string()).c_str(), entries.size());
//                    dht_put_immutable_item(demand_block.get_entry(), entries, demand_block.sha256());
//
//                    immutable_data_info demand_block_info(demand_block.sha256(), entries);
//                    block_set.insert(demand_block_info);
//                }
//            }
//
////            {
////                // find out missing txs
////                std::vector<transaction> missing_txs;
////                std::vector<transaction> txs = m_tx_pools[chain_id].get_top_ten_fee_transactions();
////                log("INFO: Txs size:%zu", txs.size());
////                find_best_solution(txs, peer_signal.tx_hash_prefix_array(), missing_txs);
////
////                log("INFO: Found missing tx size %zu", missing_txs.size());
////
////                if (!missing_txs.empty()) {
////                    // select one missing tx to response to
////                    // 产生随机数
////                    srand(now);
////                    auto index = rand() % missing_txs.size();
////                    auto miss_tx = missing_txs[index];
////                    if (!miss_tx.empty()) {
////                        std::vector<dht::node_entry> entries;
////                        m_ses.dht()->find_live_nodes(miss_tx.sha256(), entries);
////                        if (entries.size() > blockchain_immutable_payload_put_node_size) {
////                            entries.resize(blockchain_immutable_payload_put_node_size);
////                        }
////                        log("INFO: Put missing tx target[%s], entries[%zu]",
////                            aux::toHex(miss_tx.sha256().to_string()).c_str(), entries.size());
////                        dht_put_immutable_item(miss_tx.get_entry(), entries, miss_tx.sha256());
////
////                        immutable_data_info demand_tx_info(miss_tx.sha256(), entries);
////                        tx_set.insert(demand_tx_info);
////                    }
////                }
////            }
//
//            {
//                // find out missing txs
//                std::vector<transaction> missing_txs;
//                std::vector<transaction> txs = m_tx_pools[chain_id].get_top_ten_timestamp_transactions();
//                log("INFO: Txs size:%zu", txs.size());
//                find_best_solution(txs, peer_signal.latest_tx_hash_prefix_array(), missing_txs);
//
//                log("INFO: Found missing tx size %zu", missing_txs.size());
//
//                if (!missing_txs.empty()) {
//                    // select one missing tx to response to
//                    // 产生随机数
//                    srand(now);
//                    auto index = rand() % missing_txs.size();
//                    auto miss_tx = missing_txs[index];
//                    if (!miss_tx.empty()) {
//                        std::vector<dht::node_entry> entries;
//                        m_ses.dht()->find_live_nodes(miss_tx.sha256(), entries);
//                        if (entries.size() > blockchain_immutable_payload_put_node_size) {
//                            entries.resize(blockchain_immutable_payload_put_node_size);
//                        }
//                        log("INFO: Put missing tx target[%s], entries[%zu]",
//                            aux::toHex(miss_tx.sha256().to_string()).c_str(), entries.size());
//                        dht_put_immutable_item(miss_tx.get_entry(), entries, miss_tx.sha256());
//
//                        immutable_data_info demand_tx_info(miss_tx.sha256(), entries);
//                        tx_set.insert(demand_tx_info);
//                    }
//                }
//            }
////        }
//        }
//
//        // get my demand
//        std::set<sha256_hash> demand_block_hash_set;
//        auto &best_vote = m_best_votes[chain_id];
//        // voting demand block first
//        if (is_empty_chain(chain_id)) {
//            if (!best_vote.empty()) {
//                demand_block_hash_set.insert(best_vote.block_hash());
//            } else {
//                // select one randomly if voting has no result
//                auto &votes = m_votes[chain_id];
//                auto it = votes.begin();
//                if (it != votes.end()) {
//                    // select one randomly as the best vote
//                    m_best_votes[chain_id] = it->second;
//                    // request the best voting block
//                    demand_block_hash_set.insert(it->second.block_hash());
//                }
//            }
//        } else {
//            // not empty chain
//
//            if (!best_vote.empty()) {
//                // check if best vote match main chain block
//                auto hash = m_repository->get_main_chain_block_hash_by_number(chain_id, best_vote.block_number());
//                if (hash != best_vote.block_hash()) {
//                    // if not match, request blocks on best vote branch
//                    auto previous_hash = best_vote.block_hash();
//                    while (true) {
//                        // search until found absent or fork point block
//                        auto blk = get_block_from_cache_or_db(chain_id, previous_hash);
//                        if (blk.empty()) {
//                            log("INFO chain[%s] Cannot find demanding block[%s] in db/cache",
//                                aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
//                            demand_block_hash_set.insert(previous_hash);
//                            break;
//                        } else {
//                            auto main_chain_hash = m_repository->get_main_chain_block_hash_by_number(chain_id, blk.block_number());
//                            if (main_chain_hash == blk.sha256()) {
//                                break;
//                            }
//                            previous_hash = blk.previous_block_hash();
//                        }
//                    }
//                } else {
//                    auto &block_map = m_blocks[chain_id];
//                    for (auto & item: block_map) {
//                        auto b = item.second;
//                        // find a more difficult block
//                        if (b.cumulative_difficulty() > head_block.cumulative_difficulty()) {
//                            // find absent block
//                            auto previous_hash = b.previous_block_hash();
//                            bool found_absent = false;
//                            while (true) {
//                                // search until found absent or fork point block
//                                b = get_block_from_cache_or_db(chain_id, previous_hash);
//                                if (b.empty()) {
//                                    log("INFO: ----chain[%s] Cannot find demanding block hash[%s] in db/cache",
//                                        aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
//                                    demand_block_hash_set.insert(previous_hash);
//                                    found_absent = true;
//                                    break;
//                                } else {
//                                    auto main_chain_hash = m_repository->get_main_chain_block_hash_by_number(chain_id, b.block_number());
//                                    if (main_chain_hash == b.sha256()) {
//                                        break;
//                                    }
//                                    log("INFO: ----chain[%s] Got block [%s] in local",
//                                        aux::toHex(chain_id).c_str(),  b.to_string().c_str());
//                                    previous_hash = b.previous_block_hash();
//                                }
//                            }
//                            // if found absent, stop to search; otherwise continue to find more difficult in cache
//                            if (found_absent)
//                                break;
//                        }
//                    }
//                }
//            } else {
//                // not empty chain, but no best vote
//                auto &block_map = m_blocks[chain_id];
//                for (auto & item: block_map) {
//                    auto b = item.second;
//                    if (b.cumulative_difficulty() > head_block.cumulative_difficulty()) {
//                        // find absent block
//                        auto previous_hash = b.previous_block_hash();
//                        bool found_absent = false;
//                        while (true) {
//                            // search until found absent or fork point block
//                            b = get_block_from_cache_or_db(chain_id, previous_hash);
//                            if (b.empty()) {
//                                log("INFO chain[%s] Cannot find demanding block[%s] in db/cache",
//                                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
//                                demand_block_hash_set.insert(previous_hash);
//                                found_absent = true;
//                                break;
//                            } else {
//                                auto main_chain_hash = m_repository->get_main_chain_block_hash_by_number(chain_id, b.block_number());
//                                if (main_chain_hash == b.sha256()) {
//                                    break;
//                                }
//                                previous_hash = b.previous_block_hash();
//                            }
//                        }
//                        // if found absent, stop to search; otherwise continue to find more difficult in cache
//                        if (found_absent)
//                            break;
//                    }
//                }
//            }
//
//            // if sync no completed, request tail block too
//            if (!is_sync_completed(chain_id)) {
//                auto &tail_block = m_tail_blocks[chain_id];
//                if (!tail_block.empty()) {
//                    demand_block_hash_set.insert(tail_block.previous_block_hash());
//                }
//            }
//        }
//
//        if (!peer_signal.empty() && block_set.empty() && tx_set.empty() && demand_block_hash_set.empty()) {
//
//            // offer tx pool info
////        aux::bytes tx_hash_prefix_array = m_tx_pools[chain_id].get_hash_prefix_array_by_fee();
//            aux::bytes latest_tx_hash_prefix_array = m_tx_pools[chain_id].get_hash_prefix_array_by_timestamp();
//
//            // offer a peer from chain
//            auto p = select_peer_randomly(chain_id);
//
//            // make signal
//            blockchain_signal signal(chain_id, now, consensus_point_vote,
//                                     head_block_info, voting_point_block_info,
//                                     block_set, tx_set, demand_block_hash_set,
//                                     latest_tx_hash_prefix_array, p);
//
//            dht::public_key *pk = m_ses.pubkey();
//            dht::secret_key *sk = m_ses.serkey();
//
//            auto salt = make_salt(chain_id);
//
//            log("INFO: Publish signal [%s] on chain[%s], salt:[%s]", signal.to_string().c_str(),
//                aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
//
//            dht_put_mutable_item(pk->bytes,
//                                 std::bind(&put_mutable_data, _1, _2, _3, _4, pk->bytes, sk->bytes, signal.get_entry()),
//                                 salt, peer);
//        }
//    }

//    void blockchain::process_signal(const blockchain_signal &signal, const aux::bytes &chain_id,
//                                    const dht::public_key &peer) {
//        log("INFO chain[%s] Got signal:[%s] from peer[%s]", aux::toHex(chain_id).c_str(),
//            signal.to_string().c_str(), aux::toHex(peer.bytes).c_str());
//
//        // current time
//        auto now = get_total_milliseconds();
//
//        // record last time got data from dht
//        m_last_got_data_time[chain_id] = now;
//
//        auto last_time = m_latest_signal_time[chain_id][peer];
//        // update latest time
//        if (signal.timestamp() > last_time) {
//            m_latest_signal_time[chain_id][peer] = signal.timestamp();
//        }
//
//        // old data in 60s also is accepted
//        if (signal.timestamp() + 60000 < last_time) {
//            log("INFO chain[%s] Signal time is too old", aux::toHex(chain_id).c_str());
//            return;
//        }
//
//        auto consensus_point_vote = signal.consensus_point_vote();
//        // only vote time in 5 min is accepted
//        if (!consensus_point_vote.empty() && now < signal.timestamp() + DEFAULT_BLOCK_TIME * 1000) {
//            log("INFO chain[%s] valid vote[%s]",
//                aux::toHex(chain_id).c_str(), consensus_point_vote.to_string().c_str());
//            m_votes[chain_id][peer] = consensus_point_vote;
//        }
//
//        // get head block
//        auto &head_block_info = signal.head_block_info();
//        if (!head_block_info.empty()) {
//            // get immutable block
//            if (!is_block_in_cache_or_db(chain_id, head_block_info.target())) {
//                dht_get_immutable_block_item(chain_id, head_block_info.target(), head_block_info.entries());
//            }
//        }
//
//        // get voting point block
//        auto &voting_point_block_info = signal.voting_point_block_info();
//        if (!voting_point_block_info.empty()) {
//            // get immutable block
//            if (!is_block_in_cache_or_db(chain_id, voting_point_block_info.target())) {
//                dht_get_immutable_block_item(chain_id, voting_point_block_info.target(),
//                                             voting_point_block_info.entries());
//            }
//        }
//
//        // get offered block
//        auto &block_info_set = signal.block_info_set();
//        for (auto const & block_info: block_info_set) {
//            if (!block_info.empty()) {
//                if (!is_block_in_cache_or_db(chain_id, block_info.target())) {
//                    dht_get_immutable_block_item(chain_id, block_info.target(), block_info.entries());
//                }
//            }
//        }
//
//        // get tx
//        auto &tx_info_set = signal.tx_info_set();
//        for (auto const & tx_info: tx_info_set) {
//            if (!tx_info.empty()) {
//                if (!m_tx_pools[chain_id].is_transaction_in_pool(tx_info.target())) {
//                    dht_get_immutable_tx_item(chain_id, tx_info.target(), tx_info.entries());
//                }
//            }
//        }
//
//        // get gossip peer
//        auto &gossip_peer = signal.gossip_peer();
//        if (gossip_peer != dht::public_key()) {
//            log("INFO chain[%s] Got gossip peer[%s]",
//                aux::toHex(chain_id).c_str(), aux::toHex(gossip_peer.bytes).c_str());
//            m_repository->add_peer_in_gossip_peer_db(chain_id, gossip_peer);
//        }
//
//        // save signal
////        auto it = m_unchoked_peers[chain_id].find(peer);
////        if (it != m_unchoked_peers[chain_id].end()) {
////            m_unchoked_peer_signal[chain_id][peer] = signal;
////        }
//
//        // response signal
//        publish_signal(chain_id, peer, signal);
//    }

    // callback for dht_immutable_get
//    void blockchain::get_immutable_block_callback(aux::bytes const& chain_id, sha256_hash target, dht::item const& i)
//    {
//        TORRENT_ASSERT(!i.is_mutable());
//        if (!i.empty()) {
//            log("INFO: Got immutable block callback, target[%s].", aux::toHex(target.to_string()).c_str());
//
//            block blk(i.value());
//            log("INFO: ----Got immutable block:%s", blk.to_string().c_str());
//            // TODO: validate timestamp etc. ?
//            if (!blk.empty()) {
//                m_blocks[chain_id][blk.sha256()] = blk;
//
//                // notify ui tx from block
//                auto tx = blk.tx();
//                if (!tx.empty()) {
//                    m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(tx);
//                }
//            }
//        }
//    }

//    void blockchain::dht_get_immutable_block_item(aux::bytes const& chain_id, sha256_hash const& target, std::vector<dht::node_entry> const& eps)
//    {
//        if (!m_ses.dht()) return;
//        m_ses.dht()->get_item(target, eps, std::bind(&blockchain::get_immutable_block_callback
//                , this, chain_id, target, _1));
//    }
//
//    // callback for dht_immutable_get
//    void blockchain::get_immutable_tx_callback(aux::bytes const& chain_id, sha256_hash target, dht::item const& i)
//    {
//        TORRENT_ASSERT(!i.is_mutable());
//        if (!i.empty()) {
//            log("INFO: Got immutable tx callback, target[%s].", aux::toHex(target.to_string()).c_str());
//
//            transaction tx(i.value());
//            m_tx_pools[chain_id].add_tx(tx);
//
//            m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(tx);
//        }
//    }

//    void blockchain::dht_get_immutable_tx_item(aux::bytes const& chain_id, sha256_hash const& target, std::vector<dht::node_entry> const& eps)
//    {
//        if (!m_ses.dht()) return;
//        m_ses.dht()->get_item(target, eps, std::bind(&blockchain::get_immutable_tx_callback
//                , this, chain_id, target, _1));
//    }

    // callback for dht_mutable_get
//    void blockchain::get_mutable_callback(aux::bytes const& chain_id, dht::item const& i
//            , bool const authoritative)
//    {
//        TORRENT_ASSERT(i.is_mutable());
//
//        // construct mutable data wrapper from entry
//        if (!i.empty()) {
//            auto peer = i.pk();
//
//            // update latest item timestamp
//            if (i.ts() > m_latest_item_timestamp[chain_id][peer]) {
//                m_latest_item_timestamp[chain_id][peer] = i.ts();
//            }
//
//            blockchain_signal signal(i.value());
//
//            process_signal(signal, chain_id, peer);
//        }
//    }

    // key is a 32-byte binary string, the public key to look up.
    // the salt is optional
//    void blockchain::dht_get_mutable_item(aux::bytes const& chain_id, std::array<char, 32> key
//            , std::string salt, dht::timestamp t)
//    {
//        if (!m_ses.dht()) return;
//        m_ses.dht()->get_item(dht::public_key(key.data()), std::bind(&blockchain::get_mutable_callback
//                , this, chain_id, _1, _2), std::move(salt), t.value);
//    }

//    void blockchain::dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target)
//    {
//        if (!m_ses.dht()) return;
//        log("INFO: Put immutable item target[%s], entries[%zu]",
//            aux::toHex(target.to_string()).c_str(), eps.size());
//
//        m_ses.dht()->put_item(data,  eps, std::bind(&on_dht_put_immutable_item, std::ref(m_ses.alerts())
//                , target, _1));
//    }

    void blockchain::dht_put_mutable_item(std::array<char, 32> key
            , std::function<void(entry&, std::array<char,64>&
            , std::int64_t&, std::string const&)> cb
            , std::string salt, const dht::public_key &peer)
    {
        if (!m_ses.dht()) return;
        m_ses.dht()->put_item(dht::public_key(key.data())
                , std::bind(&on_dht_put_mutable_item, std::ref(m_ses.alerts()), _1, _2)
                , std::bind(&put_mutable_callback, _1, std::move(cb)), std::move(salt), peer);
    }

    bool blockchain::should_log() const
    {
        return m_ses.alerts().should_post<blockchain_log_alert>();
    }

    TORRENT_FORMAT(2,3)
    void blockchain::log(char const* fmt, ...) const noexcept try
    {
#ifndef TORRENT_DISABLE_LOGGING
        if (!should_log()) return;

        va_list v;
        va_start(v, fmt);
        m_ses.alerts().emplace_alert<blockchain_log_alert>(fmt, v);
        va_end(v);
#endif
    }
    catch (std::exception const&) {}


    aux::bytes blockchain::create_chain_id(std::string community_name) {
        libTAU::aux::bytes chain_id;
        dht::public_key * pk = m_ses.pubkey();
        std::int64_t now = get_total_milliseconds();

        std::string spk(pk->bytes.begin(), pk->bytes.end());
        std::stringstream data;
        data << spk << now;
        sha256_hash hash = dht::item_target_id(data.str());
        chain_id.insert(chain_id.end(), hash.begin(), hash.begin() + CHAIN_ID_HASH_MAX_LENGTH);

        if (community_name.length() > CHAIN_ID_COMMUNITY_NAME_MAX_LENGTH) {
            chain_id.insert(chain_id.end(), community_name.begin(), community_name.begin() + CHAIN_ID_COMMUNITY_NAME_MAX_LENGTH);
        } else {
            chain_id.insert(chain_id.end(), community_name.begin(), community_name.end());
        }

        log("INFO Create chain id[%s] with community name[%s]", aux::toHex(chain_id).c_str(), community_name.c_str());

        return chain_id;
    }

    bool blockchain::create_TAU_chain() {
        log("INFO: create tau chain.");
        std::int64_t size = TAU_CHAIN_GENESIS_ACCOUNT.size();
        std::int64_t block_number = -1 * size + 1;
        sha256_hash previous_hash;

        dht::secret_key *sk = m_ses.serkey();
        dht::public_key *pk = m_ses.pubkey();
        std::set<dht::public_key> peers;
        std::vector<block> blocks;
        for (auto const &act: TAU_CHAIN_GENESIS_ACCOUNT) {
            auto miner = act;
            peers.insert(miner);

            std::string data(miner.bytes.begin(), miner.bytes.end());
            auto genSig = dht::item_target_id(data);

            block b = block(TAU_CHAIN_ID, block_version::block_version1, TAU_CHAIN_GENESIS_TIMESTAMP, block_number, previous_hash,
                            GENESIS_BASE_TARGET, 0, genSig, transaction(), miner, GENESIS_BLOCK_BALANCE,
                            0, 0, 0, 0, 0);
            b.sign(*pk, *sk);

            blocks.push_back(b);

            previous_hash = b.sha256();
            block_number++;
        }

        // follow and load chain
        followChain(TAU_CHAIN_ID, peers);

        for (auto it = blocks.rbegin(); it != blocks.rend(); ++it) {
            log("Process tau chain block:%s", it->to_string().c_str());
            process_block(TAU_CHAIN_ID, *it);
        }

        return true;
    }

    bool blockchain::createNewCommunity(const aux::bytes &chain_id, const std::map<dht::public_key, account>& accounts) {
        std::int64_t now = get_total_milliseconds() / 1000; // second

        dht::secret_key *sk = m_ses.serkey();
        dht::public_key *pk = m_ses.pubkey();

        std::int64_t base_target = GENESIS_BASE_TARGET;
        std::string data(pk->bytes.begin(), pk->bytes.end());
        auto genSig = dht::item_target_id(data);

        std::int64_t size = accounts.size();
        std::int64_t block_number = -1 * (size > MAX_NEGATIVE_BLOCK_SIZE ? MAX_NEGATIVE_BLOCK_SIZE : size);
        sha256_hash previous_hash;

        std::set<dht::public_key> peers;
        std::vector<block> blocks;
        std::int64_t total_balance = 0;
        int i = 0;
        for (auto const &act: accounts) {
            auto miner = act.first;
            peers.insert(miner);
            std::int64_t miner_balance = act.second.balance();
            total_balance += miner_balance;

            block b = block(chain_id, block_version::block_version1, now, block_number, previous_hash,
                            base_target, 0, genSig, transaction(), miner, miner_balance,
                            0, 0, 0, 0, 0);
            b.sign(*pk, *sk);

            blocks.push_back(b);

            previous_hash = b.sha256();
            block_number++;

            i++;
            if (i >= MAX_NEGATIVE_BLOCK_SIZE)
                break;
        }

        std::int64_t genesis_balance = GENESIS_BLOCK_BALANCE > total_balance ? GENESIS_BLOCK_BALANCE - total_balance : 0;
        block b = block(chain_id, block_version::block_version1, now, block_number, previous_hash,
                        base_target, 0, genSig, transaction(), *pk, genesis_balance,
                        0, 0, 0, 0, 0);
        b.sign(*pk, *sk);

        peers.insert(*pk);
        blocks.push_back(b);

        // follow and load chain
        followChain(chain_id, peers);

        for (auto it = blocks.rbegin(); it != blocks.rend(); ++it) {
            process_block(chain_id, *it);
        }

        return true;
    }

    bool blockchain::submitTransaction(const transaction& tx) {
        try {
            log("INFO: add new tx:%s", tx.to_string().c_str());
            if (!tx.empty()) {
                auto &chain_id = tx.chain_id();

                auto peers = m_repository->get_all_peers(chain_id);
                common::transaction_entry txEntry(tx);
                auto now = get_total_milliseconds();
                for (auto const &peer: peers) {
                    common::entry_task task(common::transaction_entry::data_type_id, peer, txEntry.get_entry(), now);
                    add_entry_task_to_queue(chain_id, task);
                }

                return m_tx_pools[chain_id].add_tx(tx);
            }
        } catch (std::exception &e) {
            log("Exception add new tx [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            return false;
        }

        return false;
    }

    account blockchain::getAccountInfo(const aux::bytes &chain_id, dht::public_key publicKey) {
        return m_repository->get_account_with_effective_power(chain_id, publicKey);
    }

    block blockchain::getBlock(const aux::bytes &chain_id, std::int64_t block_number) {
        return m_repository->get_main_chain_block_by_number(chain_id, block_number);
    }

    block blockchain::getBlock(const aux::bytes &chain_id, sha256_hash block_hash) {
        return m_repository->get_block_by_hash(block_hash);
    }

    std::vector<block> blockchain::getTopTipBlocks(const aux::bytes &chain_id, int topNum) {
        std::vector<block> blocks;
        if (topNum > 0) {
            auto head_block = m_head_blocks[chain_id];
            if (!head_block.empty()) {
                blocks.push_back(head_block);
                topNum--;
                auto previous_hash = head_block.previous_block_hash();
                while (!previous_hash.is_all_zeros() && topNum > 0) {
                    auto b = m_repository->get_block_by_hash(previous_hash);
                    if (!b.empty()) {
                        blocks.push_back(b);
                        previous_hash = b.previous_block_hash();
                    }
                }
            }
        }

        return blocks;
    }

    std::int64_t blockchain::getMedianTxFee(const aux::bytes &chain_id) {
        std::vector<transaction> txs = m_tx_pools[chain_id].get_top_ten_fee_transactions();
        auto size = txs.size();
        if (size > 0) {
            return txs[size / 2].fee();
        }

        return 0;
    }

    void blockchain::set_blockchain_loop_interval(int milliseconds) {
        log("INFO: Set block chain loop interval:%d(ms)", milliseconds);
        m_refresh_time = milliseconds;
    }

    void blockchain::on_dht_item(const dht::item &i) {
        // construct mutable data wrapper from entry
        if (!i.empty()) {
            dht::public_key peer = i.pk();

            // check protocol id
//            if (auto* p = const_cast<entry *>(i.value().find_key("pid")))
//            {
//                auto protocol_id = p->integer();
//                if (blockchain_signal::protocol_id == protocol_id) {
//                    blockchain_signal signal(i.value());
//
//                    const auto& chain_id = signal.chain_id();
//
//                    // update latest item timestamp
//                    if (i.ts() > m_latest_item_timestamp[chain_id][peer]) {
//                        m_latest_item_timestamp[chain_id][peer] = i.ts();
//                    }
//
//                    process_signal(signal, chain_id, peer);
//                }
//            }
            // check data type id
            if (auto* p = const_cast<entry *>(i.value().find_key(common::entry_type)))
            {
                auto data_type_id = p->integer();
                log("---------------data type id:%ld from peer[%s]", data_type_id, aux::toHex(peer.bytes).c_str());
                switch (data_type_id) {
                    case common::block_request_entry::data_type_id: {
                        common::block_request_entry blk_request_entry(i.value());
                        auto blk = m_repository->get_block_by_hash(blk_request_entry.m_hash);

                        if (!blk.empty()) {
                            common::block_entry blockEntry(blk);
                            send_to(blk.chain_id(), peer, blockEntry.get_entry());
//                            common::entry_task task(common::block_entry::data_type_id, peer, blockEntry.get_entry(),
//                                                     get_total_milliseconds());
//                            m_tasks[blk.chain_id()].insert(task);
                        } else {
                            log("INFO: Cannot get block[%s] in local", aux::toHex(blk_request_entry.m_hash).c_str());
                        }

                        break;
                    }
                    case common::block_entry::data_type_id: {
                        common::block_entry blk_entry(i.value());

                        // TODO: validate timestamp etc. ?
                        if (!blk_entry.m_blk.empty()) {
                            log("INFO: Got block, hash[%s].", aux::toHex(blk_entry.m_blk.sha256().to_string()).c_str());

                            m_blocks[blk_entry.m_blk.chain_id()][blk_entry.m_blk.sha256()] = blk_entry.m_blk;

                            // notify ui tx from block
                            if (!blk_entry.m_blk.tx().empty()) {
                                m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(blk_entry.m_blk.tx());
                            }

                            try_to_update_visiting_peer(blk_entry.m_blk.chain_id(), peer);
                        }

                        break;
                    }
                    case common::transaction_request_entry::data_type_id: {
                        break;
                    }
                    case common::transaction_entry::data_type_id: {
                        common::transaction_entry tx_entry(i.value());
                        if (!tx_entry.m_tx.empty()) {
                            auto &chain_id = tx_entry.m_tx.chain_id();
                            log("INFO: Got transaction, hash[%s].",
                                aux::toHex(tx_entry.m_tx.sha256().to_string()).c_str());

                            auto tx1 = m_tx_pools[chain_id].get_best_transaction();
                            m_tx_pools[chain_id].add_tx(tx_entry.m_tx);
                            auto tx2 = m_tx_pools[chain_id].get_best_transaction();
                            if (tx1.sha256() != tx2.sha256()) {
                                common::transaction_entry txEntry(tx2);
                                common::entry_task task(common::transaction_entry::data_type_id, txEntry.get_entry(), get_total_milliseconds());
                                add_entry_task_to_queue(chain_id, task);
                            }

                            m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(tx_entry.m_tx);

                            try_to_update_visiting_peer(chain_id, peer);
                        }

                        break;
                    }
                    case common::vote_request_entry::data_type_id: {
                        common::vote_request_entry voteRequestEntry(i.value());
                        auto &chain_id = voteRequestEntry.m_chain_id;

                        // vote for voting point
                        auto &voting_point_block = m_voting_point_blocks[chain_id];
                        vote consensus_point_vote;
                        if (is_sync_completed(chain_id) && !voting_point_block.empty()) {
                            consensus_point_vote.setBlockHash(voting_point_block.sha256());
                            consensus_point_vote.setBlockNumber(voting_point_block.block_number());

                            common::vote_entry voteEntry(chain_id, consensus_point_vote);
                            send_to(chain_id, peer, voteEntry.get_entry());
//                            common::entry_task task(common::vote_entry::data_type_id, peer, voteEntry.get_entry(),
//                                                    get_total_milliseconds());
//                            m_tasks[chain_id].insert(task);
                        }

                        try_to_update_visiting_peer(chain_id, peer);

                        break;
                    }
                    case common::vote_entry::data_type_id: {
                        common::vote_entry voteEntry(i.value());
                        auto &chain_id = voteEntry.m_chain_id;

                        log("INFO: chain[%s] valid vote[%s]",
                            aux::toHex(chain_id).c_str(), voteEntry.m_vote.to_string().c_str());
                        m_votes[chain_id][peer] = voteEntry.m_vote;

                        try_to_update_visiting_peer(chain_id, peer);

                        break;
                    }
                    case common::head_block_request_entry::data_type_id: {
                        common::head_block_request_entry headBlockRequestEntry(i.value());
                        auto &chain_id = headBlockRequestEntry.m_chain_id;
                        auto blk = m_head_blocks[chain_id];

                        if (!blk.empty()) {
                            common::block_entry blockEntry(blk);
                            send_to(chain_id, peer, blockEntry.get_entry());
//                            common::entry_task task(common::block_entry::data_type_id, peer, blockEntry.get_entry(),
//                                                    get_total_milliseconds());
//                            m_tasks[blk.chain_id()].insert(task);
                        } else {
                            log("INFO: Cannot get head block in local");
                        }

                        try_to_update_visiting_peer(chain_id, peer);

                        break;
                    }
                    default: {
                    }
                }
            }
        }
    }

}