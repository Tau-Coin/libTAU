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

//        m_vote_timer.expires_after(seconds(DEFAULT_BLOCK_TIME));
//        m_vote_timer.async_wait(std::bind(&blockchain::refresh_vote_timeout, self(), _1));

//        m_exchange_tx_timer.expires_after(seconds(EXCHANGE_TX_TIME));
//        m_exchange_tx_timer.async_wait(std::bind(&blockchain::refresh_tx_timeout, self(), _1));

        return true;
    }

    bool blockchain::stop()
    {
        m_stop = true;

        clear_all_cache();

        log("INFO: Stop BlockChain...");

        return true;
    }

    void blockchain::account_changed() {
        log("INFO: Change account..");

        m_access_list.clear();
        m_ban_list.clear();
    }

    void blockchain::request_state(const aux::bytes &chain_id) {
        common::state_request_entry stateRequestEntry(chain_id);
        common::entry_task task(common::state_request_entry::data_type_id, stateRequestEntry.get_entry());
        add_entry_task_to_queue(chain_id, task);
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

        // create vote timer
        m_vote_timers.emplace(chain_id, aux::deadline_timer(m_ioc));

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
        m_chain_status.clear();
        m_last_voting_time.clear();
        m_vote_request_peers.clear();

        while (!m_tasks.empty()) {
            m_tasks.pop();
        }
        m_tasks_set.clear();

        m_visiting_history.clear();
        m_visiting_time.clear();
        m_access_list.clear();
        m_ban_list.clear();
        m_priority_chain = std::make_pair(aux::bytes(), 0);
//        m_chain_peers.clear();
//        m_chain_gossip_peers.clear();
//        m_unchoked_peers.clear();
//        m_unchoked_peer_signal.clear();
//        m_update_peer_time.clear();
//        m_last_got_data_time.clear();
        m_blocks.clear();
        m_head_blocks.clear();
        m_tail_blocks.clear();
        m_consensus_point_blocks.clear();
        m_voting_point_blocks.clear();
        m_best_votes.clear();
        m_votes.clear();
//        m_latest_signal_time.clear();
    }

    void blockchain::clear_chain_cache(const aux::bytes &chain_id) {
//        m_chains.erase(chain_id);
        m_tx_pools[chain_id].clear();
        m_chain_status.erase(chain_id);
        m_last_voting_time.erase(chain_id);
        m_vote_request_peers.erase(chain_id);
        m_visiting_history.erase(chain_id);
        m_visiting_time.erase(chain_id);
        m_access_list.erase(chain_id);
        m_ban_list.erase(chain_id);
//        m_chain_peers[chain_id].clear();
//        m_chain_gossip_peers[chain_id].clear();
//        m_unchoked_peers[chain_id].clear();
//        m_unchoked_peer_signal[chain_id].clear();
//        m_update_peer_time.erase(chain_id);
//        m_last_got_data_time.erase(chain_id);
        m_blocks[chain_id].clear();
        m_head_blocks.erase(chain_id);
        m_tail_blocks.erase(chain_id);
        m_consensus_point_blocks.erase(chain_id);
        m_voting_point_blocks.erase(chain_id);
        m_best_votes.erase(chain_id);
        m_votes[chain_id].clear();
//        m_latest_signal_time[chain_id].clear();
    }


    void blockchain::refresh_timeout(const error_code &e) {
        if (e || m_stop) return;

        try {
            // 随机挑选一条
            aux::bytes chain_id = select_chain_randomly();
            if (!chain_id.empty()) {
                log("INFO: Select chain:%s, status:%d", aux::toHex(chain_id).c_str(), m_chain_status[chain_id]);

                // current time
                auto now = get_total_milliseconds();

                {
                    // peer list log
                    // acl
                    auto &acl = m_access_list[chain_id];
                    for (auto const &item: acl) {
                        log("-----ACL: peer[%s], info[%s]", aux::toHex(item.first.bytes).c_str(),
                            item.second.to_string().c_str());
                    }
                    // ban list
                    auto &ban_list = m_ban_list[chain_id];
                    for (auto const &item: ban_list) {
                        log("-----Ban List: peer[%s], info[%s]", aux::toHex(item.first.bytes).c_str(),
                            item.second.to_string().c_str());
                    }
                }

                if (now > m_last_voting_time[chain_id] + 30 * 60 * 1000) {
                    m_chain_status[chain_id] = VOTE_PREPARE;

                    m_last_voting_time[chain_id] = now;
                    log("INFO: 1. chain:%s vote status:%d, time:%ld", aux::toHex(chain_id).c_str(), m_chain_status[chain_id], now);
                }

                if (m_chain_status[chain_id] == VOTE_PREPARE) {
                    auto peers = m_repository->get_all_peers(chain_id);
                    auto size = peers.size();
                    if (size < 20) {
                        m_vote_request_peers[chain_id] = peers;
                    } else {
                        for (int i = 0; i < 30; i++) {
                            auto peer = m_repository->get_peer_randomly(chain_id);
                            m_vote_request_peers[chain_id].insert(peer);
                        }
                    }

                    m_chain_status[chain_id] = VOTE_REQUEST;
                    log("INFO: 2. chain:%s vote status:%d, time:%ld", aux::toHex(chain_id).c_str(), m_chain_status[chain_id], now);
                }

                if (m_chain_status[chain_id] == VOTE_REQUEST) {
                    auto &peers = m_vote_request_peers[chain_id];
                    auto it = peers.begin();
                    if (it != peers.end()) {
                        // request vote
                        common::vote_request_entry voteRequestEntry(chain_id);
                        send_to(chain_id, *it, voteRequestEntry.get_entry());

                        peers.erase(it);
                        log("INFO: 3.1 chain:%s vote status:%d, time:%ld", aux::toHex(chain_id).c_str(), m_chain_status[chain_id], now);
                    } else {
                        m_chain_status[chain_id] = VOTE_COUNT;
                        log("INFO: 3.2. chain:%s vote status:%d, time:%ld, ready to count cotes", aux::toHex(chain_id).c_str(), m_chain_status[chain_id], now);

                        auto i = m_vote_timers.find(chain_id);
                        if (i != m_vote_timers.end()) {
                            i->second.expires_after(seconds(5));
                            i->second.async_wait(std::bind(&blockchain::count_votes, self(), _1, chain_id));
                        }
                    }
                } else if (m_chain_status[chain_id] == MINING) {

                    auto &block_map = m_blocks[chain_id];

                    // 1. if empty chain, init chain with the best voting block
                    if (is_empty_chain(chain_id)) {
                        log("INFO: chain[%s] is empty...", aux::toHex(chain_id).c_str());
                        auto &best_vote = m_best_votes[chain_id];
                        if (!best_vote.empty()) {
                            auto blk = get_block_from_cache_or_db(chain_id, best_vote.block_hash());
                            if (!blk.empty()) {
                                process_block(chain_id, blk);
                            }
                        } else {
                            log("INFO: chain[%s] vote is empty...", aux::toHex(chain_id).c_str());
                            m_chain_status[chain_id] = VOTE_PREPARE;
                        }
                    }

                    if (!is_empty_chain(chain_id)) {
                        // 2. try to connect head/tail block
                        auto &head_block = m_head_blocks[chain_id];
                        auto &tail_block = m_tail_blocks[chain_id];
                        for (auto it = block_map.begin(); it != block_map.end();) {
                            if (head_block.empty() || it->second.previous_block_hash() == head_block.sha256() ||
                                it->second.sha256() == tail_block.previous_block_hash()) {
                                log("INFO: process block:%s", it->second.to_string().c_str());
                                auto ret = process_block(chain_id, it->second);
                                if (ret == SUCCESS) {
                                    block_map.erase(it);
                                    it = block_map.begin();
                                    continue;
                                } else if (ret == FAIL) {
                                    block_map.erase(it++);
                                    continue;
                                }
                            }

                            ++it;
                        }

                        // 3. try to re-branch to a more difficult chain
                        {
                            auto &acl = m_access_list[chain_id];

                            // find out the most difficult chain
                            auto it = acl.end();
                            std::uint64_t max_difficulty = 0;
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (!iter->second.m_head_block.empty() &&
                                    iter->second.m_head_block.cumulative_difficulty() > max_difficulty) {
                                    max_difficulty = iter->second.m_head_block.cumulative_difficulty();
                                    it = iter;
                                }
                            }

                            if (max_difficulty > head_block.cumulative_difficulty() && it != acl.end()) {
                                auto blk = it->second.m_head_block;
                                auto result = try_to_rebranch(chain_id, blk);
                                // clear block cache if re-branch success/fail
                                if (result == FAIL) {
                                    // clear all blocks on the same chain
                                    remove_all_same_chain_blocks_from_cache(blk);

                                    acl.erase(it);
                                    ban_peer(chain_id, it->first);
                                } else if (result == SUCCESS) {
                                    // clear all ancestor blocks
                                    remove_all_ancestor_blocks_from_cache(blk);
                                }
                            }
                        }

                        // 4. check if need to re-branch to the best vote
                        auto &best_vote = m_best_votes[chain_id];
                        if (!best_vote.empty()) {
                            log("INFO chain[%s] current best vote[%s]", aux::toHex(chain_id).c_str(),
                                best_vote.to_string().c_str());

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
                                            remove_all_ancestor_blocks_from_cache(vote_block);

                                            // update consensus point block hash as best voting block
                                            m_consensus_point_blocks[chain_id] = vote_block;
                                            m_repository->set_consensus_point_block_hash(chain_id,
                                                                                         best_vote.block_hash());

                                            m_ses.alerts().emplace_alert<blockchain_new_consensus_point_block_alert>(
                                                    vote_block);
                                        } else if (result == FAIL) {
                                            remove_all_same_chain_blocks_from_cache(vote_block);
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

                                common::head_block_entry blockEntry(blk);
                                common::entry_task task(common::head_block_entry::data_type_id, blockEntry.get_entry());
                                add_entry_task_to_queue(chain_id, task);
                            }
                        }
                    }

                    {
                        // calc score
                        auto &acl = m_access_list[chain_id];
                        for (auto &item: acl) {
                            auto &requests_time = item.second.m_requests_time;
                            for (auto it = requests_time.begin(); it != requests_time.end();) {
                                if (now > it->second + blockchain_request_timeout) {
                                    item.second.m_score = item.second.m_score - 5;
                                    requests_time.erase(it++);
                                } else {
                                    it++;
                                }
                            }

                            // remove outdated requests
                            auto &peer_requests_time = item.second.m_peer_requests_time;
                            for (auto it = peer_requests_time.begin(); it != peer_requests_time.end();) {
                                if (now > it->second + blockchain_same_response_interval) {
                                    peer_requests_time.erase(it++);
                                } else {
                                    it++;
                                }
                            }
                        }

                        // kick out bad peer from acl and add it into ban list
                        for (auto it = acl.begin(); it != acl.end();) {
                            if (it->second.m_score <= 0 || (it->second.m_stage == NORMAL && now > it->second.m_last_seen + 210 * 1000)) {
                                auto &ban_list = m_ban_list[chain_id];
                                auto it_ban = ban_list.find(it->first);
                                if (it_ban != ban_list.end()) {
                                    it_ban->second.increase_ban_times();
                                    auto ban_time = blockchain_min_ban_time * it_ban->second.m_ban_times;
                                    if (ban_time > blockchain_max_ban_time) {
                                        ban_time = blockchain_max_ban_time;
                                    }
                                    it_ban->second.set_free_time(now + ban_time);
                                } else {
                                    ban_list[it->first] = ban_info();
                                    auto ban_time = blockchain_min_ban_time * ban_list[it->first].m_ban_times;
                                    if (ban_time > blockchain_max_ban_time) {
                                        ban_time = blockchain_max_ban_time;
                                    }
                                    ban_list[it->first].set_free_time(now + ban_time);
                                }

                                acl.erase(it++);
                            } else {
                                it++;
                            }
                        }

                        // remove surplus peers
                        if (acl.size() > blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            acl.erase(min_it);
                        }
                    }

                    if (true) {
                        {
                            auto &acl = m_access_list[chain_id];
                            auto size = acl.size();
                            if (size < blockchain_acl_min_peers) {
                                std::set<dht::public_key> peers;
                                for (auto i = blockchain_acl_max_peers - size; i > 0; i--) {
                                    auto peer = select_peer_randomly(chain_id);
                                    // if peer is not in acl, not been banned
                                    if (!peer.is_all_zeros() && acl.find(peer) == acl.end() & peer != *m_ses.pubkey()) {
                                        auto &ban_list = m_ban_list[chain_id];
                                        auto it = ban_list.find(peer);
                                        if (it != ban_list.end()) {
                                            if (it->second.m_free_time > now) {
                                                // peer is still banned
                                                continue;
                                            }
                                        }
                                        peers.insert(peer);
                                    }
                                }

                                // all peers those added into acl should request head block
                                for (auto const &peer: peers) {
                                    acl[peer] = peer_info();
                                }
                            }

                            // check if need to request on current stage
                            for (auto &item: acl) {
                                if (item.second.m_stage == HEAD_BLOCK) {
                                    if (item.second.m_requests_time.find(std::make_unique<common::head_block_request_entry>(chain_id))
                                        == item.second.m_requests_time.end()) {
                                        common::head_block_request_entry headBlockRequestEntry(chain_id);
                                        common::entry_task task(common::head_block_request_entry::data_type_id,
                                                                item.first,
                                                                headBlockRequestEntry.get_entry());
                                        add_entry_task_to_queue(chain_id, task);

                                        item.second.m_requests_time[std::make_unique<common::head_block_request_entry>(chain_id)] = now;
                                    }
                                } else if (item.second.m_stage == NORMAL) {
                                    if (!item.second.m_tx_pool_sync_done && is_sync_completed(chain_id) &&
                                        item.second.m_head_block == m_head_blocks[chain_id] &&
                                        item.second.m_requests_time.find(std::make_unique<common::tx_pool_entry>(chain_id)) == item.second.m_requests_time.end()) {
                                        common::tx_pool_entry txPoolEntry(chain_id,
                                                                         m_tx_pools[chain_id].get_hash_prefix_array_by_fee(),
                                                                         m_tx_pools[chain_id].get_hash_prefix_array_by_timestamp());
                                        common::entry_task task(common::tx_pool_entry::data_type_id, item.first, txPoolEntry.get_entry());
                                        add_entry_task_to_queue(chain_id, task);

                                        item.second.m_requests_time[std::make_unique<common::tx_pool_entry>(chain_id)] = now;
                                    }
                                    // ping every minute
                                    if (now > item.second.m_last_ping_time + 60 * 1000) {
                                        common::ping_entry pingEntry(chain_id);
                                        common::entry_task task(common::ping_entry::data_type_id, item.first, pingEntry.get_entry());
                                        add_entry_task_to_queue(chain_id, task);

                                        item.second.m_last_ping_time = now;
                                    }
                                }
                            }
                        }
//                    }
//
//                    if (m_tasks[chain_id].empty()) {
                        auto &head_block = m_head_blocks[chain_id];
                        // get my demand
                        std::set<sha256_hash> demand_block_hash_set;
                        auto &best_vote = m_best_votes[chain_id];
                        // voting demand block first
                        if (is_empty_chain(chain_id)) {
                            if (!best_vote.empty()) {
                                log("INFO chain[%s] request best vote block[%s]",
                                    aux::toHex(chain_id).c_str(), aux::toHex(best_vote.block_hash().to_string()).c_str());
                                demand_block_hash_set.insert(best_vote.block_hash());
                            }
                        } else {
                            // not empty chain

                            if (!best_vote.empty()) {
                                // check if best vote match main chain block
                                auto hash = m_repository->get_main_chain_block_hash_by_number(chain_id,
                                                                                              best_vote.block_number());
                                if (hash != best_vote.block_hash()) {
                                    // if not match, request blocks on best vote branch
                                    auto previous_hash = best_vote.block_hash();
                                    while (true) {
                                        // search until found absent or fork point block
                                        auto blk = get_block_from_cache_or_db(chain_id, previous_hash);
                                        if (blk.empty()) {
                                            log("INFO chain[%s] Cannot find demanding block[%s] in db/cache",
                                                aux::toHex(chain_id).c_str(),
                                                aux::toHex(previous_hash.to_string()).c_str());
                                            demand_block_hash_set.insert(previous_hash);
                                            break;
                                        } else {
                                            auto main_chain_hash = m_repository->get_main_chain_block_hash_by_number(
                                                    chain_id, blk.block_number());
                                            if (main_chain_hash == blk.sha256()) {
                                                break;
                                            }
                                            previous_hash = blk.previous_block_hash();
                                        }
                                    }
                                } else {
                                    // find out the most difficult chain
                                    auto &acl = m_access_list[chain_id];
                                    auto it = acl.end();
                                    std::uint64_t max_difficulty = 0;
                                    for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                        if (!iter->second.m_head_block.empty() &&
                                            iter->second.m_head_block.cumulative_difficulty() > max_difficulty) {
                                            max_difficulty = iter->second.m_head_block.cumulative_difficulty();
                                            it = iter;
                                        }
                                    }

                                    if (max_difficulty > head_block.cumulative_difficulty() && it != acl.end()) {
                                        // find absent block
                                        auto b = it->second.m_head_block;
                                        auto peer = it->first;
                                        auto previous_hash = b.previous_block_hash();
                                        while (true) {
                                            // search until found absent or fork point block
                                            b = get_block_from_cache_or_db(chain_id, previous_hash);
                                            if (b.empty()) {
                                                log("INFO: ----chain[%s] Cannot find demanding block hash[%s] in db/cache",
                                                    aux::toHex(chain_id).c_str(),
                                                    aux::toHex(previous_hash.to_string()).c_str());

                                                if (it->second.m_requests_time.find(std::make_unique<common::block_request_entry>(chain_id, previous_hash)) == it->second.m_requests_time.end()) {
                                                    common::block_request_entry blockRequestEntry(chain_id,
                                                                                                  previous_hash);
                                                    common::entry_task task(common::block_request_entry::data_type_id,
                                                                            peer, blockRequestEntry.get_entry());
                                                    add_entry_task_to_queue(chain_id, task);

                                                    it->second.m_requests_time[std::make_unique<common::block_request_entry>(chain_id, previous_hash)] = now;
                                                }

                                                break;
                                            } else {
                                                auto main_chain_hash = m_repository->get_main_chain_block_hash_by_number(
                                                        chain_id, b.block_number());
                                                if (main_chain_hash == b.sha256()) {
                                                    break;
                                                }
//                                                log("INFO: ----chain[%s] Got block [%s] in local",
//                                                    aux::toHex(chain_id).c_str(), b.to_string().c_str());
                                                previous_hash = b.previous_block_hash();
                                            }
                                        }
                                    }
                                }
                            } else {
                                // not empty chain, but no best vote
                                // find out the most difficult chain
                                auto &acl = m_access_list[chain_id];
                                auto it = acl.end();
                                std::uint64_t max_difficulty = 0;
                                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                    if (!iter->second.m_head_block.empty() &&
                                        iter->second.m_head_block.cumulative_difficulty() > max_difficulty) {
                                        max_difficulty = iter->second.m_head_block.cumulative_difficulty();
                                        it = iter;
                                    }
                                }

                                if (max_difficulty > head_block.cumulative_difficulty() && it != acl.end()) {
                                    // find absent block
                                    auto b = it->second.m_head_block;
                                    auto peer = it->first;
                                    auto previous_hash = b.previous_block_hash();
                                    while (true) {
                                        // search until found absent or fork point block
                                        b = get_block_from_cache_or_db(chain_id, previous_hash);
                                        if (b.empty()) {
                                            log("INFO: chain[%s] Cannot find demanding block hash[%s] in db/cache",
                                                aux::toHex(chain_id).c_str(),
                                                aux::toHex(previous_hash.to_string()).c_str());

                                            if (it->second.m_requests_time.find(std::make_unique<common::block_request_entry>(chain_id, previous_hash)) == it->second.m_requests_time.end()) {
                                                common::block_request_entry blockRequestEntry(chain_id, previous_hash);
                                                common::entry_task task(common::block_request_entry::data_type_id,
                                                                        peer, blockRequestEntry.get_entry());
                                                add_entry_task_to_queue(chain_id, task);

                                                it->second.m_requests_time[std::make_unique<common::block_request_entry>(chain_id, previous_hash)] = now;
                                            }

                                            break;
                                        } else {
                                            auto main_chain_hash = m_repository->get_main_chain_block_hash_by_number(
                                                    chain_id, b.block_number());
                                            if (main_chain_hash == b.sha256()) {
                                                break;
                                            }
//                                            log("INFO: ----chain[%s] Got block [%s] in local",
//                                                aux::toHex(chain_id).c_str(), b.to_string().c_str());
                                            previous_hash = b.previous_block_hash();
                                        }
                                    }
                                }
                            }

                            // if sync no completed, request tail block too
                            if (!is_sync_completed(chain_id)) {
                                auto &tail_block = m_tail_blocks[chain_id];
                                if (!tail_block.empty()) {
                                    log("INFO: Demanding tail hash[%s].", aux::toHex(tail_block.previous_block_hash()).c_str());
                                    demand_block_hash_set.insert(tail_block.previous_block_hash());
                                }
                            }
                        }

                        for (auto const &hash: demand_block_hash_set) {
                            // todo: check if in acl or requested before
                            auto &acl = m_access_list[chain_id];
                            auto max_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  > max_it->second.m_score) {
                                    max_it = iter;
                                }
                            }
                            log("INFO: ----------------chain[%s] request block hash[%s]",
                                aux::toHex(chain_id).c_str(),
                                aux::toHex(hash.to_string()).c_str());

                            if (max_it != acl.end()) {
                                auto& peer = max_it->first;
                                if (max_it->second.m_requests_time.find(std::make_unique<common::block_request_entry>(chain_id, hash)) == max_it->second.m_requests_time.end()) {
                                    common::block_request_entry blockRequestEntry(chain_id, hash);
                                    common::entry_task task(common::block_request_entry::data_type_id, peer,
                                                            blockRequestEntry.get_entry());
                                    add_entry_task_to_queue(chain_id, task);

                                    max_it->second.m_requests_time[std::make_unique<common::block_request_entry>(chain_id, hash)] = now;
                                }
                            } else {
                                log("INFO: ACL is empty, no peer to request.");
                            }
                        }
                    }
                }
            }

            if (!m_tasks.empty()) {
                auto &task = m_tasks.front();
                log("-----send task id[%ld] to peer[%s], entry[%s]", task.m_data_type_id,
                    aux::toHex(task.m_peer.bytes).c_str(), task.m_entry.to_string(true).c_str());
                if (task.m_peer.is_all_zeros()) {
                    auto &acl = m_access_list[chain_id];
                    auto p = acl.begin();
                    for (int i = 0; i < 3 && p != acl.end(); i++, p++) {
                        auto &peer = p->first;
                        send_to(chain_id, peer, task.m_entry);
                    }
                } else {
//                        if (now > m_last_visiting_time[chain_id][it->m_peer] + 1000) {
                    send_to(chain_id, task.m_peer, task.m_entry);

//                            m_last_visiting_time[chain_id][it->m_peer] = now;
//                        }
                }

                m_tasks_set.erase(task);
                m_tasks.pop();
            }
            log("-----------block chain tasks size:%lu", m_tasks.size());

            if (!m_chains.empty()) {
                int interval = 500 / m_chains.size();
                if (m_tasks_set.size() < 5 && m_refresh_time < interval) {
                    m_refresh_time = interval;
                }
            } else {
                m_refresh_time = 2000;
            }

            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(std::bind(&blockchain::refresh_timeout, self(), _1));
        } catch (std::exception &e) {
            log("Exception init [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    void blockchain::refresh_count_votes(const error_code &e) {

    }

    void blockchain::count_votes(const error_code &e, const aux::bytes &chain_id) {
        log("INFO: chain[%s] start to count votes", aux::toHex(chain_id).c_str());
        if (e) {
            log("INFO: chain[%s] error code[%d]: %s", aux::toHex(chain_id).c_str(), e.value(), e.message().c_str());
        }
        if (e || m_stop) return;

        try {
            // count votes
            log("INFO: chain[%s] count votes", aux::toHex(chain_id).c_str());
            refresh_vote(chain_id);
        } catch (std::exception &e) {
            log("Exception vote [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }

        log("INFO: chain[%s] stop to count votes", aux::toHex(chain_id).c_str());

        m_chain_status[chain_id] = MINING;
    }

//    void blockchain::refresh_vote_timeout(const error_code &e) {
//        if (e || m_stop) return;
//
//        try {
//            // refresh all chain votes
//            for (auto const& chain_id: m_chains) {
//                refresh_vote(chain_id);
//            }
//
//            m_vote_timer.expires_after(seconds(DEFAULT_BLOCK_TIME));
//            m_vote_timer.async_wait(std::bind(&blockchain::refresh_vote_timeout, self(), _1));
//        } catch (std::exception &e) {
//            log("Exception vote [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
//        }
//    }

    void blockchain::refresh_tx_timeout(const error_code &e) {
        if (e || m_stop) return;

        try {
            // refresh all chain votes
            for (auto const& chain_id: m_chains) {
                auto tx = m_tx_pools[chain_id].get_best_transaction();
                if (!tx.empty()) {
                    common::transaction_entry txEntry(tx);
                    common::entry_task task(common::transaction_entry::data_type_id, txEntry.get_entry());
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
        if (m_tasks_set.find(task) != m_tasks_set.end())
            return;

        if (m_tasks_set.size() > blockchain_max_task_size) {
            m_tasks_set.erase(m_tasks.front());
            m_tasks.pop();
        }

//        if (!task.m_peer.is_all_zeros()) {
//            auto &peer = task.m_peer;
//            auto type_id = task.m_data_type_id;
//            auto &acl = m_access_list[chain_id];
//            auto it = acl.find(peer);
//            if (it != acl.end()) {
//                if (it->second.m_requests_time.find(type_id) != it->second.m_requests_time.end()) {
//                    // already in request
//                    return;
//                }
//            }
//        }

        m_tasks.push(task);
        m_tasks_set.insert(task);
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
            auto now = get_total_milliseconds();
            if (now < m_priority_chain.second) {
                srand(now);
                auto i = rand() % 10;
                if (i < 3) {
                    return m_priority_chain.first;
                }
            }

            srand(now);
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
                        log("INFO chain[%s] 1. Cannot find block[%s] in db",
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
//            log("INFO: chain id[%s] generation signature[%s], base target[%lu], hit[%lu]",
//                aux::toHex(chain_id).c_str(), aux::toHex(genSig.to_string()).c_str(), base_target, hit);

            std::int64_t now = get_total_milliseconds() / 1000; // second
            if (now >= head_block.timestamp() + interval) {
//                log("1-----------------------------------hit:%lu, base target:%lu, interval:%lu", hit, base_target, interval);
                transaction tx;
                if (is_sync_completed(chain_id)) {
                    tx = m_tx_pools[chain_id].get_best_transaction();
                }

                auto cumulative_difficulty = consensus::calculate_cumulative_difficulty(head_block.cumulative_difficulty(), base_target);

                std::set<dht::public_key> peers;
                peers.insert(*pk);
                if (!tx.empty()) {
                    if (tx.type() == tx_type::type_transfer) {
                        peers.insert(tx.sender());
                        peers.insert(tx.receiver());
                    } else if (tx.type() == tx_type::type_note) {
                        peers.insert(tx.sender());
                    }
                }

                std::map<dht::public_key, std::int64_t> peers_balance;
                std::map<dht::public_key, std::int64_t> peers_nonce;
                std::map<dht::public_key, std::int64_t> peers_note_timestamp;
                for (auto const& peer: peers) {
                    auto peer_account = m_repository->get_account(chain_id, peer);
                    peers_balance[peer] = peer_account.balance();
                    peers_nonce[peer] = peer_account.nonce();
                    peers_note_timestamp[peer] = peer_account.note_timestamp();
                }

                if (!tx.empty()) {
                    // adjust state
                    // miner earns fee
                    peers_balance[*pk] += tx.fee();
                    if (tx.type() == tx_type::type_transfer) {
                        // receiver balance + amount
                        peers_balance[tx.receiver()] += tx.amount();
                        // sender balance - cost(fee + amount)
                        peers_balance[tx.sender()] -= tx.cost();
                        // sender nonce+1
                        peers_nonce[tx.sender()] += 1;
                    } else if (tx.type() == tx_type::type_note) {
                        // sender balance - fee
                        peers_balance[tx.sender()] -= tx.fee();
                        peers_note_timestamp[tx.sender()] = tx.timestamp();
                    } else {
                        return b;
                    }
                }

                auto ep = m_ses.external_udp_endpoint();
                if (ep.port() != 0) {
                    b = block(chain_id, block_version::block_version1, (head_block.timestamp() + interval),
                              head_block.block_number() + 1, head_block.sha256(), base_target, cumulative_difficulty,
                              genSig, tx, *pk, peers_balance[*pk], peers_nonce[*pk], peers_note_timestamp[*pk],
                              peers_balance[tx.sender()], peers_nonce[tx.sender()], peers_note_timestamp[tx.sender()],
                              peers_balance[tx.receiver()], peers_nonce[tx.receiver()], peers_note_timestamp[tx.receiver()], ep);
                } else {
                    b = block(chain_id, block_version::block_version1, (head_block.timestamp() + interval),
                              head_block.block_number() + 1, head_block.sha256(), base_target, cumulative_difficulty,
                              genSig, tx, *pk, peers_balance[*pk], peers_nonce[*pk], peers_note_timestamp[*pk],
                              peers_balance[tx.sender()], peers_nonce[tx.sender()], peers_note_timestamp[tx.sender()],
                              peers_balance[tx.receiver()], peers_nonce[tx.receiver()], peers_note_timestamp[tx.receiver()]);
                }

                b.sign(*pk, *sk);
            } else {
                log("INFO: chain id[%s] left time[%ld]s", aux::toHex(chain_id).c_str(), head_block.timestamp() + interval - now);
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
                    log("INFO chain[%s] 2. Cannot find block[%s] in db, previous_block[%s]",
                        aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str(), previous_block.to_string().c_str());
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

        std::set<dht::public_key> peers = b.get_block_peers();
        std::map<dht::public_key, std::int64_t> peers_balance;
        std::map<dht::public_key, std::int64_t> peers_nonce;
        std::map<dht::public_key, std::int64_t> peers_note_timestamp;
        for (auto const& peer: peers) {
            auto peer_account = m_repository->get_account(chain_id, peer);
            peers_balance[peer] = peer_account.balance();
            peers_nonce[peer] = peer_account.nonce();
            peers_note_timestamp[peer] = peer_account.note_timestamp();
        }

        auto const& tx = b.tx();
        if (!tx.empty()) {
            // adjust state
            // miner earns fee
            peers_balance[b.miner()] += tx.fee();
            if (tx.type() == tx_type::type_transfer) {
                // receiver balance + amount
                peers_balance[tx.receiver()] += tx.amount();
                // sender balance - cost(fee + amount)
                peers_balance[tx.sender()] -= tx.cost();
                // sender nonce+1
                peers_nonce[tx.sender()] += 1;
            } else if (tx.type() == tx_type::type_note) {
                // sender balance - fee
                peers_balance[tx.sender()] -= tx.fee();
                peers_note_timestamp[tx.sender()] = tx.timestamp();
            }
        }

        if (peers_balance[b.miner()] != b.miner_balance() || peers_nonce[b.miner()] != b.miner_nonce() ||
            peers_note_timestamp[b.miner()] != b.miner_note_timestamp() || peers_balance[b.tx().sender()] != b.sender_balance() ||
            peers_nonce[b.tx().sender()] != b.sender_nonce() || peers_note_timestamp[b.tx().sender()] != b.sender_note_timestamp() ||
            peers_balance[b.tx().receiver()] != b.receiver_balance() || peers_nonce[b.tx().receiver()] != b.receiver_nonce() ||
            peers_note_timestamp[b.tx().receiver()] != b.receiver_note_timestamp()) {
            log("INFO chain[%s] block[%s] state error!", aux::toHex(chain_id).c_str(), b.to_string().c_str());
            return FAIL;
        }

        return SUCCESS;
    }

//    void blockchain::try_to_update_consensus_point_block(const aux::bytes &chain_id) {
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
//    }

    void blockchain::try_to_update_voting_point_block(const aux::bytes &chain_id) {
        auto& head_block = m_head_blocks[chain_id];

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

                auto tail_block = m_tail_blocks[chain_id];
                // seek tail block
                while (b.timestamp() - tail_block.timestamp() >= CHAIN_EPOCH_TIME) {

                    // get next main chain block to be expired one by one
                    auto tail_next_block = track->get_main_chain_block_by_number(chain_id, tail_block.block_number() + 1);

                    if (b.timestamp() - tail_next_block.timestamp() >= CHAIN_EPOCH_TIME) {
                        if (!track->expire_block(tail_block)) {
                            log("INFO chain[%s] expire block[%s] fail",
                                aux::toHex(chain_id).c_str(), aux::toHex(tail_block.sha256().to_string()).c_str());
                            return FAIL;
                        }

                        // chain changed, re-check block peer in pool
                        auto tail_peers = tail_block.get_block_peers();
                        peers.insert(tail_peers.begin(), tail_peers.end());

                        // move to next block
                        tail_block = tail_next_block;

                        // set new tail
                        track->set_tail_block_hash(chain_id, tail_block.sha256());
                    } else {
                        break;
                    }
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

            if (m_head_blocks[chain_id].timestamp() - m_tail_blocks[chain_id].timestamp() < CHAIN_EPOCH_TIME &&
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

//    bool blockchain::is_voting_point_immutable(const aux::bytes &chain_id) {
//        // check if best vote and voting point block match, true if matched, false otherwise
//        auto &best_vote = m_best_votes[chain_id];
//        auto &voting_point_block = m_voting_point_blocks[chain_id];
//        if (voting_point_block.empty())
//            return false;
//        if (!best_vote.empty() && best_vote.block_hash() != voting_point_block.sha256())
//            return false;
//
//        return true;
//    }

    bool blockchain::is_sync_completed(const aux::bytes &chain_id) {
        auto &head_block = m_head_blocks[chain_id];
        auto &tail_block = m_tail_blocks[chain_id];

        if (head_block.empty() || tail_block.empty())
            return false;

        // if block number<=0, previous hash is all zeros, sync is completed
        if (tail_block.block_number() <= 0 && tail_block.previous_block_hash().is_all_zeros())
            return true;

        // if chain length = effective block number, sync is completed
        if (head_block.timestamp() - tail_block.timestamp() >= CHAIN_EPOCH_TIME)
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

    bool blockchain::is_peer_in_acl(const aux::bytes &chain_id, const dht::public_key &peer) {
        auto &acl = m_access_list[chain_id];
        return acl.find(peer) != acl.end();
    }

    bool blockchain::is_peer_banned(const aux::bytes &chain_id, const dht::public_key &peer) {
        auto now = get_total_milliseconds();

        auto &ban_list = m_ban_list[chain_id];
        auto it_ban = ban_list.find(peer);
        return it_ban != ban_list.end() && now < it_ban->second.m_free_time;
    }

    void blockchain::try_to_kick_out_of_ban_list(const aux::bytes &chain_id, const dht::public_key &peer) {
        m_ban_list[chain_id].erase(peer);
    }

    void blockchain::ban_peer(const aux::bytes &chain_id, const dht::public_key &peer) {
        auto now = get_total_milliseconds();
        auto &ban_list = m_ban_list[chain_id];
        auto it = ban_list.find(peer);
        if (it != ban_list.end()) {
            it->second.increase_ban_times();
            auto ban_time = blockchain_min_ban_time * it->second.m_ban_times;
            if (ban_time > blockchain_max_ban_time) {
                ban_time = blockchain_max_ban_time;
            }
            it->second.set_free_time(now + ban_time);
        } else {
            ban_list[peer] = ban_info();
            auto ban_time = blockchain_min_ban_time * ban_list[peer].m_ban_times;
            if (ban_time > blockchain_max_ban_time) {
                ban_time = blockchain_max_ban_time;
            }
            ban_list[peer].set_free_time(now + ban_time);
        }
    }

    void blockchain::add_if_peer_not_in_acl(const aux::bytes &chain_id, const dht::public_key &peer) {
        auto &acl = m_access_list[chain_id];
        if (acl.find(peer) == acl.end()) {
            acl[peer] = peer_info();
        }
    }

    void blockchain::increase_peer_score(const aux::bytes &chain_id, const dht::public_key &peer, int score) {
        auto &acl = m_access_list[chain_id];
        auto size = acl.size();
        auto it = acl.find(peer);
        if (it != acl.end()) {
            // in acl
            it->second.m_score = std::min(it->second.m_score + score, 100);
        } else {
            if (is_peer_banned(chain_id, peer)) {
                // TODO: decrease ban time?
                return;
            }

            if (size >= blockchain_acl_max_peers) {
                // find out min score peer
                auto min_it = acl.begin();
                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                    if (iter->second.m_score  < min_it->second.m_score) {
                        min_it = iter;
                    }
                }

                if (min_it->second.m_score < peer_info().m_score) {
                    // replace min score peer with new one
                    acl.erase(min_it);
                    acl[peer] = peer_info();
                }
            } else {
                acl[peer] = peer_info();
            }
        }
    }

    void blockchain::decrease_peer_score(const aux::bytes &chain_id, const dht::public_key &peer, int score) {
        auto &acl = m_access_list[chain_id];
//        auto size = acl.size();
        auto it = acl.find(peer);
        if (it != acl.end()) {
            // in acl
            it->second.m_score = it->second.m_score - score;
        } else {
            if (is_peer_banned(chain_id, peer)) {
                // TODO: increase ban time?
                return;
            }
        }
    }

    block blockchain::get_block_from_cache_or_db(const aux::bytes &chain_id, const sha256_hash &hash) {
        auto &block_map = m_blocks[chain_id];
        auto it = block_map.find(hash);
        if (it != block_map.end()) {
            if (!it->second.empty()) {
                return it->second;
            } else {
                block_map.erase(it);
            }
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

        auto const& head_block = m_head_blocks[chain_id];

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
                return FAIL;
            }

            rollback_blocks.push_back(main_chain_block);

            auto previous_hash = main_chain_block.previous_block_hash();
            main_chain_block = m_repository->get_block_by_hash(previous_hash);
            if (main_chain_block.empty()) {
                log("INFO chain[%s] 3. Cannot find block[%s] in db",
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
                log("INFO chain[%s] 4. Cannot find block[%s]",
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
                log("INFO chain[%s] 5. Cannot find block[%s]",
                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                return MISSING;
            }
        }
//        log("----2. main chain block:%s, reference block:%s", main_chain_block.to_string().c_str(), reference_block.to_string().c_str());

        // reference block is fork point block
        connect_blocks.push_back(reference_block);

        std::set<dht::public_key> peers;

        auto track = m_repository->start_tracking();

        auto tail_block = m_tail_blocks[chain_id];
        bool tail_missing = false;
        // Rollback blocks
        for (auto &blk: rollback_blocks) {
            if (!track->rollback_block(blk)) {
                log("INFO chain[%s] rollback block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                return FAIL;
            }

//            if (!tail_missing && !tail_block.previous_block_hash().is_all_zeros()) {
//                // in order to maintain the effective length of the chain,
//                // re-connect old tail block when rollback a head block
//                // if tail missing, block verification will be ignored
//                auto previous_block = track->get_block_by_hash(tail_block.previous_block_hash());
//                if (!previous_block.empty()) {
//                    tail_block = previous_block;
//                    if (!track->connect_tail_block(previous_block)) {
//                        log("INFO chain[%s] connect tail block[%s] fail",
//                            aux::toHex(chain_id).c_str(), aux::toHex(previous_block.sha256().to_string()).c_str());
//                        return FAIL;
//                    }
//
//                    // chain changed, re-check tx pool
//                    auto tail_peers = tail_block.get_block_peers();
//                    peers.insert(tail_peers.begin(), tail_peers.end());
//                } else {
//                    tail_missing = true;
//                }
//            }

            // chain changed, re-check tx pool
            auto block_peers = blk.get_block_peers();
            peers.insert(block_peers.begin(), block_peers.end());
        }

        // seek tail block
        while (head_block.timestamp() - tail_block.timestamp() < CHAIN_EPOCH_TIME && !tail_block.previous_block_hash().is_all_zeros()) {

            // get previous block
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

//            // seek tail block
//            while (blk.block_number() - tail_block.block_number() > EFFECTIVE_BLOCK_NUMBER) {
//                if (!track->expire_block(tail_block)) {
//                    log("INFO chain[%s] expire block[%s] fail",
//                        aux::toHex(chain_id).c_str(), aux::toHex(tail_block.sha256().to_string()).c_str());
//                    return FAIL;
//                }
//                // get previous main chain block to be expired one by one
//                tail_block = track->get_main_chain_block_by_number(chain_id, tail_block.block_number() + 1);
//
//                // chain changed, re-check tx pool
//                auto tail_peers = tail_block.get_block_peers();
//                peers.insert(tail_peers.begin(), tail_peers.end());
//            }

            auto block_peers = blk.get_block_peers();
            peers.insert(block_peers.begin(), block_peers.end());
        }

        // seek tail block
        while (target.timestamp() - tail_block.timestamp() >= CHAIN_EPOCH_TIME) {

            // get next main chain block to be expired one by one
            auto tail_next_block = track->get_main_chain_block_by_number(chain_id, tail_block.block_number() + 1);

            if (target.timestamp() - tail_next_block.timestamp() >= CHAIN_EPOCH_TIME) {
                if (!track->expire_block(tail_block)) {
                    log("INFO chain[%s] expire block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(tail_block.sha256().to_string()).c_str());
                    return FAIL;
                }

                // chain changed, re-check block peer in pool
                auto tail_peers = tail_block.get_block_peers();
                peers.insert(tail_peers.begin(), tail_peers.end());

                // move to next block
                tail_block = tail_next_block;
            } else {
                break;
            }
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
        for (auto i = connect_blocks.size(); i > 1; i--) {
            m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(connect_blocks[i - 2]);
        }
//        m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(target);
        m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(tail_block);
        m_ses.alerts().emplace_alert<blockchain_fork_point_block_alert>(reference_block);

        // chain changed, re-check tx pool
        m_tx_pools[chain_id].recheck_account_txs(peers);

        // re-locate consensus point block
        try_to_update_voting_point_block(chain_id);

        return SUCCESS;
    }

    namespace {
        bool sort_votes(const vote &lhs, const vote &rhs) {
            if (lhs.count() < rhs.count())
                return false;
            if (rhs.count() < lhs.count())
                return true;
            if (lhs.cumulative_difficulty() < rhs.cumulative_difficulty())
                return false;
            if (rhs.cumulative_difficulty() < lhs.cumulative_difficulty())
                return true;
            if (lhs.block_number() < rhs.block_number())
                return true;
            if (rhs.block_number() < lhs.block_number())
                return false;

            return lhs.block_hash() < rhs.block_hash();
        }
    }

    void blockchain::refresh_vote(const aux::bytes &chain_id) {
        std::set<vote> votes;
        auto & peer_votes = m_votes[chain_id];

        // vote for myself
        if (is_sync_completed(chain_id)) {
            auto &voting_point_block = m_voting_point_blocks[chain_id];
            peer_votes[*m_ses.pubkey()] = vote(voting_point_block.sha256(), voting_point_block.cumulative_difficulty(), voting_point_block.block_number());
        }

        // count votes
        for (auto const& v: peer_votes) {
            auto it = votes.find(v.second);
            if (it != votes.end()) {
                auto cv = *it;
                cv.vote_up();
                votes.erase(it);
                votes.insert(cv);
            } else {
                votes.insert(v.second);
            }
        }

        std::set<vote, decltype(sort_votes)*> sorted_votes(votes.begin(), votes.end(), sort_votes);

//        vote best_vote;
//        // if no voting result or best vote count is 1, use local voting point block
//        if ((votes.empty() || votes.rbegin()->count() == 1) && is_sync_completed(chain_id)) {
//            auto &voting_point_block = m_voting_point_blocks[chain_id];
//            best_vote = vote(voting_point_block.sha256(), voting_point_block.block_number());
//        } else {
//            if (!votes.empty()) {
//                // use the best vote
//                best_vote = *votes.rbegin();
//            }
//        }

        if (!sorted_votes.empty()) {
            m_best_votes[chain_id] = *sorted_votes.begin();
            log("INFO: chain[%s] best vote[%s]",
                aux::toHex(chain_id).c_str(), sorted_votes.begin()->to_string().c_str());
        }


        for (auto const &sorted_vote: sorted_votes) {
            log("INFO: sorted vote:%s", sorted_vote.to_string().c_str());
        }

        // select top three votes
        std::vector<vote> top_three_votes;
        int i = 0;
        for (const auto & sorted_vote : sorted_votes) {
            if (i >= 3)
                break;

            log("INFO chain[%s] top three vote[%s]",
                aux::toHex(chain_id).c_str(), sorted_vote.to_string().c_str());

            top_three_votes.push_back(sorted_vote);
            i++;
        }

        if (!top_three_votes.empty()) {
            m_ses.alerts().emplace_alert<blockchain_top_three_votes_alert>(chain_id, top_three_votes);
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
                                        std::set<transaction> &missing_txs) {
        // 如果对方没有信息，则本地消息全为缺失消息
        if (hash_prefix_array.empty()) {
            log("INFO: Hash prefix array is empty");
            missing_txs.insert(txs.begin(), txs.end());
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
                        missing_txs.insert(txs[j - 1]);
                    }
                    i--;
                    j--;
                } else if (1 == operations[i][j]) {
                    // 如果是插入操作，则将target对应的插入消息加入列表
                    // 注意由于消息是按照时间戳从小到大排列，如果缺第一个，并且此时双方满载，则判定为被挤出去而产生的差异，并非真的缺少
                    if (1 != j || targetLength != blockchain_max_tx_list_size ||
                        sourceLength != blockchain_max_tx_list_size) {
                        missing_txs.insert(txs[j - 1]);

                        // 如果是插入操作，则将邻近哈希前缀一样的消息也当作缺失的消息
                        auto k = j - 1;
                        while (k + 1 < targetLength && target[k] == target[k + 1]) {
                            missing_txs.insert(txs[k + 1]);
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

    namespace {
        void send_call_back(entry const& e, int n) {

        }
    }

    void blockchain::send_to(const aux::bytes &chain_id, const dht::public_key &peer, const entry &data) {
//        dht::public_key * pk = m_ses.pubkey();
//        dht::secret_key * sk = m_ses.serkey();
//
//        auto salt = make_salt(chain_id);
//
//        log("INFO: Send to peer[%s], salt[%s], data[%s]", aux::toHex(peer.bytes).c_str(),
//            aux::toHex(salt).c_str(), data.to_string().c_str());

        m_ses.dht()->send(peer, data, 1, 3, 3, send_call_back);
//        dht_put_mutable_item(pk->bytes, std::bind(&put_mutable_data, _1, _2, _3, _4
//                , pk->bytes, sk->bytes, data), salt, peer);
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

        std::string data(TAU_CHAIN_ID.begin(), TAU_CHAIN_ID.end());
        auto genSig = dht::item_target_id(data);

        auto ep = m_ses.external_udp_endpoint();

        for (auto const &act: TAU_CHAIN_GENESIS_ACCOUNT) {
            auto miner = act;
            peers.insert(miner);

            block b;
            if (ep.port() != 0) {
                b = block(TAU_CHAIN_ID, block_version::block_version1, TAU_CHAIN_GENESIS_TIMESTAMP, block_number,
                                previous_hash, GENESIS_BASE_TARGET, 0, genSig, transaction(),
                                miner, GENESIS_BLOCK_BALANCE, 0, 0, 0,
                                0, 0, 0, 0, 0, ep);
            } else {
                b = block(TAU_CHAIN_ID, block_version::block_version1, TAU_CHAIN_GENESIS_TIMESTAMP, block_number,
                                previous_hash,
                                GENESIS_BASE_TARGET, 0, genSig, transaction(), miner, GENESIS_BLOCK_BALANCE,
                                0, 0, 0, 0, 0, 0, 0, 0);
            }
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

    bool blockchain::createNewCommunity(const aux::bytes &chain_id, const std::map<dht::public_key, account> &accounts) {
        return createNewCommunity(chain_id, accounts, transaction());
    }

    bool blockchain::createNewCommunity(const aux::bytes &chain_id, const std::map<dht::public_key, account>& accounts, const transaction& tx) {
        std::int64_t now = get_total_milliseconds() / 1000; // second

        dht::secret_key *sk = m_ses.serkey();
        dht::public_key *pk = m_ses.pubkey();

        std::int64_t base_target = GENESIS_BASE_TARGET;
        std::string data(pk->bytes.begin(), pk->bytes.end());
        data.insert(data.end(), chain_id.begin(), chain_id.end());
        auto genSig = dht::item_target_id(data);

        std::int64_t size = accounts.size();
        std::int64_t block_number = -1 * (size > MAX_NEGATIVE_BLOCK_SIZE ? MAX_NEGATIVE_BLOCK_SIZE : size);
        sha256_hash previous_hash;

        std::set<dht::public_key> peers;
        std::vector<block> blocks;
        std::int64_t total_balance = 0;
        int i = 0;

        auto ep = m_ses.external_udp_endpoint();

        for (auto const &act: accounts) {
            auto miner = act.first;
            peers.insert(miner);
            std::int64_t miner_balance = act.second.balance();
            total_balance += miner_balance;

            block b;
            if (ep.port() != 0) {
                b = block(chain_id, block_version::block_version1, now, block_number, previous_hash,
                                base_target, 0, genSig, transaction(), miner, miner_balance,
                                0, 0, 0, 0, 0, 0, 0, 0, ep);
            } else {
                b = block(chain_id, block_version::block_version1, now, block_number, previous_hash,
                                base_target, 0, genSig, transaction(), miner, miner_balance,
                                0, 0, 0, 0, 0, 0, 0, 0);
            }
            b.sign(*pk, *sk);

            blocks.push_back(b);

            previous_hash = b.sha256();
            block_number++;

            i++;
            if (i >= MAX_NEGATIVE_BLOCK_SIZE)
                break;
        }

        std::int64_t genesis_balance = GENESIS_BLOCK_BALANCE > total_balance ? GENESIS_BLOCK_BALANCE - total_balance : 0;

        block b;
        if (ep.port() != 0) {
            b = block(chain_id, block_version::block_version1, now, block_number, previous_hash,
                            base_target, 0, genSig, tx, *pk, genesis_balance,
                            0, 0, 0, 0, 0, 0, 0, 0, ep);
        } else {
            b = block(chain_id, block_version::block_version1, now, block_number, previous_hash,
                            base_target, 0, genSig, tx, *pk, genesis_balance,
                            0, 0, 0, 0, 0, 0, 0, 0);
        }

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
                if (!tx.verify_signature())
                    return false;

                auto &chain_id = tx.chain_id();

                common::transaction_entry txEntry(tx);

                auto &acl = m_access_list[chain_id];
                for (auto const &item: acl) {
                    auto &peer = item.first;
                    common::entry_task task(common::transaction_entry::data_type_id, peer, txEntry.get_entry());
                    add_entry_task_to_queue(chain_id, task);
                }

                m_tx_pools[chain_id].add_tx(tx);
                return true;
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

    std::int64_t blockchain::getMiningTime(const aux::bytes &chain_id) {
        dht::public_key *pk = m_ses.pubkey();

        auto &head_block = m_head_blocks[chain_id];
        if (!head_block.empty()) {
            if (head_block.block_number() < 0) {
                return -1;
            }

            block ancestor;
            auto previous_hash = head_block.previous_block_hash();
            if (head_block.block_number() > 3) {
                int i = 3;
                while (i > 0) {
                    ancestor = m_repository->get_block_by_hash(previous_hash);
                    if (ancestor.empty()) {
                        return -1;
                    }
                    previous_hash = ancestor.previous_block_hash();

                    i--;
                }
            }

            auto base_target = consensus::calculate_required_base_target(head_block, ancestor);
            std::int64_t power = m_repository->get_effective_power(chain_id, *pk);
            log("INFO: chain id[%s] public key[%s] power[%ld]", aux::toHex(chain_id).c_str(), aux::toHex(pk->bytes).c_str(), power);
            if (power <= 0) {
                return -1;
            }
            auto genSig = consensus::calculate_generation_signature(head_block.generation_signature(), *pk);
            auto hit = consensus::calculate_random_hit(genSig);
            auto interval = static_cast<std::int64_t>(consensus::calculate_mining_time_interval(hit, base_target, power));

            std::int64_t now = get_total_milliseconds() / 1000; // second
            if (now >= head_block.timestamp() + interval) {
                return 0;
            } else {
                return head_block.timestamp() + interval - now;
            }
        }

        return -1;
    }

    void blockchain::set_blockchain_loop_interval(int milliseconds) {
        log("INFO: Set block chain loop interval:%d(ms)", milliseconds);
        m_refresh_time = milliseconds;
    }

    void blockchain::set_priority_chain(const aux::bytes &chain_id) {
        m_priority_chain = std::make_pair(chain_id, get_total_milliseconds() + blockchain_max_focus_time);
    }

    void blockchain::unset_priority_chain() {
        m_priority_chain = std::make_pair(aux::bytes(), 0);
    }

    void blockchain::on_dht_relay(dht::public_key const& peer, entry const& payload) {

        if(payload.type() != entry::dictionary_t){
            log("ERROR: relay data not dict. to string: %s", payload.to_string().c_str());
            return;
        }
        // construct mutable data wrapper from entry
        auto now = get_total_milliseconds();

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
        if (auto* p = const_cast<entry *>(payload.find_key(common::entry_type)))
        {
            auto data_type_id = p->integer();
            log("---------------data type id:%ld from peer[%s] entry[%s]", data_type_id,
                aux::toHex(peer.bytes).c_str(), payload.to_string(true).c_str());
            switch (data_type_id) {
                case common::block_request_entry::data_type_id: {
                    common::block_request_entry blk_request_entry(payload);
                    auto &chain_id = blk_request_entry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    auto &acl = m_access_list[chain_id];
                    auto it = acl.find(peer);
                    if (it != acl.end()) {
                        auto itor = it->second.m_peer_requests_time.find(std::make_unique<common::block_request_entry>(payload));
                        if (itor != it->second.m_peer_requests_time.end()) {
                            if (now > itor->second + blockchain_same_response_interval) {
                                it->second.m_peer_requests_time.erase(itor);
                            } else {
                                log("INFO: The same request from the same peer in 3s.");
                                break;
                            }
                        } else {
                            it->second.m_peer_requests_time.emplace(std::make_unique<common::block_request_entry>(payload), now);
                        }
                        it->second.m_score -= 3;
                        it->second.m_last_seen = now;
                    } else {
                        if (acl.size() >= blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            if (min_it->second.m_score < peer_info().m_score) {
                                // replace min score peer with new one
                                acl.erase(min_it);
                                acl[peer] = peer_info(now);
                                acl[peer].m_peer_requests_time.emplace(std::make_unique<common::block_request_entry>(payload), now);
                            } else {
                                log("INFO: Too many peers in acl to response.");
                                break;
                            }
                        } else {
                            acl[peer] = peer_info(now);
                            acl[peer].m_peer_requests_time.emplace(std::make_unique<common::block_request_entry>(payload), now);
                        }
                    }

                    auto blk = m_repository->get_block_by_hash(blk_request_entry.m_hash);

                    if (!blk.empty()) {
//                            auto &chain_id = blk.chain_id();
                        common::block_entry blockEntry(blk);
//                            send_to(blk.chain_id(), peer, blockEntry.get_entry());
                        common::entry_task task(common::block_entry::data_type_id, peer, blockEntry.get_entry());
//                            m_tasks[blk.chain_id()].insert(task);
                        add_entry_task_to_queue(chain_id, task);
                    } else {
                        log("INFO: Cannot get block[%s] in local", aux::toHex(blk_request_entry.m_hash).c_str());
                    }

                    break;
                }
                case common::block_entry::data_type_id: {
                    common::block_entry blk_entry(payload);
                    auto &chain_id = blk_entry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    // TODO: validate timestamp etc. ?
                    if (!blk_entry.m_blk.empty()) {
                        auto &acl = m_access_list[chain_id];
                        auto it = acl.find(peer);
                        if (it != acl.end()) {
                            it->second.m_score += 3;
                            if (it->second.m_score > 100) {
                                it->second.m_score = 100;
                            }
                            it->second.m_requests_time.erase(std::make_unique<common::block_request_entry>(chain_id, blk_entry.m_blk.sha256()));
                            it->second.m_last_seen = now;
                        } else {
                            if (acl.size() >= blockchain_acl_max_peers) {
                                // find out min score peer
                                auto min_it = acl.begin();
                                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                    if (iter->second.m_score  < min_it->second.m_score) {
                                        min_it = iter;
                                    }
                                }

                                if (min_it->second.m_score < peer_info().m_score) {
                                    // replace min score peer with new one
                                    acl.erase(min_it);
                                    acl[peer] = peer_info(now);
                                }
                            } else {
                                acl[peer] = peer_info(now);
                            }
                        }

                        log("INFO: Got block[%s].", blk_entry.m_blk.to_string().c_str());

                        m_blocks[chain_id][blk_entry.m_blk.sha256()] = blk_entry.m_blk;

                        m_ses.alerts().emplace_alert<blockchain_syncing_block_alert>(peer, blk_entry.m_blk);

                        // notify ui tx from block
                        if (!blk_entry.m_blk.tx().empty()) {
                            m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(blk_entry.m_blk.tx());
                        }

                        try_to_update_visiting_peer(chain_id, peer);
                    }

                    break;
                }
                case common::tx_pool_entry::data_type_id: {
                    common::tx_pool_entry txPoolEntry(payload);
                    auto &chain_id = txPoolEntry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    auto &acl = m_access_list[chain_id];
                    auto it = acl.find(peer);
                    if (it != acl.end()) {
                        it->second.m_requests_time.erase(std::make_unique<common::tx_pool_entry>(chain_id));
                        auto itor = it->second.m_peer_requests_time.find(std::make_unique<common::tx_pool_entry>(payload));
                        if (itor != it->second.m_peer_requests_time.end()) {
                            if (now > itor->second + blockchain_same_response_interval) {
                                it->second.m_peer_requests_time.erase(itor);
                            } else {
                                log("INFO: The same request from the same peer in 3s.");
                                break;
                            }
                        } else {
                            it->second.m_peer_requests_time.emplace(std::make_unique<common::tx_pool_entry>(payload), now);
                        }
                        it->second.m_score -= 3;
                        it->second.m_last_seen = now;
                        it->second.m_tx_pool_sync_done = true;
                    } else {
                        if (acl.size() >= blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            if (min_it->second.m_score < peer_info().m_score) {
                                // replace min score peer with new one
                                acl.erase(min_it);
                                acl[peer] = peer_info(now);
                                acl[peer].m_tx_pool_sync_done = true;
                                acl[peer].m_peer_requests_time.emplace(std::make_unique<common::tx_pool_entry>(payload), now);
                            } else {
                                log("INFO: Too many peers in acl to response.");
                                break;
                            }
                        } else {
                            acl[peer] = peer_info(now);
                            acl[peer].m_tx_pool_sync_done = true;
                            acl[peer].m_peer_requests_time.emplace(std::make_unique<common::tx_pool_entry>(payload), now);
                        }
                    }

                    auto fee_pool_txs = m_tx_pools[chain_id].get_top_ten_fee_transactions();
                    auto time_pool_txs = m_tx_pools[chain_id].get_top_ten_timestamp_transactions();
                    std::set<transaction> missing_txs;
                    find_best_solution(fee_pool_txs, txPoolEntry.m_fee_pooL_levenshtein_array, missing_txs);
                    find_best_solution(time_pool_txs, txPoolEntry.m_time_pooL_levenshtein_array, missing_txs);

                    for (auto const& tx: missing_txs) {
                        common::transaction_entry txEntry(tx);
                        common::entry_task task(common::transaction_entry::data_type_id, peer, txEntry.get_entry());
                        add_entry_task_to_queue(chain_id, task);
                    }
                    common::tx_pool_entry replyEntry(chain_id,
                                                       m_tx_pools[chain_id].get_hash_prefix_array_by_fee(),
                                                       m_tx_pools[chain_id].get_hash_prefix_array_by_timestamp());
                    common::entry_task task(common::tx_pool_entry::data_type_id, peer, replyEntry.get_entry());
                    add_entry_task_to_queue(chain_id, task);

                    try_to_update_visiting_peer(chain_id, peer);

                    break;
                }
                case common::transaction_request_entry::data_type_id: {
                    common::transaction_request_entry tx_request_entry(payload);
                    auto &chain_id = tx_request_entry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    auto &acl = m_access_list[chain_id];
                    auto it = acl.find(peer);
                    if (it != acl.end()) {
                        auto itor = it->second.m_peer_requests_time.find(std::make_unique<common::transaction_request_entry>(payload));
                        if (itor != it->second.m_peer_requests_time.end()) {
                            if (now > itor->second + blockchain_same_response_interval) {
                                it->second.m_peer_requests_time.erase(itor);
                            } else {
                                log("INFO: The same request from the same peer in 3s.");
                                break;
                            }
                        } else {
                            it->second.m_peer_requests_time.emplace(std::make_unique<common::transaction_request_entry>(payload), now);
                        }
                        it->second.m_score -= 3;
                        it->second.m_last_seen = now;
                    } else {
                        if (acl.size() >= blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            if (min_it->second.m_score < peer_info().m_score) {
                                // replace min score peer with new one
                                acl.erase(min_it);
                                acl[peer] = peer_info(now);
                                acl[peer].m_peer_requests_time.emplace(std::make_unique<common::transaction_request_entry>(payload), now);
                            } else {
                                log("INFO: Too many peers in acl to response.");
                                break;
                            }
                        } else {
                            acl[peer] = peer_info(now);
                            acl[peer].m_peer_requests_time.emplace(std::make_unique<common::transaction_request_entry>(payload), now);
                        }
                    }

                    try_to_update_visiting_peer(chain_id, peer);

                    break;
                }
                case common::transaction_entry::data_type_id: {
                    common::transaction_entry tx_entry(payload);
                    auto &chain_id = tx_entry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    if (!tx_entry.m_tx.empty()) {
                        auto &tx = tx_entry.m_tx;

                        auto &acl = m_access_list[chain_id];
                        auto it = acl.find(peer);
                        if (it != acl.end()) {
                            it->second.m_score += 3;
                            if (it->second.m_score > 100) {
                                it->second.m_score = 100;
                            }
                            it->second.m_requests_time.erase(std::make_unique<common::transaction_request_entry>(chain_id, tx_entry.m_tx.sha256()));
                            it->second.m_last_seen = now;
                        } else {
                            if (acl.size() >= blockchain_acl_max_peers) {
                                // find out min score peer
                                auto min_it = acl.begin();
                                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                    if (iter->second.m_score  < min_it->second.m_score) {
                                        min_it = iter;
                                    }
                                }

                                if (min_it->second.m_score < peer_info().m_score) {
                                    // replace min score peer with new one
                                    acl.erase(min_it);
                                    acl[peer] = peer_info(now);
                                }
                            } else {
                                acl[peer] = peer_info(now);
                            }
                        }

                        log("INFO: Got transaction[%s].", tx.to_string().c_str());

                        if (tx.sender() == peer) {
                            common::transaction_reply_entry txReplyEntry(chain_id, tx.sha256());
                            common::entry_task task(common::transaction_reply_entry::data_type_id, txReplyEntry.get_entry());
                            add_entry_task_to_queue(chain_id, task);
                        }

                        auto &pool = m_tx_pools[chain_id];
                        if (pool.add_tx(tx)) {
                            common::transaction_entry txEntry(tx);
                            common::entry_task task(common::transaction_entry::data_type_id, txEntry.get_entry());
                            add_entry_task_to_queue(chain_id, task);

                            m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(tx_entry.m_tx);
                        }

                        try_to_update_visiting_peer(chain_id, peer);
                    }

                    break;
                }
                case common::vote_request_entry::data_type_id: {
                    common::vote_request_entry voteRequestEntry(payload);
                    auto &chain_id = voteRequestEntry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    auto &acl = m_access_list[chain_id];
                    auto it = acl.find(peer);
                    if (it != acl.end()) {
                        auto itor = it->second.m_peer_requests_time.find(std::make_unique<common::vote_request_entry>(payload));
                        if (itor != it->second.m_peer_requests_time.end()) {
                            if (now > itor->second + blockchain_same_response_interval) {
                                it->second.m_peer_requests_time.erase(itor);
                            } else {
                                log("INFO: The same request from the same peer in 3s.");
                                break;
                            }
                        } else {
                            it->second.m_peer_requests_time.emplace(std::make_unique<common::vote_request_entry>(payload), now);
                        }
                        it->second.m_score -= 3;
                        it->second.m_last_seen = now;
                    } else {
                        if (acl.size() >= blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            if (min_it->second.m_score < peer_info().m_score) {
                                // replace min score peer with new one
                                acl.erase(min_it);
                                acl[peer] = peer_info(now);
                                acl[peer].m_peer_requests_time.emplace(std::make_unique<common::vote_request_entry>(payload), now);
                            }
                        } else {
                            acl[peer] = peer_info(now);
                            acl[peer].m_peer_requests_time.emplace(std::make_unique<common::vote_request_entry>(payload), now);
                        }
                    }

                    // vote for voting point
                    auto &voting_point_block = m_voting_point_blocks[chain_id];
                    if (is_sync_completed(chain_id) && !voting_point_block.empty()) {
                        common::vote_entry voteEntry(chain_id,
                                                     vote(voting_point_block.sha256(), voting_point_block.cumulative_difficulty(), voting_point_block.block_number()));
//                            send_to(chain_id, peer, voteEntry.get_entry());
                        common::entry_task task(common::vote_entry::data_type_id, peer, voteEntry.get_entry());
//                            m_tasks[chain_id].insert(task);
                        add_entry_task_to_queue(chain_id, task);
                    }

                    try_to_update_visiting_peer(chain_id, peer);

                    break;
                }
                case common::vote_entry::data_type_id: {
                    common::vote_entry voteEntry(payload);
                    auto &chain_id = voteEntry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    auto &acl = m_access_list[chain_id];
                    auto it = acl.find(peer);
                    if (it != acl.end()) {
                        it->second.m_score += 3;
                        if (it->second.m_score > 100) {
                            it->second.m_score = 100;
                        }
                        it->second.m_requests_time.erase(std::make_unique<common::vote_request_entry>(chain_id));
                        it->second.m_last_seen = now;
                    } else {
                        if (acl.size() >= blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            if (min_it->second.m_score < peer_info().m_score) {
                                // replace min score peer with new one
                                acl.erase(min_it);
                                acl[peer] = peer_info(now);
                            }
                        } else {
                            acl[peer] = peer_info(now);
                        }
                    }

                    log("INFO: chain[%s] valid vote[%s]",
                        aux::toHex(chain_id).c_str(), voteEntry.m_vote.to_string().c_str());
                    m_votes[chain_id][peer] = voteEntry.m_vote;

                    try_to_update_visiting_peer(chain_id, peer);

                    break;
                }
                case common::head_block_request_entry::data_type_id: {
                    common::head_block_request_entry headBlockRequestEntry(payload);
                    auto &chain_id = headBlockRequestEntry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    auto &acl = m_access_list[chain_id];
                    auto it = acl.find(peer);
                    if (it != acl.end()) {
                        auto itor = it->second.m_peer_requests_time.find(std::make_unique<common::head_block_request_entry>(payload));
                        if (itor != it->second.m_peer_requests_time.end()) {
                            if (now > itor->second + blockchain_same_response_interval) {
                                it->second.m_peer_requests_time.erase(itor);
                            } else {
                                log("INFO: The same request from the same peer in 3s.");
                                break;
                            }
                        } else {
                            it->second.m_peer_requests_time.emplace(std::make_unique<common::head_block_request_entry>(payload), now);
                        }
                        it->second.m_score -= 3;
                        it->second.m_last_seen = now;
                    } else {
                        if (acl.size() >= blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            if (min_it->second.m_score < peer_info().m_score) {
                                // replace min score peer with new one
                                acl.erase(min_it);
                                acl[peer] = peer_info(now);
                                acl[peer].m_peer_requests_time.emplace(std::make_unique<common::head_block_request_entry>(payload), now);
                            } else {
                                log("INFO: Too many peers in acl to response.");
                                break;
                            }
                        } else {
                            acl[peer] = peer_info(now);
                            acl[peer].m_peer_requests_time.emplace(std::make_unique<common::head_block_request_entry>(payload), now);
                        }
                    }

                    auto &blk = m_head_blocks[chain_id];

                    if (!blk.empty()) {
                        common::head_block_entry blockEntry(blk);
//                            send_to(chain_id, peer, blockEntry.get_entry());
                        common::entry_task task(common::head_block_entry::data_type_id, peer, blockEntry.get_entry());
//                            m_tasks[blk.chain_id()].insert(task);
                        add_entry_task_to_queue(chain_id, task);
                    } else {
                        log("INFO: Cannot get head block in local");
                    }

                    try_to_update_visiting_peer(chain_id, peer);

                    break;
                }
                case common::head_block_entry::data_type_id: {
                    common::head_block_entry blk_entry(payload);

                    // TODO: validate timestamp etc. ?
                    if (!blk_entry.m_blk.empty()) {
                        auto &chain_id = blk_entry.m_blk.chain_id();

                        try_to_kick_out_of_ban_list(chain_id, peer);

                        auto &acl = m_access_list[chain_id];
                        auto it = acl.find(peer);
                        if (it != acl.end()) {
                            it->second.m_stage = NORMAL;
                            if (it->second.m_head_block.empty() || blk_entry.m_blk.cumulative_difficulty() > it->second.m_head_block.cumulative_difficulty()) {
                                it->second.m_score += 5;
                            } else {
                                it->second.m_score += 3;
                            }
                            if (it->second.m_score > 100) {
                                it->second.m_score = 100;
                            }
                            it->second.m_head_block = blk_entry.m_blk;
                            it->second.m_requests_time.erase(std::make_unique<common::head_block_request_entry>(chain_id));
                            it->second.m_last_seen = now;
                        } else {
                            if (acl.size() >= blockchain_acl_max_peers) {
                                // find out min score peer
                                auto min_it = acl.begin();
                                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                    if (iter->second.m_score  < min_it->second.m_score) {
                                        min_it = iter;
                                    }
                                }

                                if (min_it->second.m_score < peer_info().m_score) {
                                    // replace min score peer with new one
                                    acl.erase(min_it);
                                    acl[peer] = peer_info(NORMAL, blk_entry.m_blk, now);
                                }
                            } else {
                                acl[peer] = peer_info(NORMAL, blk_entry.m_blk, now);
                            }
                        }

                        log("INFO: Got head block, hash[%s].", aux::toHex(blk_entry.m_blk.sha256().to_string()).c_str());

                        m_blocks[chain_id][blk_entry.m_blk.sha256()] = blk_entry.m_blk;

                        if (blk_entry.m_blk.cumulative_difficulty() > m_head_blocks[chain_id].cumulative_difficulty()) {
                            m_ses.alerts().emplace_alert<blockchain_syncing_head_block_alert>(peer, blk_entry.m_blk);
                        }

                        // notify ui tx from block
                        if (!blk_entry.m_blk.tx().empty()) {
                            m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(blk_entry.m_blk.tx());
                        }

                        try_to_update_visiting_peer(chain_id, peer);
                    }

                    break;
                }
                case common::state_request_entry::data_type_id: {
                    common::state_request_entry stateRequestEntry(payload);
                    auto &chain_id = stateRequestEntry.m_chain_id;

                    log("INFO: chain[%s] request state", aux::toHex(chain_id).c_str());

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    auto &acl = m_access_list[chain_id];
                    auto it = acl.find(peer);
                    if (it != acl.end()) {
                        auto itor = it->second.m_peer_requests_time.find(std::make_unique<common::state_request_entry>(payload));
                        if (itor != it->second.m_peer_requests_time.end()) {
                            if (now > itor->second + blockchain_same_response_interval) {
                                it->second.m_peer_requests_time.erase(itor);
                            } else {
                                log("INFO: The same request from the same peer in 3s.");
                                break;
                            }
                        } else {
                            it->second.m_peer_requests_time.emplace(std::make_unique<common::state_request_entry>(payload), now);
                        }
                        it->second.m_score -= 3;
                        it->second.m_last_seen = now;
                    } else {
                        if (acl.size() >= blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            if (min_it->second.m_score < peer_info().m_score) {
                                // replace min score peer with new one
                                acl.erase(min_it);
                                acl[peer] = peer_info(now);
                                acl[peer].m_peer_requests_time.emplace(std::make_unique<common::state_request_entry>(payload), now);
                            } else {
                                log("INFO: Too many peers in acl to response.");
                                break;
                            }
                        } else {
                            acl[peer] = peer_info(now);
                            acl[peer].m_peer_requests_time.emplace(std::make_unique<common::state_request_entry>(payload), now);
                        }
                    }

                    auto act = m_repository->get_account(chain_id, peer);

                    if (!act.empty()) {
                        common::state_entry stateEntry(chain_id, act);
                        common::entry_task task(common::state_entry::data_type_id, peer, stateEntry.get_entry());
                        add_entry_task_to_queue(chain_id, task);
                    }

                    break;
                }
                case common::state_entry::data_type_id: {
                    common::state_entry stateEntry(payload);
                    auto &chain_id = stateEntry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    auto &acl = m_access_list[chain_id];
                    auto it = acl.find(peer);
                    if (it != acl.end()) {
                        it->second.m_score += 3;
                        if (it->second.m_score > 100) {
                            it->second.m_score = 100;
                        }
                        it->second.m_requests_time.erase(std::make_unique<common::state_request_entry>(chain_id));
                        it->second.m_last_seen = now;
                    } else {
                        if (acl.size() >= blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            if (min_it->second.m_score < peer_info().m_score) {
                                // replace min score peer with new one
                                acl.erase(min_it);
                                acl[peer] = peer_info(now);
                            }
                        } else {
                            acl[peer] = peer_info(now);
                        }
                    }

                    log("INFO: chain[%s] Got state",
                        aux::toHex(chain_id).c_str());

                    auto &act = stateEntry.m_act;

                    if (!act.empty()) {
                        m_ses.alerts().emplace_alert<blockchain_state_alert>(chain_id, act);
                    }

                    break;
                }
                case common::transaction_reply_entry::data_type_id: {
                    common::transaction_reply_entry txReplyEntry(payload);
                    auto &chain_id = txReplyEntry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    auto &acl = m_access_list[chain_id];
                    auto it = acl.find(peer);
                    if (it != acl.end()) {
                        it->second.m_score += 3;
                        if (it->second.m_score > 100) {
                            it->second.m_score = 100;
                        }
                        it->second.m_last_seen = now;
                    } else {
                        if (acl.size() >= blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            if (min_it->second.m_score < peer_info().m_score) {
                                // replace min score peer with new one
                                acl.erase(min_it);
                                acl[peer] = peer_info(now);
                            }
                        } else {
                            acl[peer] = peer_info(now);
                        }
                    }

                    log("INFO: chain[%s] Got tx reply", aux::toHex(txReplyEntry.m_hash).c_str());

                    if (!txReplyEntry.m_hash.is_all_zeros()) {
                        m_ses.alerts().emplace_alert<blockchain_tx_confirmation_alert>(chain_id, peer, txReplyEntry.m_hash);
                    }

                    break;
                }
                case common::ping_entry::data_type_id: {
                    common::ping_entry pingEntry(payload);
                    auto &chain_id = pingEntry.m_chain_id;

                    try_to_kick_out_of_ban_list(chain_id, peer);

                    auto &acl = m_access_list[chain_id];
                    auto it = acl.find(peer);
                    if (it != acl.end()) {
                        it->second.m_last_seen = now;
                    } else {
                        if (acl.size() >= blockchain_acl_max_peers) {
                            // find out min score peer
                            auto min_it = acl.begin();
                            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
                                if (iter->second.m_score  < min_it->second.m_score) {
                                    min_it = iter;
                                }
                            }

                            if (min_it->second.m_score < peer_info().m_score) {
                                // replace min score peer with new one
                                acl.erase(min_it);
                                acl[peer] = peer_info(now);
                            }
                        } else {
                            acl[peer] = peer_info(now);
                        }
                    }

                    log("INFO: chain[%s] Got ping", aux::toHex(chain_id).c_str());

                    break;
                }
                default: {
                }
            }
        }
    }

}
