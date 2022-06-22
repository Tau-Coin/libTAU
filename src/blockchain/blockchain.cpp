/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <cinttypes> // for PRId64 et.al.
#include <utility>

#include "libTAU/blockchain/blockchain.hpp"
#include "libTAU/blockchain/consensus.hpp"
#include "libTAU/common/entry_type.hpp"
#include "libTAU/kademlia/dht_tracker.hpp"
#include "libTAU/kademlia/ed25519.hpp"


using namespace std::placeholders;

namespace libTAU::blockchain {
    using namespace aux;

    bool blockchain::init() {
        try {
            // get all chains
            auto chains = m_repository->get_all_chains();
            m_chains.insert(m_chains.end(), chains.begin(), chains.end());

            // load all chains
//            bool has_tau = false;
//            for (auto const &chain_id: m_chains) {
//                if (chain_id == TAU_CHAIN_ID) {
//                    has_tau = true;
//                }
//                load_chain(chain_id);
//            }

            // create tau chain
//            if (!has_tau) {
//                create_TAU_chain();
//            }
        } catch (std::exception &e) {
            log(LOG_ERR, "Exception init [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            return false;
        }

        return true;
    }

    bool blockchain::start()
    {
        log(LOG_INFO, "INFO: Start BlockChain...");
        if (!init()) {
            log(LOG_ERR, "ERROR: Init fail.");
            return false;
        }

        m_stop = false;

        // start all chains
        for (auto const &chain_id: m_chains) {
            start_chain(chain_id);
        }

        m_refresh_timer.expires_after(milliseconds(200));
        m_refresh_timer.async_wait(std::bind(&blockchain::refresh_timeout, self(), _1));
        return true;
    }

    bool blockchain::stop()
    {
        for (auto& item: m_gossip_peers) {
            auto const& chain_id = item.first;
            auto const& gossip_peers = item.second;
            if (!gossip_peers.empty()) {
                m_repository->delete_all_peers_in_gossip_peer_db(chain_id);
                for (auto const&peer: gossip_peers) {
                    m_repository->add_peer_in_gossip_peer_db(chain_id, peer);
                }
            }
        }

        m_stop = true;

        m_refresh_timer.cancel();

        for (auto& timer: m_chain_timers) {
            timer.second.cancel();
        }

        for (auto& timer: m_chain_status_timers) {
            timer.second.cancel();
        }

        clear_all_cache();

        log(LOG_INFO, "INFO: Stop BlockChain...");

        return true;
    }

    void blockchain::account_changed() {
        log(LOG_INFO, "INFO: Change account..");

        m_access_list.clear();
        m_ban_list.clear();
    }

    void blockchain::on_pause() {
        log(LOG_INFO, "Block chain is on pause");
        m_pause = true;
    }

    void blockchain::on_resume() {
        log(LOG_INFO, "Block chain is on resume");
        m_pause = false;

        m_refresh_timer.cancel();

        for (auto& timer: m_chain_timers) {
            timer.second.cancel();
        }
    }

    void blockchain::request_state(const aux::bytes &chain_id) {
        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it == m_chains.end()) {
            log(LOG_ERR, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
            return;
        }

        common::state_request_entry stateRequestEntry(chain_id);
        transfer_to_acl_peers(chain_id, stateRequestEntry.get_entry());
    }

    bool blockchain::followChain(const aux::bytes &chain_id, const std::set<dht::public_key>& peers) {
        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it != m_chains.end()) {
            log(LOG_INFO, "INFO: Already followed chain[%s]", aux::toHex(chain_id).c_str());
            return true;
        }

        if (!chain_id.empty()) {
            log(LOG_INFO, "INFO: Follow chain:%s", aux::toHex(chain_id).c_str());

            // create sqlite peer db
            if (!m_repository->create_peer_db(chain_id)) {
                log(LOG_ERR, "INFO: chain:%s, create peer db fail.", aux::toHex(chain_id).c_str());
            }
            if (!m_repository->create_gossip_peer_db(chain_id)) {
                log(LOG_ERR, "INFO: chain:%s, create gossip peer db fail.", aux::toHex(chain_id).c_str());
            }

            // add peer into db
            for (auto const &peer: peers) {
                log(LOG_INFO, "INFO: chain:%s, initial peer:%s", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                if (!m_repository->add_peer_in_peer_db(chain_id, peer)) {
                    log(LOG_ERR, "INFO: chain:%s, insert peer:%s fail in peer db.", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                }
                if (!m_repository->add_peer_in_gossip_peer_db(chain_id, peer)) {
                    log(LOG_ERR, "INFO: chain:%s, insert gossip peer:%s fail in gossip db.", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                }
            }

            // follow chain id in memory and db
            m_repository->add_new_chain(chain_id);
            m_chains.push_back(chain_id);

            // start chain
            start_chain(chain_id);

            return true;
        } else {
            return false;
        }
    }

    bool blockchain::add_new_bootstrap_peers(const aux::bytes &chain_id, const std::set<dht::public_key> &peers) {
        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return false;
        }

        // add peer into db
        for (auto const &peer: peers) {
            log(LOG_INFO, "INFO: chain:%s, add peer:%s", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
            if (!m_repository->add_peer_in_peer_db(chain_id, peer)) {
                log(LOG_ERR, "INFO: chain:%s, insert peer:%s fail in peer db.", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
            }
            if (!m_repository->add_peer_in_gossip_peer_db(chain_id, peer)) {
                log(LOG_ERR, "INFO: chain:%s, insert gossip peer:%s fail in gossip db.", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
            }
        }

        return true;
    }

    bool blockchain::unfollowChain(const aux::bytes &chain_id) {
        log(LOG_INFO, "INFO: Unfollow chain:%s", aux::toHex(chain_id).c_str());

        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it != m_chains.end()) {
            m_chains.erase(it);

            // remove chain id from db
            m_repository->delete_chain(chain_id);

            // cancel
            auto it_chain_timer = m_chain_timers.find(chain_id);
            if (it_chain_timer != m_chain_timers.end()) {
                it_chain_timer->second.cancel();
            }
            auto it_chain_status_timer = m_chain_status_timers.find(chain_id);
            if (it_chain_status_timer != m_chain_status_timers.end()) {
                it_chain_status_timer->second.cancel();
            }
            // remove chain cache
            clear_chain_cache(chain_id);
            // todo: clear data in db?
        }

        return true;
    }

    bool blockchain::load_chain(const aux::bytes &chain_id) {
        log(LOG_INFO, "INFO: load chain[%s]", aux::toHex(chain_id).c_str());

        // create vote timer
        m_chain_status_timers.emplace(chain_id, aux::deadline_timer(m_ioc));

        // create tx pool
        m_tx_pools[chain_id] = tx_pool(m_repository.get());

        // get gossip peers
        m_gossip_peers[chain_id] = m_repository->get_all_gossip_peers(chain_id);

        // load key point block in memory
        // load head/tail/consensus block
        auto head_block_hash = m_repository->get_head_block_hash(chain_id);
        auto tail_block_hash = m_repository->get_tail_block_hash(chain_id);
        auto consensus_point_block_hash = m_repository->get_consensus_point_block_hash(chain_id);
        log(LOG_INFO, "INFO chain id[%s], head block hash[%s], tail block hash[%s], consensus point block hash[%s]",
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
                log(LOG_INFO, "INFO: Head block: %s", head_block.to_string().c_str());
                log(LOG_INFO, "INFO: Tail block: %s", tail_block.to_string().c_str());
                log(LOG_INFO, "INFO: Consensus point block: %s", consensus_point_block.to_string().c_str());

                // try to update voting point block
                try_to_update_voting_point_block(chain_id);
            }
        }

        return true;
    }

    bool blockchain::start_chain(const aux::bytes &chain_id) {
        log(LOG_INFO, "INFO: start chain[%s]", aux::toHex(chain_id).c_str());

        // create tx pool
        m_tx_pools[chain_id] = tx_pool(m_repository.get());

        // get gossip peers
        m_gossip_peers[chain_id] = m_repository->get_all_gossip_peers(chain_id);

        // load key point block in memory
        // load head/tail/consensus block
        auto head_block_hash = m_repository->get_head_block_hash(chain_id);
        auto tail_block_hash = m_repository->get_tail_block_hash(chain_id);
        auto consensus_point_block_hash = m_repository->get_consensus_point_block_hash(chain_id);
        log(LOG_INFO, "INFO chain id[%s], head block hash[%s], tail block hash[%s], consensus point block hash[%s]",
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
                log(LOG_INFO, "INFO: Head block: %s", head_block.to_string().c_str());
                log(LOG_INFO, "INFO: Tail block: %s", tail_block.to_string().c_str());
                log(LOG_INFO, "INFO: Consensus point block: %s", consensus_point_block.to_string().c_str());

                // try to update voting point block
                try_to_update_voting_point_block(chain_id);

                // try to clear outdated data in db
                try_to_clear_outdated_data_in_db(chain_id);
            }
        }

        // create chain status timer
        m_chain_status_timers.emplace(chain_id, aux::deadline_timer(m_ioc));
        // set chain status
        auto i = m_chain_status_timers.find(chain_id);
        if (i != m_chain_status_timers.end()) {
            i->second.expires_after(milliseconds (100));
            i->second.async_wait(std::bind(&blockchain::refresh_chain_status, self(), _1, chain_id));
        }

        // create chain timer
        m_chain_timers.emplace(chain_id, aux::deadline_timer(m_ioc));
        // start mining
        auto it = m_chain_timers.find(chain_id);
        if (it != m_chain_timers.end()) {
            it->second.expires_after(milliseconds (150));
            it->second.async_wait(std::bind(&blockchain::refresh_mining_timeout, self(), _1, chain_id));
        }

        return true;
    }

    void blockchain::manage_peers_in_acl_ban_list(const aux::bytes &chain_id) {
        auto now = get_total_milliseconds();

        // calc score
        auto &acl = m_access_list[chain_id];
        for (auto &item: acl) {
            auto &requests_time = item.second.m_requests_time;
            for (auto it = requests_time.begin(); it != requests_time.end();) {
                if (now > it->second + blockchain_request_timeout) {
                    item.second.m_score = item.second.m_score - 8;
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
            if (it->second.m_score <= 0 ||
                (it->second.m_stage == NORMAL && now > it->second.m_last_seen + 210 * 1000)) {
                auto &ban_list = m_ban_list[chain_id];
                ban_list[it->first] = ban_info(now + blockchain_min_ban_time);

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
                if (iter->second.m_score < min_it->second.m_score) {
                    min_it = iter;
                }
            }

            acl.erase(min_it);
        }
    }

    void blockchain::add_and_access_peers_in_acl(const aux::bytes &chain_id) {
        auto now = get_total_milliseconds();

        auto &acl = m_access_list[chain_id];
        auto size = acl.size();
        if (size < blockchain_acl_min_peers) {
            std::set<dht::public_key> peers;
            for (auto i = blockchain_acl_min_peers - size; i > 0; i--) {
                auto peer = select_peer_randomly(chain_id);
//              log("INFO: Chain[%s] select peer[%s]", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                // if peer is not in acl, not been banned
                if (!peer.is_all_zeros() &&
                    acl.find(peer) == acl.end() & peer != *m_ses.pubkey()) {
                    auto &ban_list = m_ban_list[chain_id];
                    auto it = ban_list.find(peer);
                    if (it != ban_list.end()) {
                        if (it->second.m_free_time > now) {
                            // peer is still banned
//                          log("INFO: Chain[%s] peer[%s] is in ban list", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                            continue;
                        } else {
                            ban_list.erase(it);
                        }
                    }
                    peers.insert(peer);
                }
            }

            // all peers those added into acl should request head block
            for (auto const &peer: peers) {
                acl[peer] = peer_info();

                introduce_gossip_peers(chain_id, peer);
            }
        }

        // check if need to request on current stage
        for (auto &item: acl) {
            if (item.second.m_stage == HEAD_BLOCK) {
                if (item.second.m_requests_time.find(
                        std::make_unique<common::head_block_request_entry>(chain_id))
                    == item.second.m_requests_time.end()) {
                    common::head_block_request_entry headBlockRequestEntry(chain_id);
                    send_to(item.first, headBlockRequestEntry.get_entry());

                    item.second.m_requests_time[std::make_unique<common::head_block_request_entry>(chain_id)] = now;
                }
            } else if (item.second.m_stage == NORMAL) {
                if (!item.second.m_fee_tx_pool_sync_done && is_sync_completed(chain_id)) {
                    common::fee_tx_pool_entry feeTxPoolEntry(chain_id, m_tx_pools[chain_id].get_hash_prefix_array_by_fee());
                    send_to(item.first, feeTxPoolEntry.get_entry());

                    item.second.m_fee_tx_pool_sync_done = true;
                }
                if (!item.second.m_time_tx_pool_sync_done) {
                    common::time_tx_pool_entry txPoolEntry(chain_id, m_tx_pools[chain_id].get_hash_prefix_array_by_timestamp());
                    send_to(item.first, txPoolEntry.get_entry());

                    item.second.m_time_tx_pool_sync_done = true;
                }
                // ping every minute
                if (now > item.second.m_last_ping_time + 60 * 1000) {
                    common::ping_entry pingEntry(chain_id);
                    send_to(item.first, pingEntry.get_entry());

                    item.second.m_last_ping_time = now;
                }
            }
        }
    }

    std::int64_t blockchain::get_total_milliseconds() {
        return total_milliseconds(system_clock::now().time_since_epoch());
    }

    std::int64_t blockchain::get_total_microseconds() {
        return total_microseconds(system_clock::now().time_since_epoch());
    }

    void blockchain::clear_all_cache() {
        m_chains.clear();
        m_tx_pools.clear();
        m_chain_status.clear();
        m_chain_timers.clear();
        m_chain_status_timers.clear();
        m_access_list.clear();
        m_ban_list.clear();
//        m_blocks.clear();
        m_head_blocks.clear();
        m_tail_blocks.clear();
        m_consensus_point_blocks.clear();
        m_voting_point_blocks.clear();
        m_best_votes.clear();
        m_votes.clear();
        m_gossip_peers.clear();
    }

    void blockchain::clear_chain_cache(const aux::bytes &chain_id) {
//        m_chains.erase(chain_id);
        m_tx_pools[chain_id].clear();
        m_chain_status.erase(chain_id);
        m_chain_timers.erase(chain_id);
        m_chain_status_timers.erase(chain_id);
        m_access_list.erase(chain_id);
        m_ban_list.erase(chain_id);
//        m_blocks[chain_id].clear();
        m_head_blocks.erase(chain_id);
        m_tail_blocks.erase(chain_id);
        m_consensus_point_blocks.erase(chain_id);
        m_voting_point_blocks.erase(chain_id);
        m_best_votes.erase(chain_id);
        m_votes[chain_id].clear();
        m_gossip_peers[chain_id].clear();
    }

    void blockchain::try_to_clear_outdated_data_in_db(const aux::bytes &chain_id) {
        auto const& head_block = m_head_blocks[chain_id];
        if (!head_block.empty() && head_block.block_number() > OUTDATED_BLOCK_NUMBER) {
            // remove outdated data from db
            m_repository->delete_all_outdated_data(chain_id, head_block.block_number() - OUTDATED_BLOCK_NUMBER);
        }
    }


    void blockchain::refresh_timeout(const error_code &e) {
        if ((e.value() != 0 && e.value() != boost::asio::error::operation_aborted) || m_stop) return;

        try {
            if (e.value() != boost::asio::error::operation_aborted) {
                if (!m_pause) {
                    // 随机挑选一条
                    for (auto const &chain_id: m_chains) {
                        if (!chain_id.empty()) {
//                        log("INFO: Select chain:%s, status:%d", aux::toHex(chain_id).c_str(), m_chain_status[chain_id]);

                            // current time
                            auto now = get_total_milliseconds();

                            if (now > m_last_cache_gossip_peers_time[chain_id] + 6 * 60 * 60 * 1000) {
                                put_gossip_peers_to_cache(chain_id);
                                m_last_cache_gossip_peers_time[chain_id] = now;
                            }

                            // log
                            print_acl_ban_list_info(chain_id);

                            manage_peers_in_acl_ban_list(chain_id);

                            if (m_chain_status[chain_id] == MINE) {
                                add_and_access_peers_in_acl(chain_id);

                                if (!is_empty_chain(chain_id)) {
                                    // 1. try to sync block
                                    try_to_sync_block(chain_id);

                                    // 2. try to re-branch to a more difficult chain
                                    try_to_rebranch_to_most_difficult_chain(chain_id);

                                    // 3. try to re-branch to best vote
                                    try_to_rebranch_to_best_vote(chain_id);
                                }
                            }
                        }
                    }
                }
            }

            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(std::bind(&blockchain::refresh_timeout, self(), _1));
        } catch (std::exception &e) {
            log(LOG_ERR, "Exception init [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    void blockchain::reset_chain_status(const aux::bytes &chain_id) {
        m_chain_status[chain_id] = GET_GOSSIP_PEERS;
    }

    void blockchain::refresh_chain_status(const error_code &e, const aux::bytes &chain_id) {
        if ((e.value() != 0 && e.value() != boost::asio::error::operation_aborted) || m_stop) return;

        try {
            // reset chain status
            log(LOG_INFO, "INFO: reset chain[%s] status", aux::toHex(chain_id).c_str());
            reset_chain_status(chain_id);

            auto i = m_chain_status_timers.find(chain_id);
            if (i != m_chain_status_timers.end()) {
                i->second.expires_after(seconds(blockchain_status_reset_interval));
                i->second.async_wait(std::bind(&blockchain::refresh_chain_status, self(), _1, chain_id));
            }
        } catch (std::exception &e) {
            log(LOG_ERR, "Exception vote [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    void blockchain::refresh_mining_timeout(const error_code &e, const aux::bytes &chain_id) {
        if ((e.value() != 0 && e.value() != boost::asio::error::operation_aborted) || m_stop) {
            log(LOG_ERR, "ERROR: refresh_mining_timeout:%d", e.value());
            return;
        }

        try {
            log(LOG_INFO, "INFO: 1. Chain[%s] status[%d]", aux::toHex(chain_id).c_str(), m_chain_status[chain_id]);

            long refresh_time = DEFAULT_BLOCK_TIME * 1000;

            if (!m_pause) {
                // current time
                auto now = get_total_milliseconds();

                if (m_chain_status[chain_id] == GET_GOSSIP_PEERS) {
                    std::set<dht::public_key> peers;
                    for (int i = 0; i < 30; i++) {
                        auto peer = m_repository->get_peer_randomly(chain_id);
                        peers.insert(peer);
                    }

                    peers.erase(*m_ses.pubkey());

                    for (auto const &peer: peers) {
                        // get gossip peers
                        get_gossip_peers(chain_id, peer);
                    }

                    m_chain_status[chain_id] = COLLECT_GOSSIP_PEERS;

                    refresh_time = 3000;
                    m_collect_gossip_peers_time[chain_id] = now + refresh_time;
                } else if (m_chain_status[chain_id] == COLLECT_GOSSIP_PEERS) {
                    if (now + 200 >= m_collect_gossip_peers_time[chain_id]) {
                        m_chain_status[chain_id] = VOTE;
                    } else {
                        refresh_time = m_collect_gossip_peers_time[chain_id] - now;
                    }
                }

                if (m_chain_status[chain_id] == VOTE) {
                    std::set<dht::public_key> peers;
                    for (int i = 0; i < 30; i++) {
                        auto peer = m_repository->get_peer_randomly(chain_id);
                        peers.insert(peer);
                    }

                    auto size = peers.size();
                    if (size < 20) {
                        // vote with gossip peers
                        auto const &gossip_peers = m_gossip_peers[chain_id];
                        if (!gossip_peers.empty()) {
                            for (int k = 0; k < 20 - size; k++) {
                                srand(get_total_microseconds());
                                auto index = rand() % gossip_peers.size();

                                int i = 0;
                                for (const auto &gossip_peer : gossip_peers) {
                                    if (i == index) {
                                        peers.insert(gossip_peer);
                                        break;
                                    }
                                    i++;
                                }
                            }
                        }
                    }

                    peers.erase(*m_ses.pubkey());

                    for (auto const &peer: peers) {
                        // request vote
                        get_voting_block(chain_id, peer);
                    }

                    m_chain_status[chain_id] = COUNT_VOTES;
                    log(LOG_INFO, "INFO: 2. chain:%s vote status:%d, ready to count cotes",
                        aux::toHex(chain_id).c_str(), m_chain_status[chain_id]);

                    refresh_time = 3000;
                    m_count_votes_time[chain_id] = now + refresh_time;
                } else if (m_chain_status[chain_id] == COUNT_VOTES) {
                    if (now + 200 >= m_count_votes_time[chain_id]) {
                        count_votes(chain_id);

                        try_to_rebranch_to_best_vote(chain_id);

                        m_chain_status[chain_id] = MINE;
                    } else {
                        refresh_time = m_count_votes_time[chain_id] - now;
                    }
                }

                if (m_chain_status[chain_id] == MINE) {
                    // try to mine on the best chain
                    if (m_counters[counters::dht_nodes] > 0) {
                        if (!is_empty_chain(chain_id)) {
                            dht::secret_key *sk = m_ses.serkey();
                            dht::public_key *pk = m_ses.pubkey();

                            bool missing = false;
                            const auto &head_block = m_head_blocks[chain_id];

                            block ancestor;
                            auto previous_hash = head_block.previous_block_hash();
                            if (head_block.block_number() > 3) {
                                int i = 3;
                                while (i > 0) {
                                    ancestor = m_repository->get_block_by_hash(previous_hash);
                                    if (ancestor.empty()) {
                                        log(LOG_INFO, "INFO chain[%s] 1. Cannot find block[%s] in db",
                                            aux::toHex(chain_id).c_str(),
                                            aux::toHex(previous_hash.to_string()).c_str());
                                        missing = true;
                                        request_block(chain_id, previous_hash);
                                        break;
                                    }
                                    previous_hash = ancestor.previous_block_hash();

                                    i--;
                                }
                            }

                            if (!missing) {
                                auto base_target = consensus::calculate_required_base_target(head_block, ancestor);
                                std::int64_t power = m_repository->get_effective_power(chain_id, *pk);
                                log(LOG_INFO, "INFO: chain id[%s] public key[%s] power[%" PRId64 "]",
                                    aux::toHex(chain_id).c_str(),
                                    aux::toHex(pk->bytes).c_str(), power);
                                auto genSig = consensus::calculate_generation_signature(
                                        head_block.generation_signature(),
                                        *pk);
                                auto hit = consensus::calculate_random_hit(genSig);
                                auto interval = static_cast<std::int64_t>(consensus::calculate_mining_time_interval(hit,
                                                                                                                    base_target,
                                                                                                                    power));
                                log(LOG_INFO,
                                    "INFO: chain id[%s] generation signature[%s], base target[%" PRIu64 "], hit[%" PRIu64 "]",
                                    aux::toHex(chain_id).c_str(), aux::toHex(genSig.to_string()).c_str(), base_target,
                                    hit);

                                auto cumulative_difficulty = consensus::calculate_cumulative_difficulty(
                                        head_block.cumulative_difficulty(), base_target);

                                std::int64_t current_time = get_total_milliseconds() / 1000; // second
                                if (current_time >= head_block.timestamp() + interval) {
                                    transaction tx;
                                    if (is_sync_completed(chain_id)) {
                                        tx = m_tx_pools[chain_id].get_best_fee_transaction();

                                        if (tx.empty()) {
                                            tx = m_tx_pools[chain_id].get_latest_note_transaction();
                                        }
                                    } else {
                                        tx = m_tx_pools[chain_id].get_latest_note_transaction();
                                    }

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

                                    if (is_sync_completed(chain_id)) {
                                        for (auto const &peer: peers) {
                                            auto peer_account = m_repository->get_account(chain_id, peer);
                                            peers_balance[peer] = peer_account.balance();
                                            peers_nonce[peer] = peer_account.nonce();
                                        }

                                        if (!tx.empty()) {
                                            // adjust state
                                            if (tx.type() == tx_type::type_transfer) {
                                                // miner earns fee
                                                peers_balance[*pk] += tx.fee();
                                                // receiver balance + amount
                                                peers_balance[tx.receiver()] += tx.amount();
                                                // sender balance - cost(fee + amount)
                                                peers_balance[tx.sender()] -= tx.cost();
                                                // sender nonce+1
                                                peers_nonce[tx.sender()] += 1;
                                            }
                                        }
                                    }

                                    auto ep = m_ses.external_udp_endpoint();
                                    // mine block with current time instead of (head_block.timestamp() + interval)
                                    block b;
                                    if (ep.port() != 0) {
                                        b = block(chain_id, block_version::block_version1, current_time,
                                                  head_block.block_number() + 1, head_block.sha256(), base_target,
                                                  cumulative_difficulty,
                                                  genSig, tx, *pk, peers_balance[*pk], peers_nonce[*pk],
                                                  peers_balance[tx.sender()], peers_nonce[tx.sender()],
                                                  peers_balance[tx.receiver()], peers_nonce[tx.receiver()], ep);
                                    } else {
                                        b = block(chain_id, block_version::block_version1, current_time,
                                                  head_block.block_number() + 1, head_block.sha256(), base_target,
                                                  cumulative_difficulty,
                                                  genSig, tx, *pk, peers_balance[*pk], peers_nonce[*pk],
                                                  peers_balance[tx.sender()], peers_nonce[tx.sender()],
                                                  peers_balance[tx.receiver()], peers_nonce[tx.receiver()]);
                                    }

                                    b.sign(*pk, *sk);

                                    // process mined block
                                    log(LOG_INFO, "INFO chain[%s] process mined block[%s]",
                                        aux::toHex(chain_id).c_str(), b.to_string().c_str());

                                    process_block(chain_id, b);

                                    refresh_time = 100;
                                } else {
                                    log(LOG_INFO, "INFO: chain id[%s] left time[%" PRId64 "]s",
                                        aux::toHex(chain_id).c_str(), head_block.timestamp() + interval - current_time);
                                    refresh_time = (head_block.timestamp() + interval - current_time) * 1000;
                                }
                            }
                        } else {
                            // continue to vote if chain is empty
                            reset_chain_status(chain_id);

                            log(LOG_INFO, "Chain[%s] re-vote after 15s", aux::toHex(chain_id).c_str());
                            refresh_time = 15000;
                        }
                    } else {
                        log(LOG_INFO, "Chain[%s] stop mining", aux::toHex(chain_id).c_str());
                        refresh_time = 5000;
                    }
                }
            } else {
                log(LOG_INFO, "Block chain is paused.");
            }

            log(LOG_INFO, "refresh time:%ld ", refresh_time);
            auto it = m_chain_timers.find(chain_id);
            if (it != m_chain_timers.end()) {
                it->second.expires_after(milliseconds(refresh_time));
                it->second.async_wait(std::bind(&blockchain::refresh_mining_timeout, self(), _1, chain_id));
            }
        } catch (std::exception &e) {
            log(LOG_ERR, "Exception init [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    dht::public_key blockchain::select_peer_randomly(const aux::bytes &chain_id) {
        srand(get_total_microseconds());
        auto n = rand() % 10;
        auto& gossip_peers = m_gossip_peers[chain_id];
        if (gossip_peers.empty() || n < 9) {
            return m_repository->get_peer_randomly(chain_id);
        } else {
            srand(get_total_microseconds());
            auto index = rand() % gossip_peers.size();

            int i = 0;
            for (const auto & gossip_peer : gossip_peers) {
                if (i == index) {
                    return gossip_peer;
                }
                i++;
            }
        }

        return dht::public_key();
    }

    block blockchain::try_to_mine_block(const aux::bytes &chain_id) {
        dht::secret_key *sk = m_ses.serkey();
        dht::public_key *pk = m_ses.pubkey();

        block b;
        auto &head_block = m_head_blocks[chain_id];
        if (!head_block.empty()) {
            if (head_block.block_number() < 0) {
                log(LOG_INFO, "INFO chain[%s] Negative and genesis block cannot be mined", aux::toHex(chain_id).c_str());
                return b;
            }

            block ancestor;
            auto previous_hash = head_block.previous_block_hash();
            if (head_block.block_number() > 3) {
                int i = 3;
                while (i > 0) {
                    ancestor = m_repository->get_block_by_hash(previous_hash);
                    if (ancestor.empty()) {
                        log(LOG_INFO, "INFO chain[%s] 1. Cannot find block[%s] in db",
                            aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                        return b;
                    }
                    previous_hash = ancestor.previous_block_hash();

                    i--;
                }
            }

            auto base_target = consensus::calculate_required_base_target(head_block, ancestor);
            std::int64_t power = m_repository->get_effective_power(chain_id, *pk);
            auto genSig = consensus::calculate_generation_signature(head_block.generation_signature(), *pk);
            auto hit = consensus::calculate_random_hit(genSig);
            auto interval = static_cast<std::int64_t>(consensus::calculate_mining_time_interval(hit, base_target, power));
            log(LOG_INFO, "INFO: chain id[%s] generation signature[%s], base target[%" PRIu64 "], hit[%" PRIu64 "]",
                aux::toHex(chain_id).c_str(), aux::toHex(genSig.to_string()).c_str(), base_target, hit);

            auto cumulative_difficulty = consensus::calculate_cumulative_difficulty(head_block.cumulative_difficulty(), base_target);

            std::int64_t now = get_total_milliseconds() / 1000; // second
            if (now >= head_block.timestamp() + interval) {
                transaction tx;
                if (is_sync_completed(chain_id)) {
                    tx = m_tx_pools[chain_id].get_best_fee_transaction();

                    if (tx.empty()) {
                        tx = m_tx_pools[chain_id].get_latest_note_transaction();
                    }
                } else {
                    tx = m_tx_pools[chain_id].get_latest_note_transaction();
                }

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

                if (is_sync_completed(chain_id)) {
                    for (auto const &peer: peers) {
                        auto peer_account = m_repository->get_account(chain_id, peer);
                        peers_balance[peer] = peer_account.balance();
                        peers_nonce[peer] = peer_account.nonce();
                    }

                    if (!tx.empty()) {
                        // adjust state
                        if (tx.type() == tx_type::type_transfer) {
                            // miner earns fee
                            peers_balance[*pk] += tx.fee();
                            // receiver balance + amount
                            peers_balance[tx.receiver()] += tx.amount();
                            // sender balance - cost(fee + amount)
                            peers_balance[tx.sender()] -= tx.cost();
                            // sender nonce+1
                            peers_nonce[tx.sender()] += 1;
                        }
                    }
                }

                auto ep = m_ses.external_udp_endpoint();
                // mine block with current time instead of (head_block.timestamp() + interval)
                if (ep.port() != 0) {
                    b = block(chain_id, block_version::block_version1, now,
                              head_block.block_number() + 1, head_block.sha256(), base_target, cumulative_difficulty,
                              genSig, tx, *pk, peers_balance[*pk], peers_nonce[*pk],
                              peers_balance[tx.sender()], peers_nonce[tx.sender()],
                              peers_balance[tx.receiver()], peers_nonce[tx.receiver()], ep);
                } else {
                    b = block(chain_id, block_version::block_version1, now,
                              head_block.block_number() + 1, head_block.sha256(), base_target, cumulative_difficulty,
                              genSig, tx, *pk, peers_balance[*pk], peers_nonce[*pk],
                              peers_balance[tx.sender()], peers_nonce[tx.sender()],
                              peers_balance[tx.receiver()], peers_nonce[tx.receiver()]);
                }

                b.sign(*pk, *sk);
            }
        }

        return b;
    }

    RESULT blockchain::verify_block(const aux::bytes &chain_id, const block &b, const block &previous_block, repository *repo) {
        return SUCCESS;

        if (b.empty()) {
            log(LOG_ERR, "INFO chain[%s] block is empty", aux::toHex(chain_id).c_str());
            return FAIL;
        }

        if (previous_block.block_number() + 1 != b.block_number()) {
            log(LOG_ERR, "INFO chain[%s] block number error.", aux::toHex(chain_id).c_str());
            return FAIL;
        }

        if (b.block_number() <= 0) {
            log(LOG_INFO, "INFO chain[%s] Negative and genesis block is always true", aux::toHex(chain_id).c_str());
            return SUCCESS;
        }

        if (b.timestamp() <= previous_block.timestamp()) {
            log(LOG_ERR, "INFO chain[%s] block timestamp error.", aux::toHex(chain_id).c_str());
            return FAIL;
        }

        if (!b.verify_signature()) {
            log(LOG_ERR, "INFO chain[%s] block[%s] has bad signature",
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
                    log(LOG_INFO, "INFO chain[%s] 2. Cannot find block[%s] in db, previous_block[%s]",
                        aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str(), previous_block.to_string().c_str());
                    request_block(chain_id, previous_hash);
                    return MISSING;
                }
                previous_hash = ancestor.previous_block_hash();

                i--;
            }
        }

        auto base_target = consensus::calculate_required_base_target(previous_block, ancestor);
        std::int64_t power = repo->get_effective_power(chain_id, b.miner());

        log(LOG_INFO, "INFO chain[%s] Account[%s] power[%" PRId64 "] in db",aux::toHex(chain_id).c_str(), aux::toHex(b.miner().bytes).c_str(), power);

        auto genSig = consensus::calculate_generation_signature(previous_block.generation_signature(), b.miner());
        auto hit = consensus::calculate_random_hit(genSig);

        if (genSig != b.generation_signature()) {
            log(LOG_ERR, "ERROR chain[%s] generation signature[%s, %s] mismatch",
                aux::toHex(chain_id).c_str(), aux::toHex(genSig.to_string()).c_str(), aux::toHex(b.generation_signature().to_string()).c_str());
            return FAIL;
        }

        if (base_target != b.base_target()) {
            log(LOG_ERR, "ERROR chain[%s] base target[%" PRIu64 ", %" PRIu64 "] mismatch",
                aux::toHex(chain_id).c_str(), base_target, b.base_target());
            return FAIL;
        }

        auto cumulative_difficulty = consensus::calculate_cumulative_difficulty(previous_block.cumulative_difficulty(), base_target);
        if (cumulative_difficulty != b.cumulative_difficulty()) {
            log(LOG_ERR, "ERROR chain[%s] cumulative difficulty[%" PRIu64 ", %" PRIu64 "] mismatch",
                aux::toHex(chain_id).c_str(), cumulative_difficulty, b.cumulative_difficulty());
            return FAIL;
        }

        auto necessary_interval = consensus::calculate_mining_time_interval(hit, base_target, power);
        if (b.timestamp() - previous_block.timestamp() < necessary_interval) {
            log(LOG_ERR, "ERROR: Time is too short! hit:%" PRIu64 ", base target:%" PRIu64 ", power:%" PRId64 ", necessary interval:%" PRIu64 ", real interval:%" PRId64 "",
                hit, base_target, power, necessary_interval, b.timestamp() - previous_block.timestamp());
            return FAIL;
        }
        log(LOG_INFO, "hit:%" PRIu64 ", base target:%" PRIu64 ", power:%" PRId64 ", interval:%" PRIu64 ", real interval:%" PRId64 "",
            hit, base_target, power, necessary_interval, b.timestamp() - previous_block.timestamp());
        // notes: if use hit < base target * power * interval, data may be overflow
//        if (!consensus::verify_hit(hit, base_target, power, interval)) {
//            log("INFO chain[%s] block[%s] verify hit fail",
//                aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
//            return FAIL;
//        }

        std::map<dht::public_key, std::int64_t> peers_balance;
        std::map<dht::public_key, std::int64_t> peers_nonce;

        auto const& tx = b.tx();

        if (!tx.empty()) {
            if (b.chain_id() != tx.chain_id()) {
                log(LOG_ERR, "INFO chain[%s] block chain id[%s] and tx chain id[%s] mismatch",
                    aux::toHex(chain_id).c_str(), aux::toHex(b.chain_id()).c_str(), aux::toHex(tx.chain_id()).c_str());
                return FAIL;
            }

            if (!tx.verify_signature()) {
                log(LOG_ERR, "INFO chain[%s] block tx[%s] has bad signature",
                    aux::toHex(chain_id).c_str(), aux::toHex(b.sha256().to_string()).c_str());
                return FAIL;
            }
        }

        if ((!tx.empty() && tx.type() == tx_type::type_transfer) ||
            b.miner_balance() != 0 || b.miner_nonce() != 0 || b.sender_balance() != 0 || b.sender_nonce() != 0 || b.receiver_balance() != 0 || b.receiver_nonce() != 0) {
            std::set<dht::public_key> peers = b.get_block_peers();
            for (auto const& peer: peers) {
                // note: verify block with cache data, do not use m_repository
                auto peer_account = repo->get_account(chain_id, peer);
                log(LOG_INFO, "INFO: peer[%s] account[%s]", aux::toHex(peer.bytes).c_str(), peer_account.to_string().c_str());
                peers_balance[peer] = peer_account.balance();
                peers_nonce[peer] = peer_account.nonce();
            }

            if (!tx.empty() && tx.type() == tx_type::type_transfer) {
                // adjust state
                // miner earns fee
                peers_balance[b.miner()] += tx.fee();
                // receiver balance + amount
                peers_balance[tx.receiver()] += tx.amount();
                // sender balance - cost(fee + amount)
                peers_balance[tx.sender()] -= tx.cost();
                // sender nonce+1
                peers_nonce[tx.sender()] += 1;
            }

            if (peers_balance[b.miner()] != b.miner_balance() || peers_nonce[b.miner()] != b.miner_nonce() ||
                peers_balance[b.tx().sender()] != b.sender_balance() || peers_nonce[b.tx().sender()] != b.sender_nonce() ||
                peers_balance[b.tx().receiver()] != b.receiver_balance() || peers_nonce[b.tx().receiver()] != b.receiver_nonce()) {
                log(LOG_ERR, "ERROR chain[%s] block[%s] state error!", aux::toHex(chain_id).c_str(), b.to_string().c_str());
                return FAIL;
            }
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
                log(LOG_INFO, "INFO chain[%s] Voting point block[%s]", aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                m_voting_point_blocks[chain_id] = blk;

                put_voting_block(chain_id, blk);
            } else {
                log(LOG_INFO, "INFO chain[%s] Cannot find voting point block", aux::toHex(chain_id).c_str());
            }
        }
    }

    RESULT blockchain::process_block(const aux::bytes &chain_id, const block &blk) {
        if (blk.empty())
            return FAIL;

        auto &head_block  = m_head_blocks[chain_id];
        if (head_block.empty()) {
            auto track = m_repository->start_tracking();

            if (!track->connect_head_block(blk)) {
                log(LOG_ERR, "INFO chain[%s] connect head block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                return FAIL;
            }
            if (!track->set_head_block_hash(chain_id, blk.sha256())) {
                log(LOG_ERR, "INFO chain[%s] set head block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                return FAIL;
            }
            if (!track->set_tail_block_hash(chain_id, blk.sha256())) {
                log(LOG_ERR, "INFO chain[%s] set tail block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                return FAIL;
            }
            if (!track->set_consensus_point_block_hash(chain_id, blk.sha256())) {
                log(LOG_ERR, "INFO chain[%s] set consensus point block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                return FAIL;
            }

            if (!track->commit()) {
                log(LOG_ERR, "INFO chain[%s] commit fail", aux::toHex(chain_id).c_str());
                return FAIL;
            }
            if (!m_repository->flush(chain_id)) {
                log(LOG_ERR, "INFO chain[%s] flush fail", aux::toHex(chain_id).c_str());
                return FAIL;
            }

            // chain changed, re-check tx pool
            m_tx_pools[chain_id].recheck_account_txs(blk.get_block_peers());
            m_tx_pools[chain_id].delete_tx_from_time_pool(blk.tx());

            m_head_blocks[chain_id] = blk;
            m_tail_blocks[chain_id] = blk;
            m_consensus_point_blocks[chain_id] = blk;

            m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(blk);
            m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(blk);
            m_ses.alerts().emplace_alert<blockchain_new_consensus_point_block_alert>(blk);
        } else {
            if (blk.previous_block_hash() == head_block.sha256()) {
                std::set<dht::public_key> peers = blk.get_block_peers();

                auto track = m_repository->start_tracking();

                // no need to verify block if not sync completed
                if (!is_sync_completed(chain_id)) {
                    auto result = verify_block(chain_id, blk, head_block, track.get());
                    if (result != SUCCESS)
                        return result;
                }

                if (!track->connect_head_block(blk)) {
                    log(LOG_ERR, "INFO chain[%s] connect head block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                    return FAIL;
                }

                if (!track->set_head_block_hash(chain_id, blk.sha256())) {
                    log(LOG_ERR, "INFO chain[%s] set head block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                    return FAIL;
                }

                auto tail_block = m_tail_blocks[chain_id];
                // seek tail block
                while (blk.block_number() - tail_block.block_number() >= CHAIN_EPOCH_BLOCK_SIZE) {

                    // get next main chain block to be expired one by one
                    auto tail_next_block = track->get_main_chain_block_by_number(chain_id, tail_block.block_number() + 1);

                    if (tail_next_block.empty()) {
                        log(LOG_ERR, "INFO chain[%s] Cannot get next tail block", aux::toHex(chain_id).c_str());
                        return FAIL;
                    }

                    if (!track->expire_block(tail_block)) {
                        log(LOG_ERR, "INFO chain[%s] expire block[%s] fail",
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
                }

                if (!track->commit()) {
                    log(LOG_ERR, "INFO chain[%s] commit fail", aux::toHex(chain_id).c_str());
                    return FAIL;
                }
                m_repository->flush(chain_id);

                transfer_head_block(chain_id, blk);

                // todo: test
//                for (auto const& peer: peers) {
//                    auto abp = m_repository->get_account_block_pointer(chain_id, peer);
//                    log("+++++++++++++++++++:peer[%s], account block pointer[%s]", aux::toHex(peer.bytes).c_str(), abp.to_string().c_str());
//                }
//
//                auto sl = m_repository->get_state_linker(b.sha256());
//                log("+++++++++++++++++++:state linker:%s", sl.to_string().c_str());
//
//                auto iki = m_repository->get_index_info(chain_id, b.block_number());
//                log("+++++++++++++++++++:index key info:%s", iki.to_string().c_str());

                m_head_blocks[chain_id] = blk;
                if (!tail_block.empty()) {
                    m_tail_blocks[chain_id] = tail_block;
                    m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(tail_block);
                }

                // chain changed, re-check tx pool
                m_tx_pools[chain_id].recheck_account_txs(peers);
                m_tx_pools[chain_id].delete_tx_from_time_pool(blk.tx());

                m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(blk);
            }

            if (m_head_blocks[chain_id].block_number() - m_tail_blocks[chain_id].block_number() < CHAIN_EPOCH_BLOCK_SIZE - 1 &&
                blk.sha256() == m_tail_blocks[chain_id].previous_block_hash()) {
                auto track = m_repository->start_tracking();

                if (!track->connect_tail_block(blk)) {
                    log(LOG_ERR, "INFO chain[%s] connect tail block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                    return FAIL;
                }
                if (!track->set_tail_block_hash(chain_id, blk.sha256())) {
                    log(LOG_ERR, "INFO chain[%s] set tail block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                    return FAIL;
                }

                if (!track->commit()) {
                    log(LOG_ERR, "INFO chain[%s] commit fail", aux::toHex(chain_id).c_str());
                    return FAIL;
                }
                m_repository->flush(chain_id);

                m_tail_blocks[chain_id] = blk;

                // chain changed, re-check tx pool
                m_tx_pools[chain_id].recheck_account_txs(blk.get_block_peers());
                m_tx_pools[chain_id].delete_tx_from_time_pool(blk.tx());

                m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(blk);
            }
        }

        // re-locate consensus point block
        try_to_update_voting_point_block(chain_id);

        return SUCCESS;
    }

    void blockchain::block_reception_event(const aux::bytes &chain_id, const block &blk) {
//        if (m_chain_status[chain_id] == MINING) {
            auto now = get_total_milliseconds();

//            auto &block_map = m_blocks[chain_id];

            // 1. if empty chain, init chain with the best voting block
            if (is_empty_chain(chain_id)) {
                log(LOG_INFO, "INFO: chain[%s] is empty...", aux::toHex(chain_id).c_str());
                auto &best_vote = m_best_votes[chain_id];
                if (!best_vote.empty()) {
                    process_block(chain_id, best_vote.voting_block());
                }
            }

            if (!is_empty_chain(chain_id)) {
                // 2. try to connect head/tail block
                auto &head_block = m_head_blocks[chain_id];
                auto &tail_block = m_tail_blocks[chain_id];
                if (head_block.empty() || blk.previous_block_hash() == head_block.sha256() ||
                    blk.sha256() == tail_block.previous_block_hash()) {
                    log(LOG_INFO, "INFO: process block:%s", blk.to_string().c_str());
                    auto ret = process_block(chain_id, blk);
                    if (ret == FAIL) {
                        log(LOG_ERR, "ERROR: process block fail!");
                    }
                }

                // 3. try to sync block
                try_to_sync_block(chain_id);

//                for (auto it = block_map.begin(); it != block_map.end();) {
//                    if (head_block.empty() || it->second.previous_block_hash() == head_block.sha256() ||
//                        it->second.sha256() == tail_block.previous_block_hash()) {
//                        log("INFO: process block:%s", it->second.to_string().c_str());
//                        auto ret = process_block(chain_id, it->second);
//                        if (ret == SUCCESS) {
//                            block_map.erase(it);
//                            it = block_map.begin();
//                            continue;
//                        } else if (ret == FAIL) {
//                            block_map.erase(it++);
//                            continue;
//                        }
//                    }
//
//                    ++it;
//                }

                // 4. try to re-branch to a more difficult chain
                try_to_rebranch_to_most_difficult_chain(chain_id);

                // 5. try to re-branch to best vote
                try_to_rebranch_to_best_vote(chain_id);

                // 6. try to mine block
                auto it_timer = m_chain_timers.find(chain_id);
                if (it_timer != m_chain_timers.end()) {
                    it_timer->second.cancel();
                }
            }
//        }
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
        if (head_block.block_number() - tail_block.block_number() >= CHAIN_EPOCH_BLOCK_SIZE - 1)
            return true;

        return false;
    }

    bool blockchain::clear_chain_all_state_in_cache_and_db(const aux::bytes &chain_id) {
        m_head_blocks.erase(chain_id);
        m_tail_blocks.erase(chain_id);
        m_consensus_point_blocks.erase(chain_id);
        m_voting_point_blocks.erase(chain_id);
        return m_repository->delete_all_chain_data(chain_id);
    }

    bool blockchain::is_block_in_cache_or_db(const aux::bytes &chain_id, const sha256_hash &hash) {
//        auto &block_map = m_blocks[chain_id];
//        auto it = block_map.find(hash);
//        if (it != block_map.end() && !it->second.empty()) {
//            return true;
//        }

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

//    void blockchain::add_if_peer_not_in_acl(const aux::bytes &chain_id, const dht::public_key &peer) {
//        auto &acl = m_access_list[chain_id];
//        if (acl.find(peer) == acl.end()) {
//            acl[peer] = peer_info();
//        }
//    }

//    void blockchain::increase_peer_score(const aux::bytes &chain_id, const dht::public_key &peer, int score) {
//        auto &acl = m_access_list[chain_id];
//        auto size = acl.size();
//        auto it = acl.find(peer);
//        if (it != acl.end()) {
//            // in acl
//            it->second.m_score = std::min(it->second.m_score + score, 100);
//        } else {
//            if (is_peer_banned(chain_id, peer)) {
//                // TODO: decrease ban time?
//                return;
//            }
//
//            if (size >= blockchain_acl_max_peers) {
//                // find out min score peer
//                auto min_it = acl.begin();
//                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
//                    if (iter->second.m_score  < min_it->second.m_score) {
//                        min_it = iter;
//                    }
//                }
//
//                if (min_it->second.m_score < peer_info().m_score) {
//                    // replace min score peer with new one
//                    acl.erase(min_it);
//                    acl[peer] = peer_info();
//                }
//            } else {
//                acl[peer] = peer_info();
//            }
//        }
//    }

//    void blockchain::decrease_peer_score(const aux::bytes &chain_id, const dht::public_key &peer, int score) {
//        auto &acl = m_access_list[chain_id];
////        auto size = acl.size();
//        auto it = acl.find(peer);
//        if (it != acl.end()) {
//            // in acl
//            it->second.m_score = it->second.m_score - score;
//        } else {
//            if (is_peer_banned(chain_id, peer)) {
//                // TODO: increase ban time?
//                return;
//            }
//        }
//    }

    block blockchain::get_block_from_cache_or_db(const aux::bytes &chain_id, const sha256_hash &hash) {
//        auto &block_map = m_blocks[chain_id];
//        auto it = block_map.find(hash);
//        if (it != block_map.end()) {
//            if (!it->second.empty()) {
//                return it->second;
//            } else {
//                block_map.erase(it);
//            }
//        }

        return m_repository->get_block_by_hash(hash);
    }

    void blockchain::remove_all_same_chain_blocks_from_cache(const block &blk) {
//        auto& block_map = m_blocks[blk.chain_id()];
//        auto previous_hash = blk.previous_block_hash();
//        auto it = block_map.find(previous_hash);
//        while (it != block_map.end()) {
//            previous_hash = it->second.previous_block_hash();
//            block_map.erase(it);
//            it = block_map.find(previous_hash);
//        }
//
//        previous_hash = blk.sha256();
//        for (it = block_map.begin(); it != block_map.end();) {
//            if (it->second.previous_block_hash() == previous_hash) {
//                previous_hash = it->second.sha256();
//                block_map.erase(it);
//
//                it = block_map.begin();
//                continue;
//            }
//
//            ++it;
//        }
//
//        block_map.erase(blk.sha256());
    }

    void blockchain::remove_all_ancestor_blocks_from_cache(const block &blk) {
//        auto& block_map = m_blocks[blk.chain_id()];
//        auto previous_hash = blk.previous_block_hash();
//        auto it = block_map.find(previous_hash);
//        while (it != block_map.end()) {
//            previous_hash = it->second.previous_block_hash();
//            block_map.erase(it);
//            it = block_map.find(previous_hash);
//        }
//
//        block_map.erase(blk.sha256());
    }

    RESULT blockchain::try_to_rebranch(const aux::bytes &chain_id, const block &target, bool absolute, dht::public_key peer) {
        log(LOG_INFO, "INFO chain[%s] try to rebranch to block[%s]",
            aux::toHex(chain_id).c_str(), target.to_string().c_str());

        auto const& head_block = m_head_blocks[chain_id];

        // re-branch, try to find out fork point block
        std::vector<block> rollback_blocks;
        std::vector<block> connect_blocks;

        // align main chain and branch block number
        block main_chain_block = head_block;
        while (main_chain_block.block_number() > target.block_number()) {
            // check if try to rollback voting point block
            if (!absolute) {
                if (is_block_immutable_certainly(chain_id, main_chain_block)) {
                    log(LOG_ERR, "INFO chain[%s] block[%s] is immutable.",
                        aux::toHex(chain_id).c_str(), main_chain_block.to_string().c_str());
                    return FAIL;
                }
            }

            rollback_blocks.push_back(main_chain_block);

            auto previous_hash = main_chain_block.previous_block_hash();
            main_chain_block = m_repository->get_block_by_hash(previous_hash);
            if (main_chain_block.empty()) {
                if(absolute) {
                    log(LOG_INFO, "INFO chain[%s] has no fork point", aux::toHex(chain_id).c_str());
                    return NO_FORK_POINT;
                }
                log(LOG_INFO, "INFO chain[%s] 3. Cannot find block[%s] in db",
                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                request_block(chain_id, previous_hash);
                return MISSING;
            }
        }

        block reference_block = target;
        while (head_block.block_number() < reference_block.block_number()) {
            if (absolute && target.block_number() - reference_block.block_number() >= CHAIN_EPOCH_BLOCK_SIZE) {
                log(LOG_INFO, "INFO chain[%s] has no fork point", aux::toHex(chain_id).c_str());
                return NO_FORK_POINT;
            }
            connect_blocks.push_back(reference_block);

            // find branch block from cache and db
            auto previous_hash = reference_block.previous_block_hash();
            reference_block = get_block_from_cache_or_db(chain_id, previous_hash);

            if (reference_block.empty()) {
                log(LOG_INFO, "INFO chain[%s] 4. Cannot find block[%s]",
                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                request_block(chain_id, peer, previous_hash);
                return MISSING;
            }
        }

//        log("----1. main chain block:%s, reference block:%s", main_chain_block.to_string().c_str(), reference_block.to_string().c_str());
        // find out common ancestor
        while (main_chain_block.sha256() != reference_block.sha256()) {
            if (!absolute) {
                if (is_block_immutable_certainly(chain_id, main_chain_block)) {
                    log(LOG_ERR, "INFO chain[%s] block[%s] is immutable",
                        aux::toHex(chain_id).c_str(), main_chain_block.to_string().c_str());
                    return FAIL;
                }
            }

            rollback_blocks.push_back(main_chain_block);

            auto main_chain_previous_hash = main_chain_block.previous_block_hash();
            main_chain_block = m_repository->get_block_by_hash(main_chain_previous_hash);
            if (main_chain_block.empty()) {
                if(absolute) {
                    log(LOG_INFO, "INFO chain[%s] has no fork point", aux::toHex(chain_id).c_str());
                    return NO_FORK_POINT;
                }
                log(LOG_INFO, "INFO chain[%s] 5.1 Cannot find main chain block[%s]",
                    aux::toHex(chain_id).c_str(), aux::toHex(main_chain_previous_hash.to_string()).c_str());
                request_block(chain_id, main_chain_previous_hash);
                return MISSING;
            }

            if (absolute && target.block_number() - reference_block.block_number() >= CHAIN_EPOCH_BLOCK_SIZE) {
                log(LOG_INFO, "INFO chain[%s] has no fork point", aux::toHex(chain_id).c_str());
                return NO_FORK_POINT;
            }
            connect_blocks.push_back(reference_block);

            // find branch block from cache and db
            auto previous_hash = reference_block.previous_block_hash();
//            log("INFO chain[%s] find branch block[%s]",
//                aux::toHex(chain_id).c_str(), reference_block.to_string().c_str());
            reference_block = get_block_from_cache_or_db(chain_id, previous_hash);

            if (reference_block.empty()) {
                log(LOG_INFO, "INFO chain[%s] 5.2 Cannot find block[%s]",
                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                request_block(chain_id, peer, previous_hash);
                return MISSING;
            }
        }

        log(LOG_INFO, "INFO: try to rebranch from main chain block[%s] to target block[%s], fork point block:%s",
            head_block.to_string().c_str(), target.to_string().c_str(), reference_block.to_string().c_str());

        // reference block is fork point block
        connect_blocks.push_back(reference_block);

        std::set<dht::public_key> peers;

        auto track = m_repository->start_tracking();

        auto tail_block = m_tail_blocks[chain_id];
        bool tail_missing = false;
        // Rollback blocks
        for (auto &blk: rollback_blocks) {
//            log("INFO: try to rollback block:%s", blk.to_string().c_str());
            if (!track->rollback_block(blk)) {
                log(LOG_ERR, "INFO chain[%s] rollback block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                return FAIL;
            }

            if (!tail_missing && !tail_block.previous_block_hash().is_all_zeros()) {
                // in order to maintain the effective length of the chain,
                // re-connect old tail block when rollback a head block
                // if tail missing, block verification will be ignored
                auto previous_block = track->get_block_by_hash(tail_block.previous_block_hash());
                if (!previous_block.empty()) {
                    tail_block = previous_block;
                    if (!track->connect_tail_block(previous_block)) {
                        log(LOG_ERR, "INFO chain[%s] connect tail block[%s] fail",
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

//            log("INFO: try to connect block:%s", blk.to_string().c_str());
            if (!tail_missing) {
                auto result = verify_block(chain_id, blk, previous_block, track.get());
                if (result != SUCCESS)
                    return result;
            }

            if (!track->connect_head_block(blk)) {
                log(LOG_ERR, "INFO chain[%s] connect head block[%s] fail",
                    aux::toHex(chain_id).c_str(), aux::toHex(blk.sha256().to_string()).c_str());
                return FAIL;
            }

            // seek tail block
            while (blk.block_number() - tail_block.block_number() >= CHAIN_EPOCH_BLOCK_SIZE) {
                // get next main chain block to be expired one by one
                auto tail_next_block = track->get_main_chain_block_by_number(chain_id, tail_block.block_number() + 1);

                if (tail_next_block.empty()) {
                    log(LOG_ERR, "INFO chain[%s] Cannot get next tail block", aux::toHex(chain_id).c_str());
                    return FAIL;
                }

                if (!track->expire_block(tail_block)) {
                    log(LOG_ERR, "INFO chain[%s] expire block[%s] fail",
                        aux::toHex(chain_id).c_str(), aux::toHex(tail_block.sha256().to_string()).c_str());
                    return FAIL;
                }

                // chain changed, re-check block peer in pool
                auto tail_peers = tail_block.get_block_peers();
                peers.insert(tail_peers.begin(), tail_peers.end());

                // move to next block
                tail_block = tail_next_block;
            }

            auto block_peers = blk.get_block_peers();
            peers.insert(block_peers.begin(), block_peers.end());
        }

        if (!track->set_tail_block_hash(chain_id, tail_block.sha256())) {
            log(LOG_ERR, "INFO chain[%s] set tail block[%s] fail",
                aux::toHex(chain_id).c_str(), aux::toHex(tail_block.sha256().to_string()).c_str());
            return FAIL;
        }
        if (!track->set_head_block_hash(chain_id, target.sha256())) {
            log(LOG_ERR, "INFO chain[%s] set head block[%s] fail",
                aux::toHex(chain_id).c_str(), aux::toHex(target.sha256().to_string()).c_str());
            return FAIL;
        }

        if (!track->commit()) {
            log(LOG_ERR, "INFO chain[%s] commit fail", aux::toHex(chain_id).c_str());
            return FAIL;
        }
        m_repository->flush(chain_id);

        // after all above is success
        m_head_blocks[chain_id] = target;
        m_tail_blocks[chain_id] = tail_block;

        // chain changed, re-check tx pool
        m_tx_pools[chain_id].recheck_account_txs(peers);

        // re-locate consensus point block
        try_to_update_voting_point_block(chain_id);

        for (auto &blk: rollback_blocks) {
            // send back rollback block tx to pool
            m_tx_pools[chain_id].add_tx(blk.tx());
            // notify rollback block
            m_ses.alerts().emplace_alert<blockchain_rollback_block_alert>(blk);
        }
        for (auto i = connect_blocks.size(); i > 1; i--) {
            m_tx_pools[chain_id].delete_tx_from_time_pool(connect_blocks[i - 2].tx());
            m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(connect_blocks[i - 2]);
        }
//        m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(target);
        m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(tail_block);
        m_ses.alerts().emplace_alert<blockchain_fork_point_block_alert>(reference_block);

        return SUCCESS;
    }

    void blockchain::try_to_sync_block(const aux::bytes &chain_id) {
        // if sync no completed, request tail block too
        if (!is_sync_completed(chain_id)) {
            auto &tail_block = m_tail_blocks[chain_id];
            if (!tail_block.empty()) {
                log(LOG_INFO, "INFO: Demanding tail hash[%s].",
                    aux::toHex(tail_block.previous_block_hash()).c_str());
                request_block(chain_id, tail_block.previous_block_hash());
            }
        }
    }

    void blockchain::try_to_rebranch_to_best_vote(const aux::bytes &chain_id) {
        auto &best_vote = m_best_votes[chain_id];
        if (!best_vote.empty()) {
            if (!is_empty_chain(chain_id)) {
                // 4. check if need to re-branch to the best vote

                if (!best_vote.empty()) {
//                    log("INFO chain[%s] current best vote[%s]", aux::toHex(chain_id).c_str(),
//                        best_vote.to_string().c_str());

                    auto &consensus_point_block = m_consensus_point_blocks[chain_id];
                    if (consensus_point_block != best_vote.voting_block()) {
                        auto hash = m_repository->get_main_chain_block_hash_by_number(chain_id,
                                                                                      best_vote.voting_block().block_number());
                        // if current main chain block hash and voting block hash mismatch
                        if (hash != best_vote.voting_block().sha256()) {
                            log(LOG_INFO, "INFO chain[%s] main chain block[%s] mismatch the best vote",
                                aux::toHex(chain_id).c_str(), aux::toHex(hash.to_string()).c_str());
                            // re-branch
                            const auto &best_voting_block = best_vote.voting_block();
                            if (!best_voting_block.empty()) {
                                log(LOG_INFO, "INFO chain[%s] try to re-branch to best voting block[%s]",
                                    aux::toHex(chain_id).c_str(), best_voting_block.to_string().c_str());
                                auto result = try_to_rebranch(chain_id, best_voting_block, true);
                                // clear block cache if re-branch success/fail
                                if (result == SUCCESS) {
                                    // clear all ancestor blocks
                                    remove_all_ancestor_blocks_from_cache(best_voting_block);

                                    // update consensus point block hash as best voting block
                                    m_consensus_point_blocks[chain_id] = best_voting_block;
                                    m_repository->set_consensus_point_block_hash(chain_id,
                                                                                 best_vote.voting_block().sha256());

                                    m_ses.alerts().emplace_alert<blockchain_new_consensus_point_block_alert>(
                                            best_voting_block);
                                } else if (result == FAIL) {
                                    remove_all_same_chain_blocks_from_cache(best_voting_block);
                                } else if (result == NO_FORK_POINT) {
                                    clear_chain_all_state_in_cache_and_db(chain_id);
                                    m_repository->delete_peer_db(chain_id);
                                    m_repository->create_peer_db(chain_id);
                                    block_reception_event(chain_id, best_voting_block);
                                    reset_chain_status(chain_id);
                                    // cancel
                                    auto it_chain_timer = m_chain_timers.find(chain_id);
                                    if (it_chain_timer != m_chain_timers.end()) {
                                        it_chain_timer->second.cancel();
                                    }
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
            } else {
                process_block(chain_id, best_vote.voting_block());
            }
        }
    }

    void blockchain::try_to_rebranch_to_most_difficult_chain(const aux::bytes &chain_id) {
        auto now = get_total_milliseconds();

        auto &head_block = m_head_blocks[chain_id];
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
            auto peer_head_block = it->second.m_head_block;
            auto result = try_to_rebranch(chain_id, peer_head_block, false, it->first);
            // clear block cache if re-branch success/fail
            if (result == FAIL) {
                // clear all blocks on the same chain
                remove_all_same_chain_blocks_from_cache(peer_head_block);

                acl.erase(it);
                auto &ban_list = m_ban_list[chain_id];
                ban_list[it->first] = ban_info(now + blockchain_max_ban_time);
            } else if (result == SUCCESS) {
                // clear all ancestor blocks
                remove_all_ancestor_blocks_from_cache(peer_head_block);
            }
        }
    }

    namespace {
        bool sort_votes(const vote &lhs, const vote &rhs) {
            if (lhs.count() < rhs.count())
                return false;
            if (rhs.count() < lhs.count())
                return true;
            if (lhs.voting_block().cumulative_difficulty() < rhs.voting_block().cumulative_difficulty())
                return false;
            if (rhs.voting_block().cumulative_difficulty() < lhs.voting_block().cumulative_difficulty())
                return true;
            if (lhs.voting_block().block_number() < rhs.voting_block().block_number())
                return true;
            if (rhs.voting_block().block_number() < lhs.voting_block().block_number())
                return false;

            return lhs.voting_block().sha256()< rhs.voting_block().sha256();
        }
    }

    void blockchain::count_votes(const aux::bytes &chain_id) {
        std::set<vote> votes;
        auto & peer_votes = m_votes[chain_id];

        // vote for myself
        if (is_sync_completed(chain_id)) {
            auto &voting_point_block = m_voting_point_blocks[chain_id];
            peer_votes[*m_ses.pubkey()] = vote(voting_point_block);
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
            log(LOG_INFO, "INFO: chain[%s] best vote[%s]",
                aux::toHex(chain_id).c_str(), sorted_votes.begin()->to_string().c_str());
        }


        for (auto const &sorted_vote: sorted_votes) {
            log(LOG_INFO, "INFO: sorted vote:%s", sorted_vote.to_string().c_str());
        }

        // select top three votes
        std::vector<vote> top_three_votes;
        int i = 0;
        for (const auto & sorted_vote : sorted_votes) {
            if (i >= 3)
                break;

            log(LOG_INFO, "INFO chain[%s] top three vote[%s]",
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

    void blockchain::on_dht_put_mutable_item(const dht::item &i, const std::vector<std::pair<dht::node_entry, bool>> &nodes, dht::public_key const& peer) {
//        log(true, "INFO: peer[%s], value[%s]", aux::toHex(peer.bytes).c_str(), i.value().to_string().c_str());
//
//        auto salt = i.salt();
//        if (salt.length() > common::salt_pubkey_length) {
//            std::string encode(salt.begin() + common::salt_pubkey_length, salt.end());
//            common::protocol_entry protocolEntry(encode);
//            if (protocolEntry.m_data_type_id == common::transaction_entry::data_type_id) {
//                for (auto const &n: nodes) {
//                    log(true, "INFO: nodes:%s, bool:%d", n.first.addr().to_string().c_str(), n.second);
//                }
//
//                common::transaction_entry txEntry(i.value());
//                auto now = get_total_milliseconds();
//                m_ses.alerts().emplace_alert<blockchain_tx_sent_alert>(peer, txEntry.m_tx.sha256(), now);
//                for (auto const &n: nodes) {
//                    if (n.second) {
//                        m_ses.alerts().emplace_alert<blockchain_tx_arrived_alert>(peer, txEntry.m_tx.sha256(), now);
//                        break;
//                    }
//                }
//            }
//        } else {
//            log(true, "ERROR: Invalid salt on dht put mutable item!");
//        }
    }

    void blockchain::on_dht_relay_mutable_item(const entry &payload,
                                               const std::vector<std::pair<dht::node_entry, bool>> &nodes,
                                               const dht::public_key &peer) {
        // data type id
        if (auto* i = const_cast<entry *>(payload.find_key(common::entry_type)))
        {
            auto data_type_id = i->integer();
            if (data_type_id == common::transaction_entry::data_type_id) {
                for (auto const &n: nodes) {
                    log(LOG_DEBUG, "INFO: nodes:%s, bool:%d", n.first.addr().to_string().c_str(), n.second);
                }

                common::transaction_entry txEntry(payload);
                auto now = get_total_milliseconds();
                m_ses.alerts().emplace_alert<blockchain_tx_sent_alert>(peer, txEntry.m_tx.sha256(), now);
                for (auto const &n: nodes) {
                    if (n.second) {
                        m_ses.alerts().emplace_alert<blockchain_tx_arrived_alert>(peer, txEntry.m_tx.sha256(), now);
                        break;
                    }
                }
            }
        }
    }

    namespace {

//        void on_dht_put_immutable_item(aux::alert_manager& alerts, sha256_hash target, int num)
//        {
//        }

//        void relay_mutable_data(entry& e, std::array<char, 64>& sig
//                , std::int64_t& ts
//                , std::array<char, 32> const& pk
//                , std::array<char, 64> const& sk
//                , entry const& data)
//        {
//            using lt::dht::sign_mutable_item;
//
//            e = data;
//            std::vector<char> buf;
//            // bencode要发布的mutable data
//            bencode(std::back_inserter(buf), e);
//            dht::signature sign;
//            // get unix timestamp
//            ts = libTAU::aux::utcTime();
//            // 对编码完成之后的数据(data + salt + ts)进行签名
//            sign = sign_mutable_item(buf, salt, dht::timestamp(ts)
//                    , dht::public_key(pk.data())
//                    , dht::secret_key(sk.data()));
//            sig = sign.bytes;
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

//        void on_dht_put_mutable_item(aux::alert_manager& alerts, dht::item const& i, int num)
//        {
//        }

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
            log(LOG_INFO, "INFO: Hash prefix array is empty");
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

            log(LOG_INFO, "INFO: tx array: source array[%s], target array[%s]", aux::toHex(source).c_str(), aux::toHex(target).c_str());
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

    std::string blockchain::make_salt(dht::public_key peer, const aux::bytes &chain_id, std::int64_t data_type_id) {
        std::string salt(peer.bytes.begin(), peer.bytes.begin() + common::salt_pubkey_length);
        common::protocol_entry protocolEntry(chain_id, data_type_id);
        std::string encode = protocolEntry.get_encode();
        salt.insert(salt.end(), encode.begin(), encode.end());

        return salt;
    }

//    std::string blockchain::make_salt(dht::public_key peer, std::int64_t data_type_id) {
//        std::string salt(peer.bytes.begin(), peer.bytes.begin() + common::salt_pubkey_length);
//        common::protocol_entry protocolEntry(data_type_id);
//        std::string encode = protocolEntry.get_encode();
//        salt.insert(salt.end(), encode.begin(), encode.end());
//
//        return salt;
//    }

    void blockchain::send_to(const dht::public_key &peer, const entry &data) {
        if (!m_ses.dht()) return;
        log(LOG_INFO, "Send [%s] to peer[%s]", data.to_string(true).c_str(), aux::toHex(peer.bytes).c_str());
        m_ses.dht()->send(peer, data, 1, 8, 10, 1
                , std::bind(&blockchain::on_dht_relay_mutable_item, self(), _1, _2, peer));
    }

    void blockchain::request_block(const aux::bytes &chain_id, const sha256_hash &hash) {
        auto now = get_total_milliseconds();

        auto &acl = m_access_list[chain_id];
        auto max_it = acl.begin();
        for (auto iter = acl.begin(); iter != acl.end(); iter++) {
            if (iter->second.m_score > max_it->second.m_score) {
                max_it = iter;
            }
        }

        if (max_it != acl.end()) {
            auto &peer = max_it->first;
            if (max_it->second.m_requests_time.find(std::make_unique<common::block_request_entry>(chain_id, hash)) ==
                max_it->second.m_requests_time.end()) {
                log(LOG_INFO, "=====INFO: chain[%s] request block hash[%s] time:%" PRId64, aux::toHex(chain_id).c_str(),
                    aux::toHex(hash.to_string()).c_str(), now);
                common::block_request_entry blockRequestEntry(chain_id, hash);
                send_to(peer, blockRequestEntry.get_entry());

                max_it->second.m_requests_time[std::make_unique<common::block_request_entry>(chain_id, hash)] = now;
            }
        } else {
            log(LOG_INFO, "INFO: ACL is empty, no peer to request.");
        }
    }

    void blockchain::request_block(const aux::bytes &chain_id, const dht::public_key &peer, const sha256_hash &hash) {
        if (!peer.is_all_zeros()) {
            auto it = m_access_list[chain_id].find(peer);

            if (it != m_access_list[chain_id].end()) {
                if (it->second.m_requests_time.find(std::make_unique<common::block_request_entry>(chain_id, hash)) ==
                    it->second.m_requests_time.end()) {
                    auto now = get_total_milliseconds();

                    log(LOG_INFO, "=====INFO: chain[%s] request block hash[%s] time:%" PRId64, aux::toHex(chain_id).c_str(),
                        aux::toHex(hash.to_string()).c_str(), now);
                    common::block_request_entry blockRequestEntry(chain_id, hash);
                    send_to(peer, blockRequestEntry.get_entry());

                    it->second.m_requests_time[std::make_unique<common::block_request_entry>(chain_id, hash)] = now;
                }
            }
        } else {
            request_block(chain_id, hash);
        }
    }

    void blockchain::transfer_to_acl_peers(const aux::bytes &chain_id, const entry &data,
                                           const dht::public_key &incoming_peer) {
        std::set<dht::public_key> peers;
        auto &acl = m_access_list[chain_id];
        for (auto const &item: acl) {
            peers.insert(item.first);
        }

        auto size = acl.size();
        if (size < blockchain_acl_max_peers) {
            for (int i = 0; i < blockchain_acl_max_peers - size; i++) {
                auto peer = m_repository->get_peer_randomly(chain_id);
                peers.insert(peer);
            }
        }

        peers.erase(incoming_peer);

        for (auto const& peer: peers) {
            send_to(peer, data);
        }
    }

    void blockchain::transfer_head_block(const bytes &chain_id, const block &blk) {
        std::set<dht::public_key> peers;
        auto &acl = m_access_list[chain_id];
        for (auto const &item: acl) {
            if (item.second.m_head_block != blk) {
                peers.insert(item.first);
            }
        }

        auto size = acl.size();
        if (size < blockchain_acl_max_peers) {
            for (int i = 0; i < blockchain_acl_max_peers - size; i++) {
                auto peer = m_repository->get_peer_randomly(chain_id);
                peers.insert(peer);
            }
        }

        common::head_block_entry blockEntry(blk);

        for (auto const& peer: peers) {
            send_to(peer, blockEntry.get_entry());
        }
    }

    void blockchain::transfer_transaction(const bytes &chain_id, const transaction &tx) {
        std::set<dht::public_key> peers;
        auto &acl = m_access_list[chain_id];
        for (auto const &item: acl) {
            if (item.second.m_latest_tx != tx) {
                peers.insert(item.first);
            }
        }

        auto size = acl.size();
        if (size < blockchain_acl_max_peers) {
            for (int i = 0; i < blockchain_acl_max_peers - size; i++) {
                auto peer = m_repository->get_peer_randomly(chain_id);
                peers.insert(peer);
            }
        }

        common::transaction_entry transactionEntry(tx);

        for (auto const& peer: peers) {
            send_to(peer, transactionEntry.get_entry());
        }
    }

    void blockchain::get_gossip_peers(const aux::bytes &chain_id, const dht::public_key &peer) {
        // salt is x pubkey when request signal
        auto salt = make_salt(peer, chain_id, common::gossip_cache_peers_entry::data_type_id);

        log(LOG_INFO, "INFO: Request gossip peers from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
        dht_get_mutable_item(chain_id, peer.bytes, salt);
    }

    void blockchain::get_voting_block(const aux::bytes &chain_id, const dht::public_key &peer) {
        // salt is x pubkey when request signal
        auto salt = make_salt(peer, chain_id, common::voting_block_cache_entry::data_type_id);

        log(LOG_INFO, "INFO: Request vote from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
        dht_get_mutable_item(chain_id, peer.bytes, salt);
    }

    void blockchain::put_voting_block(const aux::bytes &chain_id, const block &blk) {
        if (!blk.empty()) {
            common::voting_block_cache_entry votingBlockCacheEntry(blk);

            dht::public_key * pk = m_ses.pubkey();
            dht::secret_key * sk = m_ses.serkey();

            // salt is y pubkey when publish signal
            auto salt = make_salt(*pk, chain_id, common::voting_block_cache_entry::data_type_id);

            log(LOG_INFO, "INFO: Chain id[%s] Cache voting block salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());

            dht_put_mutable_item(pk->bytes, std::bind(&put_mutable_data, _1, _2, _3, _4
                    , pk->bytes, sk->bytes, votingBlockCacheEntry.get_entry()), 1, 8, 100, salt, *pk, true);
        }
    }

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
    void blockchain::get_mutable_callback(aux::bytes const& chain_id, dht::item const& i
            , bool const authoritative)
    {
        TORRENT_ASSERT(i.is_mutable());

        // construct mutable data wrapper from entry
        try {
            if (!i.empty()) {
                auto peer = i.pk();
                auto salt = i.salt();
                if (salt.length() > common::salt_pubkey_length) {
                    std::string encode(salt.begin() + common::salt_pubkey_length, salt.end());
                    common::protocol_entry protocolEntry(encode);
                    switch (protocolEntry.m_data_type_id) {
                        case common::voting_block_cache_entry::data_type_id: {
                            common::voting_block_cache_entry votingBlockCacheEntry(i.value());
                            if (!votingBlockCacheEntry.m_blk.empty()) {
                                log(LOG_INFO, "INFO: chain[%s] get vote[%s] from peer[%s]",
                                    aux::toHex(chain_id).c_str(),
                                    votingBlockCacheEntry.m_blk.to_string().c_str(),
                                    aux::toHex(peer.bytes).c_str());
                                m_votes[chain_id][peer] = vote(votingBlockCacheEntry.m_blk);
                            }
                            break;
                        }
                        case common::gossip_cache_peers_entry::data_type_id: {
                            common::gossip_cache_peers_entry gossipCachePeersEntry(i.value());
                            log(LOG_INFO, "INFO: chain[%s] get %d gossip peers from peer[%s]",
                                aux::toHex(chain_id).c_str(),
                                gossipCachePeersEntry.m_peers.size(), aux::toHex(peer.bytes).c_str());
                            add_gossip_peers(chain_id, gossipCachePeersEntry.m_peers);
                            break;
                        }
                        default: {

                        }
                    }
                } else {
                    log(LOG_ERR, "ERROR: Invalid salt in getting callback!");
                }
            }
        } catch (std::exception &e) {
            log(LOG_ERR, "ERROR: Exception in get mutable callback.");
        }
    }

    // key is a 32-byte binary string, the public key to look up.
    // the salt is optional
    void blockchain::dht_get_mutable_item(aux::bytes const& chain_id, std::array<char, 32> key, std::string salt)
    {
        if (!m_ses.dht()) return;
        m_ses.dht()->get_item(dht::public_key(key.data()), std::bind(&blockchain::get_mutable_callback
                , this, chain_id, _1, _2), std::move(salt));
    }

//    void blockchain::dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target)
//    {
//        if (!m_ses.dht()) return;
//        m_ses.dht()->put_item(data,  eps, std::bind(&on_dht_put_immutable_item, std::ref(m_ses.alerts())
//                , target, _1));
//    }

    void blockchain::dht_put_mutable_item(std::array<char, 32> key
            , std::function<void(entry&, std::array<char,64>&
            , std::int64_t&, std::string const&)> cb
            , std::int8_t alpha, std::int8_t beta, std::int8_t invoke_limit
            , std::string salt, const dht::public_key &peer, bool cache)
    {
        if (!m_ses.dht()) return;
//        m_ses.dht()->put_item(dht::public_key(key.data())
//                , std::bind(&on_dht_put_mutable_item, std::ref(m_ses.alerts()), _1, _2)
//                , std::bind(&put_mutable_callback, _1, std::move(cb)), std::move(salt), peer);
        m_ses.dht()->put_item(dht::public_key(key.data())
                , std::bind(&blockchain::on_dht_put_mutable_item, self(), _1, _2, peer)
                , std::bind(&put_mutable_callback, _1, std::move(cb))
                , alpha, beta, invoke_limit, salt, peer, cache);
    }

    bool blockchain::should_log(aux::LOG_LEVEL log_level) const
    {
        return log_level <= m_ses.get_log_level() && m_ses.alerts().should_post<blockchain_log_alert>();
    }

    TORRENT_FORMAT(3,4)
    void blockchain::log(aux::LOG_LEVEL log_level, char const* fmt, ...) const noexcept try
    {
#ifndef TORRENT_DISABLE_LOGGING
        if (!should_log(log_level)) return;

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

        log(LOG_INFO, "INFO Create chain id[%s] with community name[%s]", aux::toHex(chain_id).c_str(), community_name.c_str());

        return chain_id;
    }

    bool blockchain::create_TAU_chain() {
        log(LOG_INFO, "INFO: create tau chain.");
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
                                miner, GENESIS_BLOCK_BALANCE, 0, 0, 0, 0, 0, ep);
            } else {
                b = block(TAU_CHAIN_ID, block_version::block_version1, TAU_CHAIN_GENESIS_TIMESTAMP, block_number,
                                previous_hash, GENESIS_BASE_TARGET, 0, genSig, transaction(), miner,
                                GENESIS_BLOCK_BALANCE, 0, 0, 0, 0, 0);
            }
            b.sign(*pk, *sk);

            blocks.push_back(b);

            previous_hash = b.sha256();
            block_number++;
        }

        // follow and load chain
        followChain(TAU_CHAIN_ID, peers);

        for (auto it = blocks.rbegin(); it != blocks.rend(); ++it) {
            log(LOG_INFO, "Process tau chain block:%s", it->to_string().c_str());
            process_block(TAU_CHAIN_ID, *it);
        }

        return true;
    }

    bool blockchain::createNewCommunity(const aux::bytes &chain_id, const std::map<dht::public_key, account>& accounts) {
        std::int64_t now = get_total_milliseconds() / 1000; // second

        dht::secret_key *sk = m_ses.serkey();
        dht::public_key *pk = m_ses.pubkey();

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
                          GENESIS_BASE_TARGET, 0, genSig, transaction(), miner, miner_balance,
                                0, 0, 0, 0, 0, ep);
            } else {
                b = block(chain_id, block_version::block_version1, now, block_number, previous_hash,
                          GENESIS_BASE_TARGET, 0, genSig, transaction(), miner, miner_balance,
                                0, 0, 0, 0, 0);
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
                      GENESIS_BASE_TARGET, 0, genSig, transaction(), *pk, genesis_balance,
                            0, 0, 0, 0, 0, ep);
        } else {
            b = block(chain_id, block_version::block_version1, now, block_number, previous_hash,
                      GENESIS_BASE_TARGET, 0, genSig, transaction(), *pk, genesis_balance,
                            0, 0, 0, 0, 0);
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

    std::set<aux::bytes> blockchain::get_all_chains() {
        return m_repository->get_all_chains();
    }

    bool blockchain::submitTransaction(const transaction& tx) {
        try {
            log(LOG_INFO, "INFO: add new tx:%s", tx.to_string().c_str());
            if (!tx.empty()) {
                if (!tx.verify_signature()) {
                    log(LOG_INFO, "INFO: Bad signature.");
                    return false;
                }

                auto &chain_id = tx.chain_id();

                auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                if (it == m_chains.end()) {
                    log(LOG_INFO, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
                    return false;
                }

                transfer_transaction(chain_id, tx);

                m_tx_pools[chain_id].add_tx(tx);
                return true;
            }
        } catch (std::exception &e) {
            log(LOG_ERR, "Exception add new tx [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            return false;
        }

        return false;
    }

    bool blockchain::is_transaction_in_fee_pool(const aux::bytes &chain_id, const sha256_hash &txid) {
        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return false;
        }

        return m_tx_pools[chain_id].is_transaction_in_fee_pool(txid);
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
        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return std::vector<block>();
        }

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
        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return 0;
        }

        std::vector<transaction> txs = m_tx_pools[chain_id].get_top_ten_fee_transactions();
        auto size = txs.size();
        if (size > 0) {
            return txs[size / 2].fee();
        }

        return 0;
    }

    std::int64_t blockchain::getMiningTime(const aux::bytes &chain_id) {
        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return -1;
        }

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
            log(LOG_INFO, "INFO: chain id[%s] public key[%s] power[%" PRId64 "]", aux::toHex(chain_id).c_str(), aux::toHex(pk->bytes).c_str(), power);
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

    std::set<dht::public_key> blockchain::get_access_list(const aux::bytes &chain_id) {
        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return std::set<dht::public_key>();
        }

        std::set<dht::public_key> peers;
        auto& access_list = m_access_list[chain_id];
        for (auto const& item: access_list) {
            peers.insert(item.first);
        }

        return peers;
    }

    std::set<dht::public_key> blockchain::get_ban_list(const aux::bytes &chain_id) {
        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return std::set<dht::public_key>();
        }

        std::set<dht::public_key> peers;
        auto& ban_list = m_ban_list[chain_id];
        for (auto const& item: ban_list) {
            peers.insert(item.first);
        }

        return peers;
    }

    std::set<dht::public_key> blockchain::get_gossip_peers(const aux::bytes &chain_id) {
        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
        if (it == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return std::set<dht::public_key>();
        }

        auto gossip_peers = m_gossip_peers[chain_id];
        if (!gossip_peers.empty()) {
            return gossip_peers;
        }

        return m_repository->get_all_gossip_peers(chain_id);
    }

//    void blockchain::set_blockchain_loop_interval(int milliseconds) {
//        log("INFO: Set block chain loop interval:%d(ms)", milliseconds);
//        m_refresh_time = milliseconds;
//        m_refresh_timer.cancel();
//    }

    void blockchain::introduce_gossip_peers(const aux::bytes &chain_id, const dht::public_key &peer) {
        auto const& acl = m_access_list[chain_id];
        std::set<dht::public_key> peers;
        int i = 0;
        for (auto iter = acl.begin(); iter != acl.end() && i < blockchain_acl_max_peers; iter++, i++) {
            peers.insert(iter->first);
        }

        peers.erase(peer);

        if (!peers.empty()) {
            introduce_peers(chain_id, peer, peers);
        }
    }

    void blockchain::introduce_peers(const aux::bytes &chain_id, const dht::public_key &peer, const std::set<dht::public_key>& peers) {
        auto act = m_repository->get_account(chain_id, peer);
        if (act.empty()) {
            common::gossip_peers_entry gossipPeersEntry(chain_id, peers);
            send_to(peer, gossipPeersEntry.get_entry());
        } else {
            account balance_account(act.balance());
            common::gossip_peers_entry gossipPeersEntry(chain_id, peers, balance_account.balance());
            send_to(peer, gossipPeersEntry.get_entry());
        }
    }

    void blockchain::put_gossip_peers_to_cache(const aux::bytes &chain_id) {
        auto const& acl = m_access_list[chain_id];
        std::set<dht::public_key> peers;
        int i = 0;
        for (auto iter = acl.begin(); iter != acl.end() && i < blockchain_acl_max_peers; iter++, i++) {
            peers.insert(iter->first);
        }

        if (peers.size() < blockchain_acl_max_peers) {
            auto gossip_peers = m_repository->get_all_gossip_peers(chain_id);
            int m = blockchain_acl_max_peers - peers.size();
            int k = 0;
            for (const auto & gossip_peer : gossip_peers) {
                if (k < m) {
                    peers.insert(gossip_peer);
                } else {
                    break;
                }

                k++;
            }
        }

        if (peers.size() < blockchain_acl_max_peers) {
            int m = blockchain_acl_max_peers - peers.size();
            for (int k = 0; k < m; k++) {
                auto pubKey = m_repository->get_peer_randomly(chain_id);
                if (!pubKey.is_all_zeros()) {
                    peers.insert(pubKey);
                }
            }

        }

        if (!peers.empty()) {
            common::gossip_cache_peers_entry gossipCachePeersEntry(peers);

            dht::public_key * pk = m_ses.pubkey();
            dht::secret_key * sk = m_ses.serkey();

            // salt is y pubkey when publish signal
            auto salt = make_salt(*pk, chain_id, common::gossip_cache_peers_entry::data_type_id);

            log(LOG_INFO, "INFO: Chain id[%s] Cache gossip peers salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());

            dht_put_mutable_item(pk->bytes, std::bind(&put_mutable_data, _1, _2, _3, _4
                    , pk->bytes, sk->bytes, gossipCachePeersEntry.get_entry()), 1, 8, 100, salt, *pk, true);
        }
    }

    void blockchain::add_gossip_peers(const aux::bytes &chain_id, const std::set<dht::public_key> &peers) {
        m_gossip_peers[chain_id].insert(peers.begin(), peers.end());
        auto& gossip_peers = m_gossip_peers[chain_id];
        while (gossip_peers.size() > 10) {
            srand(get_total_microseconds());
            auto index = rand() % gossip_peers.size();
            int i = 0;
            for (auto it = gossip_peers.begin(); it != gossip_peers.end(); it++) {
                if (i == index) {
                    gossip_peers.erase(it);
                    break;
                }
                i++;
            }
        }
    }

    void blockchain::data_received_from_peer(const aux::bytes &chain_id, const dht::public_key& peer, int score) {
        auto now = get_total_milliseconds();
        auto &acl = m_access_list[chain_id];

        auto it = acl.find(peer);
        if (it != acl.end()) {
            it->second.m_score += score;
            if (it->second.m_score > 100) {
                it->second.m_score = 100;
            }
            it->second.m_last_seen = now;
        } else {
            if (acl.size() < blockchain_acl_max_peers) {
                acl[peer] = peer_info(now);

                introduce_gossip_peers(chain_id, peer);
            }
        }
    }

    void blockchain::data_received_from_peer(const aux::bytes &chain_id, const dht::public_key &peer, int score,
                                             const std::unique_ptr<common::blockchain_entry_base> &ptr) {
        auto now = get_total_milliseconds();
        auto &acl = m_access_list[chain_id];

        auto it = acl.find(peer);
        if (it != acl.end()) {
            it->second.m_score += score;
            if (it->second.m_score > 100) {
                it->second.m_score = 100;
            }
            it->second.m_requests_time.erase(ptr);
            it->second.m_last_seen = now;
        } else {
            if (acl.size() < blockchain_acl_max_peers) {
                acl[peer] = peer_info(now);

                introduce_gossip_peers(chain_id, peer);
            }
        }
    }

    void blockchain::head_block_received_from_peer(const aux::bytes &chain_id, const dht::public_key &peer, const block &blk) {
        auto now = get_total_milliseconds();
        auto &acl = m_access_list[chain_id];

        auto it = acl.find(peer);
        if (it != acl.end()) {
            it->second.m_stage = NORMAL;
            it->second.m_score += 3;
            if (it->second.m_score > 100) {
                it->second.m_score = 100;
            }
            it->second.m_head_block = blk;
            it->second.m_requests_time.erase(std::make_unique<common::head_block_request_entry>(chain_id));
            it->second.m_last_seen = now;
        } else {
            if (acl.size() < blockchain_acl_max_peers) {
                acl[peer] = peer_info(NORMAL, blk, now);

                introduce_gossip_peers(chain_id, peer);
            }
        }
    }

    void blockchain::transaction_received_from_peer(const bytes &chain_id, const dht::public_key &peer,
                                                    const transaction &tx) {
        auto now = get_total_milliseconds();
        auto &acl = m_access_list[chain_id];

        auto it = acl.find(peer);
        if (it != acl.end()) {
            it->second.m_score += 3;
            if (it->second.m_score > 100) {
                it->second.m_score = 100;
            }
            it->second.m_latest_tx = tx;
            it->second.m_requests_time.erase(std::make_unique<common::transaction_request_entry>(chain_id, tx.sha256()));
            it->second.m_last_seen = now;
        } else {
            if (acl.size() < blockchain_acl_max_peers) {
                acl[peer] = peer_info(tx, now);

                introduce_gossip_peers(chain_id, peer);
            }
        }
    }

    bool blockchain::request_received_from_peer(const aux::bytes &chain_id, const dht::public_key& peer,
                                                std::unique_ptr<common::blockchain_entry_base>& ptr) {
        auto now = get_total_milliseconds();
        auto &acl = m_access_list[chain_id];
        auto it = acl.find(peer);
        if (it != acl.end()) {
            auto itor = it->second.m_peer_requests_time.find(ptr);
            if (itor != it->second.m_peer_requests_time.end()) {
                if (now > itor->second + blockchain_same_response_interval) {
                    it->second.m_peer_requests_time.erase(itor);
                } else {
                    log(LOG_INFO, "INFO: The same request from the same peer in 4s.");
                    return false;
                }
            } else {
                it->second.m_peer_requests_time.emplace(std::move(ptr), now);
            }
            it->second.m_last_seen = now;
            it->second.m_score -= 1;
            if (it->second.m_score <= 0) {
                acl.erase(it);
            }
        } else {
            if (acl.size() >= blockchain_acl_max_peers) {
                log(LOG_INFO, "INFO: Too many peers in acl to response.");
                introduce_gossip_peers(chain_id, peer);
                return false;
            } else {
                acl[peer] = peer_info(now);
                acl[peer].m_peer_requests_time.emplace(std::move(ptr), now);

                introduce_gossip_peers(chain_id, peer);
            }
        }

        return true;
    }

    void blockchain::on_dht_relay(dht::public_key const& peer, entry const& payload) {
        if (m_pause) {
            log(LOG_INFO, "INFO: Block chain is paused.");
            return;
        }

        if(payload.type() != entry::dictionary_t){
            log(LOG_ERR, "ERROR: relay data not dict. to string: %s", payload.to_string().c_str());
            return;
        }
        // construct mutable data wrapper from entry
        auto now = get_total_milliseconds();

        try {
            // data type id
            if (auto* i = const_cast<entry *>(payload.find_key(common::entry_type)))
            {
                auto data_type_id = i->integer();

                log(LOG_INFO, "data type id:%" PRId64 " from peer[%s] entry[%s]", data_type_id,
                    aux::toHex(peer.bytes).c_str(), payload.to_string(true).c_str());
                switch (data_type_id) {
                    case common::block_request_entry::data_type_id: {
                        common::block_request_entry blk_request_entry(payload);
                        auto &chain_id = blk_request_entry.m_chain_id;

                        {
                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                            if (it == m_chains.end()) {
                                log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                                return;
                            }
                        }

                        try_to_kick_out_of_ban_list(chain_id, peer);

                        std::unique_ptr<common::blockchain_entry_base> ptr = std::make_unique<common::block_request_entry>(payload);
                        if (!request_received_from_peer(chain_id, peer, ptr)) {
                            break;
                        }

                        log(LOG_INFO, "=====INFO: Got block request[%s], time:%" PRId64,
                            aux::toHex(blk_request_entry.m_hash.to_string()).c_str(), get_total_milliseconds());

                        auto blk = m_repository->get_block_by_hash(blk_request_entry.m_hash);

                        if (!blk.empty()) {
                            log(LOG_INFO, "=====INFO: response block request[%s], time:%" PRId64,
                                aux::toHex(blk_request_entry.m_hash.to_string()).c_str(), get_total_milliseconds());
                            common::block_entry blockEntry(blk);
                            send_to(peer, blockEntry.get_entry());
                        } else {
                            log(LOG_INFO, "INFO: Cannot get block[%s] in local", aux::toHex(blk_request_entry.m_hash).c_str());
                        }

                        break;
                    }
                    case common::block_entry::data_type_id: {
                        common::block_entry blk_entry(payload);
                        auto &chain_id = blk_entry.m_chain_id;

                        {
                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                            if (it == m_chains.end()) {
                                log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                                return;
                            }
                        }

                        try_to_kick_out_of_ban_list(chain_id, peer);

                        // TODO: validate timestamp etc. ?
                        if (!blk_entry.m_blk.empty()) {
                            auto &acl = m_access_list[chain_id];

                            if (acl.empty()) {
                                auto peers = blk_entry.m_blk.get_block_peers();
                                peers.erase(*m_ses.pubkey());
                                if (!peers.empty()) {
                                    add_gossip_peers(chain_id, peers);
                                }
                            }

                            data_received_from_peer(chain_id, peer, 3, std::make_unique<common::block_request_entry>(chain_id, blk_entry.m_blk.sha256()));

                            log(LOG_INFO, "=====INFO: Got block[%s], time:%" PRId64,
                                blk_entry.m_blk.to_string().c_str(), get_total_milliseconds());

                            m_repository->save_block(blk_entry.m_blk);

//                            m_blocks[chain_id][blk_entry.m_blk.sha256()] = blk_entry.m_blk;

//                            m_ses.alerts().emplace_alert<blockchain_syncing_block_alert>(peer, blk_entry.m_blk);

                            // notify ui tx from block
                            if (!blk_entry.m_blk.tx().empty()) {
                                m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(blk_entry.m_blk.tx());
                            }

                            block_reception_event(chain_id, blk_entry.m_blk);
                        }

                        break;
                    }
                    case common::fee_tx_pool_entry::data_type_id: {
                        common::fee_tx_pool_entry txPoolEntry(payload);
                        auto &chain_id = txPoolEntry.m_chain_id;

                        {
                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                            if (it == m_chains.end()) {
                                log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                                return;
                            }
                        }

                        try_to_kick_out_of_ban_list(chain_id, peer);

                        std::unique_ptr<common::blockchain_entry_base> ptr = std::make_unique<common::fee_tx_pool_entry>(payload);
                        if (!request_received_from_peer(chain_id, peer, ptr)) {
                            break;
                        }

                        auto fee_pool_txs = m_tx_pools[chain_id].get_top_ten_fee_transactions();
                        std::set<transaction> missing_txs;
                        find_best_solution(fee_pool_txs, txPoolEntry.m_fee_pooL_levenshtein_array, missing_txs);

                        for (auto const& tx: missing_txs) {
                            common::transaction_entry txEntry(tx);
                            send_to(peer, txEntry.get_entry());
                        }

                        break;
                    }
                    case common::time_tx_pool_entry::data_type_id: {
                        common::time_tx_pool_entry txPoolEntry(payload);
                        auto &chain_id = txPoolEntry.m_chain_id;

                        {
                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                            if (it == m_chains.end()) {
                                log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                                return;
                            }
                        }

                        try_to_kick_out_of_ban_list(chain_id, peer);

                        std::unique_ptr<common::blockchain_entry_base> ptr = std::make_unique<common::time_tx_pool_entry>(payload);
                        if (!request_received_from_peer(chain_id, peer, ptr)) {
                            break;
                        }

                        auto time_pool_txs = m_tx_pools[chain_id].get_top_ten_timestamp_transactions();
                        std::set<transaction> missing_txs;
                        find_best_solution(time_pool_txs, txPoolEntry.m_time_pooL_levenshtein_array, missing_txs);

                        for (auto const& tx: missing_txs) {
                            common::transaction_entry txEntry(tx);
                            send_to(peer, txEntry.get_entry());
                        }

                        break;
                    }
                    case common::transaction_request_entry::data_type_id: {
                        common::transaction_request_entry tx_request_entry(payload);
                        auto &chain_id = tx_request_entry.m_chain_id;

                        {
                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                            if (it == m_chains.end()) {
                                log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                                return;
                            }
                        }

                        try_to_kick_out_of_ban_list(chain_id, peer);

                        std::unique_ptr<common::blockchain_entry_base> ptr = std::make_unique<common::transaction_request_entry>(payload);
                        if (!request_received_from_peer(chain_id, peer, ptr)) {
                            break;
                        }

                        break;
                    }
                    case common::transaction_entry::data_type_id: {
                        common::transaction_entry tx_entry(payload);
                        auto &chain_id = tx_entry.m_chain_id;

                        {
                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                            if (it == m_chains.end()) {
                                log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                                return;
                            }
                        }

                        try_to_kick_out_of_ban_list(chain_id, peer);

                        if (!tx_entry.m_tx.empty()) {
                            auto &tx = tx_entry.m_tx;
                            log(LOG_INFO, "INFO: Got transaction[%s].", tx.to_string().c_str());

                            transaction_received_from_peer(chain_id, peer, tx_entry.m_tx);

                            m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(tx_entry.m_tx);

//                            if (tx.sender() == peer) {
//                                common::transaction_reply_entry txReplyEntry(chain_id, tx.sha256());
//                                send_to(chain_id, peer, common::transaction_reply_entry::data_type_id, txReplyEntry.get_entry(), true);
//                            }

                            auto &pool = m_tx_pools[chain_id];
                            if (pool.add_tx(tx)) {
                                transfer_transaction(chain_id, tx);
                            }
                        }

                        break;
                    }
//                    case common::vote_request_entry::data_type_id: {
//                        common::vote_request_entry voteRequestEntry(payload);
//                        auto &chain_id = voteRequestEntry.m_chain_id;
//
//                        {
//                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
//                            if (it == m_chains.end()) {
//                                log("INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
//                                return;
//                            }
//                        }
//
//                        try_to_kick_out_of_ban_list(chain_id, peer);
//
//                        auto &acl = m_access_list[chain_id];
//                        auto it = acl.find(peer);
//                        if (it != acl.end()) {
//                            auto itor = it->second.m_peer_requests_time.find(std::make_unique<common::vote_request_entry>(payload));
//                            if (itor != it->second.m_peer_requests_time.end()) {
//                                if (now > itor->second + blockchain_same_response_interval) {
//                                    it->second.m_peer_requests_time.erase(itor);
//                                } else {
//                                    log("INFO: The same request from the same peer in 3s.");
//                                    break;
//                                }
//                            } else {
//                                it->second.m_peer_requests_time.emplace(std::make_unique<common::vote_request_entry>(payload), now);
//                            }
//                            it->second.m_score -= 3;
//                            it->second.m_last_seen = now;
//                        } else {
//                            if (acl.size() >= blockchain_acl_max_peers) {
//                                // find out min score peer
//                                auto min_it = acl.begin();
//                                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
//                                    if (iter->second.m_score  < min_it->second.m_score) {
//                                        min_it = iter;
//                                    }
//                                }
//
//                                if (min_it->second.m_score < peer_info().m_score) {
//                                    // replace min score peer with new one
//                                    acl.erase(min_it);
//                                    acl[peer] = peer_info(now);
//                                    acl[peer].m_peer_requests_time.emplace(std::make_unique<common::vote_request_entry>(payload), now);
//
//                                    introduce_gossip_peers(chain_id, peer);
//                                }
//                            } else {
//                                acl[peer] = peer_info(now);
//                                acl[peer].m_peer_requests_time.emplace(std::make_unique<common::vote_request_entry>(payload), now);
//
//                                introduce_gossip_peers(chain_id, peer);
//                            }
//                        }
//
//                        // vote for voting point
//                        auto &voting_point_block = m_voting_point_blocks[chain_id];
//                        if (is_sync_completed(chain_id) && !voting_point_block.empty()) {
//                            common::vote_entry voteEntry(chain_id,vote(voting_point_block.sha256(),
//                                                                       voting_point_block.cumulative_difficulty(),
//                                                                       voting_point_block.block_number()));
//                            send_to(chain_id, peer, common::vote_entry::data_type_id, voteEntry.get_entry(), true);
//                        }
//
//                        break;
//                    }
//                    case common::vote_entry::data_type_id: {
//                        common::vote_entry voteEntry(payload);
//                        auto &chain_id = voteEntry.m_chain_id;
//
//                        {
//                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
//                            if (it == m_chains.end()) {
//                                log("INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
//                                return;
//                            }
//                        }
//
//                        try_to_kick_out_of_ban_list(chain_id, peer);
//
//                        auto &acl = m_access_list[chain_id];
//                        auto it = acl.find(peer);
//                        if (it != acl.end()) {
//                            it->second.m_score += 3;
//                            if (it->second.m_score > 100) {
//                                it->second.m_score = 100;
//                            }
//                            it->second.m_requests_time.erase(std::make_unique<common::vote_request_entry>(chain_id));
//                            it->second.m_last_seen = now;
//                        } else {
//                            if (acl.size() >= blockchain_acl_max_peers) {
//                                // find out min score peer
//                                auto min_it = acl.begin();
//                                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
//                                    if (iter->second.m_score  < min_it->second.m_score) {
//                                        min_it = iter;
//                                    }
//                                }
//
//                                if (min_it->second.m_score < peer_info().m_score) {
//                                    // replace min score peer with new one
//                                    acl.erase(min_it);
//                                    acl[peer] = peer_info(now);
//
//                                    introduce_gossip_peers(chain_id, peer);
//                                }
//                            } else {
//                                acl[peer] = peer_info(now);
//
//                                introduce_gossip_peers(chain_id, peer);
//                            }
//                        }
//
//                        log("INFO: chain[%s] valid vote[%s]",
//                            aux::toHex(chain_id).c_str(), voteEntry.m_vote.to_string().c_str());
//                        m_votes[chain_id][peer] = voteEntry.m_vote;
//
//                        break;
//                    }
                    case common::head_block_request_entry::data_type_id: {
                        common::head_block_request_entry headBlockRequestEntry(payload);
                        auto &chain_id = headBlockRequestEntry.m_chain_id;

                        {
                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                            if (it == m_chains.end()) {
                                log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                                return;
                            }
                        }

                        try_to_kick_out_of_ban_list(chain_id, peer);

                        std::unique_ptr<common::blockchain_entry_base> ptr = std::make_unique<common::head_block_request_entry>(payload);
                        if (!request_received_from_peer(chain_id, peer, ptr)) {
                            break;
                        }

                        auto &blk = m_head_blocks[chain_id];

                        if (!blk.empty()) {
                            common::head_block_entry blockEntry(blk);
                            send_to(peer, blockEntry.get_entry());
                        } else {
                            log(LOG_INFO, "INFO: Cannot get head block in local");
                        }

                        break;
                    }
                    case common::head_block_entry::data_type_id: {
                        common::head_block_entry blk_entry(payload);

                        // TODO: validate timestamp etc. ?
                        if (!blk_entry.m_blk.empty()) {
                            auto &chain_id = blk_entry.m_blk.chain_id();

                            {
                                auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                                if (it == m_chains.end()) {
                                    log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                                    return;
                                }
                            }

                            try_to_kick_out_of_ban_list(chain_id, peer);

                            auto &acl = m_access_list[chain_id];

                            if (acl.empty()) {
                                auto peers = blk_entry.m_blk.get_block_peers();
                                peers.erase(*m_ses.pubkey());
                                if (!peers.empty()) {
                                    add_gossip_peers(chain_id, peers);
                                }
                            }

                            head_block_received_from_peer(chain_id, peer, blk_entry.m_blk);

                            log(LOG_INFO, "INFO: Got head block[%s] from peer[%s].",
                                blk_entry.m_blk.to_string().c_str(), aux::toHex(peer.bytes).c_str());

                            m_repository->save_block(blk_entry.m_blk);

//                            m_blocks[chain_id][blk_entry.m_blk.sha256()] = blk_entry.m_blk;

                            if (is_empty_chain(chain_id)) {
                                process_block(chain_id, blk_entry.m_blk);
                            }

                            if (blk_entry.m_blk.cumulative_difficulty() > m_head_blocks[chain_id].cumulative_difficulty()) {
                                m_ses.alerts().emplace_alert<blockchain_syncing_head_block_alert>(peer, blk_entry.m_blk);
                            }

                            // notify ui tx from block
                            if (!blk_entry.m_blk.tx().empty()) {
                                m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(blk_entry.m_blk.tx());
                            }

                            block_reception_event(chain_id, blk_entry.m_blk);
                        }

                        break;
                    }
//                    case common::state_request_entry::data_type_id: {
//                        common::state_request_entry stateRequestEntry(payload);
//                        auto &chain_id = stateRequestEntry.m_chain_id;
//
//                        {
//                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
//                            if (it == m_chains.end()) {
//                                log("INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
//                                return;
//                            }
//                        }
//
//                        log("INFO: chain[%s] request state", aux::toHex(chain_id).c_str());
//
//                        try_to_kick_out_of_ban_list(chain_id, peer);
//
//                        auto &acl = m_access_list[chain_id];
//                        auto it = acl.find(peer);
//                        if (it != acl.end()) {
//                            auto itor = it->second.m_peer_requests_time.find(std::make_unique<common::state_request_entry>(payload));
//                            if (itor != it->second.m_peer_requests_time.end()) {
//                                if (now > itor->second + blockchain_same_response_interval) {
//                                    it->second.m_peer_requests_time.erase(itor);
//                                } else {
//                                    log("INFO: The same request from the same peer in 3s.");
//                                    break;
//                                }
//                            } else {
//                                it->second.m_peer_requests_time.emplace(std::make_unique<common::state_request_entry>(payload), now);
//                            }
//                            it->second.m_score -= 3;
//                            it->second.m_last_seen = now;
//                        } else {
//                            if (acl.size() >= blockchain_acl_max_peers) {
//                                // find out min score peer
//                                auto min_it = acl.begin();
//                                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
//                                    if (iter->second.m_score  < min_it->second.m_score) {
//                                        min_it = iter;
//                                    }
//                                }
//
//                                if (min_it->second.m_score < peer_info().m_score) {
//                                    // replace min score peer with new one
//                                    acl.erase(min_it);
//                                    acl[peer] = peer_info(now);
//                                    acl[peer].m_peer_requests_time.emplace(std::make_unique<common::state_request_entry>(payload), now);
//
//                                    introduce_gossip_peers(chain_id, peer);
//                                } else {
//                                    log("INFO: Too many peers in acl to response.");
//                                    introduce_gossip_peers(chain_id, peer);
//                                    break;
//                                }
//                            } else {
//                                acl[peer] = peer_info(now);
//                                acl[peer].m_peer_requests_time.emplace(std::make_unique<common::state_request_entry>(payload), now);
//
//                                introduce_gossip_peers(chain_id, peer);
//                            }
//                        }
//
//                        auto act = m_repository->get_account(chain_id, peer);
//
//                        if (!act.empty()) {
//                            common::state_entry stateEntry(chain_id, act);
//                            send_to(chain_id, peer, common::state_entry::data_type_id, stateEntry.get_entry(), true);
//                        }
//
//                        break;
//                    }
//                    case common::state_entry::data_type_id: {
//                        common::state_entry stateEntry(payload);
//                        auto &chain_id = stateEntry.m_chain_id;
//
//                        {
//                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
//                            if (it == m_chains.end()) {
//                                log("INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
//                                return;
//                            }
//                        }
//
//                        try_to_kick_out_of_ban_list(chain_id, peer);
//
//                        auto &acl = m_access_list[chain_id];
//                        auto it = acl.find(peer);
//                        if (it != acl.end()) {
//                            it->second.m_score += 3;
//                            if (it->second.m_score > 100) {
//                                it->second.m_score = 100;
//                            }
//                            it->second.m_requests_time.erase(std::make_unique<common::state_request_entry>(chain_id));
//                            it->second.m_last_seen = now;
//                        } else {
//                            if (acl.size() >= blockchain_acl_max_peers) {
//                                // find out min score peer
//                                auto min_it = acl.begin();
//                                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
//                                    if (iter->second.m_score  < min_it->second.m_score) {
//                                        min_it = iter;
//                                    }
//                                }
//
//                                if (min_it->second.m_score < peer_info().m_score) {
//                                    // replace min score peer with new one
//                                    acl.erase(min_it);
//                                    acl[peer] = peer_info(now);
//
//                                    introduce_gossip_peers(chain_id, peer);
//                                }
//                            } else {
//                                acl[peer] = peer_info(now);
//
//                                introduce_gossip_peers(chain_id, peer);
//                            }
//                        }
//
//                        log("INFO: chain[%s] Got state",
//                            aux::toHex(chain_id).c_str());
//
//                        auto &act = stateEntry.m_act;
//
//                        if (!act.empty()) {
//                            m_ses.alerts().emplace_alert<blockchain_state_alert>(chain_id, act);
//                        }
//
//                        break;
//                    }
//                    case common::transaction_reply_entry::data_type_id: {
//                        common::transaction_reply_entry txReplyEntry(payload);
//                        auto &chain_id = txReplyEntry.m_chain_id;
//
//                        {
//                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
//                            if (it == m_chains.end()) {
//                                log("INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
//                                return;
//                            }
//                        }
//
//                        try_to_kick_out_of_ban_list(chain_id, peer);
//
//                        auto &acl = m_access_list[chain_id];
//                        auto it = acl.find(peer);
//                        if (it != acl.end()) {
//                            it->second.m_score += 3;
//                            if (it->second.m_score > 100) {
//                                it->second.m_score = 100;
//                            }
//                            it->second.m_last_seen = now;
//                        } else {
//                            if (acl.size() >= blockchain_acl_max_peers) {
//                                // find out min score peer
//                                auto min_it = acl.begin();
//                                for (auto iter = acl.begin(); iter != acl.end(); iter++) {
//                                    if (iter->second.m_score  < min_it->second.m_score) {
//                                        min_it = iter;
//                                    }
//                                }
//
//                                if (min_it->second.m_score < peer_info().m_score) {
//                                    // replace min score peer with new one
//                                    acl.erase(min_it);
//                                    acl[peer] = peer_info(now);
//
//                                    introduce_gossip_peers(chain_id, peer);
//                                }
//                            } else {
//                                acl[peer] = peer_info(now);
//
//                                introduce_gossip_peers(chain_id, peer);
//                            }
//                        }
//
//                        log("INFO: chain[%s] Got tx reply", aux::toHex(txReplyEntry.m_hash).c_str());
//
//                        if (!txReplyEntry.m_hash.is_all_zeros()) {
//                            m_ses.alerts().emplace_alert<blockchain_tx_confirmation_alert>(chain_id, peer, txReplyEntry.m_hash);
//                        }
//
//                        break;
//                    }
                    case common::gossip_peers_entry::data_type_id: {
                        common::gossip_peers_entry gossipPeersEntry(payload);
                        auto &chain_id = gossipPeersEntry.m_chain_id;

                        {
                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                            if (it == m_chains.end()) {
                                log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                                return;
                            }
                        }

                        try_to_kick_out_of_ban_list(chain_id, peer);

                        data_received_from_peer(chain_id, peer, 3);

                        if (!gossipPeersEntry.m_peers.empty()) {
                            auto peers = gossipPeersEntry.m_peers;
                            for (auto const &pubkey: peers) {
                                log(LOG_INFO, "Got gossip peer:%s", aux::toHex(pubkey.bytes).c_str());
                            }
                            peers.erase(*m_ses.pubkey());
                            if (!peers.empty()) {
                                add_gossip_peers(chain_id, peers);
                            }
                        }

                        if (gossipPeersEntry.m_balance > 0) {
                            log(LOG_INFO, "Chain[%s] gossip state[%" PRId64 "]", aux::toHex(chain_id).c_str(), gossipPeersEntry.m_balance);
                            account act(gossipPeersEntry.m_balance);
                            if (now > m_last_balance_alert_time[chain_id] + 60 * 1000) {
                                m_ses.alerts().emplace_alert<blockchain_state_alert>(chain_id, act);

                                m_last_balance_alert_time[chain_id] = now;
                            }
                        }

                        break;
                    }
                    case common::ping_entry::data_type_id: {
                        common::ping_entry pingEntry(payload);
                        auto &chain_id = pingEntry.m_chain_id;

                        {
                            auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
                            if (it == m_chains.end()) {
                                log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                                return;
                            }
                        }

                        try_to_kick_out_of_ban_list(chain_id, peer);

                        data_received_from_peer(chain_id, peer, 5);

                        log(LOG_INFO, "INFO: chain[%s] Got ping", aux::toHex(chain_id).c_str());

                        break;
                    }
                    default: {
                    }
                }
            }
        } catch (std::exception &e) {
            log(LOG_ERR, "ERROR: Receive exception data.");
        }

    }

    void blockchain::print_acl_ban_list_info(const aux::bytes &chain_id) {
        // peer list log
        // acl
        auto &acl = m_access_list[chain_id];
        for (auto const &item: acl) {
            log(LOG_INFO, "-----ACL: peer[%s], info[%s]", aux::toHex(item.first.bytes).c_str(),
                item.second.to_string().c_str());
        }
        // ban list
        auto &ban_list = m_ban_list[chain_id];
        for (auto const &item: ban_list) {
            log(LOG_INFO, "-----Ban List: peer[%s], info[%s]", aux::toHex(item.first.bytes).c_str(),
                item.second.to_string().c_str());
        }
    }

}
