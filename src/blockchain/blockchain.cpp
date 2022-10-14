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
            // db init
            if (!m_repository->init()) {
                log(LOG_INFO, "INFO: Blockchain init fail!");
                return false;
            }

            // get all chains
            m_chains = m_repository->get_all_chains();
            for (auto const& chain_id: m_chains) {
                m_chain_connected[chain_id] = false;
            }
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

        for (auto const& chain_id: m_chains) {
            try {
                if (!init_chain(chain_id)) {
                    log(LOG_ERR, "INFO: Init chain[%s] fail", aux::toHex(chain_id).c_str());
                    m_chain_connected[chain_id] = true;
                    return false;
                }
            } catch(std::exception &e) {
                log(LOG_ERR, "Exception init chain %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
                continue;
            }
        }

        m_stop = false;

        m_dht_tasks_timer.expires_after(milliseconds(50));
        m_dht_tasks_timer.async_wait(std::bind(&blockchain::refresh_dht_task_timer, self(), _1));

        m_refresh_timer.expires_after(milliseconds(100));
        m_refresh_timer.async_wait(std::bind(&blockchain::refresh_timeout, self(), _1));

        return true;
    }

    bool blockchain::stop()
    {
        m_stop = true;

        m_refresh_timer.cancel();

        for (auto& timer: m_chain_timers) {
            timer.second.cancel();
        }

        m_dht_tasks_timer.cancel();

        for (auto const& chain_id: m_chains) {
            m_repository->clear_acl_db(chain_id);
            auto const &acl = m_access_list[chain_id];
            for (auto const& item: acl) {
                m_repository->add_peer_in_acl_db(chain_id, item.first);
            }
        }

//        for (auto& timer: m_chain_status_timers) {
//            timer.second.cancel();
//        }

        clear_all_cache();

        log(LOG_INFO, "INFO: Stop BlockChain...");

        return true;
    }

    void blockchain::account_changed() {
        log(LOG_INFO, "INFO: Change account..");

//        m_access_list.clear();
    }

    void blockchain::on_pause() {
        log(LOG_INFO, "Block chain is on pause");
        m_pause = true;
    }

    void blockchain::on_resume() {
        log(LOG_INFO, "Block chain is on resume");
        m_pause = false;

//        m_refresh_timer.cancel();

        for (auto& timer: m_chain_timers) {
            timer.second.cancel();
        }
    }

    bool blockchain::create_chain_db(const bytes &chain_id) {
        // create sqlite peer db
        if (!m_repository->create_block_db(chain_id)) {
            log(LOG_ERR, "INFO: chain:%s, create block db fail.", aux::toHex(chain_id).c_str());
            return false;
        }
        if (!m_repository->create_state_db(chain_id)) {
            log(LOG_ERR, "INFO: chain:%s, create state db fail.", aux::toHex(chain_id).c_str());
            return false;
        }
        if (!m_repository->create_state_array_db(chain_id)) {
            log(LOG_ERR, "INFO: chain:%s, create state array db fail.", aux::toHex(chain_id).c_str());
            return false;
        }
        if (!m_repository->create_peer_db(chain_id)) {
            log(LOG_ERR, "INFO: chain:%s, create bootstrap db fail.", aux::toHex(chain_id).c_str());
            return false;
        }
        if (!m_repository->create_acl_db(chain_id)) {
            log(LOG_ERR, "INFO: chain:%s, create acl db fail.", aux::toHex(chain_id).c_str());
            return false;
        }

        return true;
    }

    bool blockchain::followChain(const aux::bytes &chain_id, const std::set<dht::public_key>& peers) {
        if (m_chains.find(chain_id) != m_chains.end()) {
            log(LOG_INFO, "INFO: Already followed chain[%s]", aux::toHex(chain_id).c_str());
            return true;
        }

        if (!chain_id.empty()) {
            log(LOG_INFO, "INFO: Follow chain:%s", aux::toHex(chain_id).c_str());

            // create db
            if (!create_chain_db(chain_id))
                return false;

            // add bootstrap into db
            for (auto const &peer: peers) {
                log(LOG_INFO, "INFO: chain:%s, bootstrap peer:%s", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                if (!m_repository->add_peer_in_peer_db(chain_id, peer)) {
                    log(LOG_ERR, "INFO: chain:%s, insert bootstrap peer:%s fail in db.", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                }
            }

            // follow chain id in memory and db
            if (!m_repository->add_new_chain(chain_id)) {
                log(LOG_ERR, "INFO: Add new chain[%s] fail", aux::toHex(chain_id).c_str());
                return false;
            }
            m_chains.insert(chain_id);

            if (!init_chain(chain_id)) {
                log(LOG_ERR, "INFO: Init chain[%s] fail", aux::toHex(chain_id).c_str());
                return false;
            }

            m_chain_connected[chain_id] = false;

            // connect chain
            connect_chain(chain_id);

            return true;
        } else {
            return false;
        }
    }

    bool blockchain::add_new_bootstrap_peers(const aux::bytes &chain_id, const std::set<dht::public_key> &peers) {
        if (m_chains.find(chain_id) == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return false;
        }

        if (!m_chain_connected[chain_id]) {
            log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
            return false;
        }

        // add peer into db
        for (auto const &peer: peers) {
            log(LOG_INFO, "INFO: chain:%s, add peer:%s", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
            if (!m_repository->add_peer_in_peer_db(chain_id, peer)) {
                log(LOG_ERR, "INFO: chain:%s, insert peer:%s fail in db.", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
            }
        }

        return true;
    }

    bool blockchain::unfollowChain(const aux::bytes &chain_id) {
        log(LOG_INFO, "INFO: Unfollow chain:%s", aux::toHex(chain_id).c_str());

        if (m_chains.find(chain_id) != m_chains.end()) {
            m_chains.erase(chain_id);

            // remove chain id from db
            if (!m_repository->delete_chain(chain_id)) {
                log(LOG_ERR, "INFO: chain:%s, delete chain fail.", aux::toHex(chain_id).c_str());
                return false;
            }

            if (!m_repository->delete_block_db(chain_id)) {
                log(LOG_ERR, "INFO: chain:%s, delete block db fail.", aux::toHex(chain_id).c_str());
                return false;
            }

            if (!m_repository->delete_state_db(chain_id)) {
                log(LOG_ERR, "INFO: chain:%s, delete state db fail.", aux::toHex(chain_id).c_str());
                return false;
            }

            if (!m_repository->delete_state_array_db(chain_id)) {
                log(LOG_ERR, "INFO: chain:%s, delete state array db fail.", aux::toHex(chain_id).c_str());
                return false;
            }

            if (!m_repository->delete_peer_db(chain_id)) {
                log(LOG_ERR, "INFO: chain:%s, delete peer db fail.", aux::toHex(chain_id).c_str());
                return false;
            }
            if (!m_repository->delete_acl_db(chain_id)) {
                log(LOG_ERR, "INFO: chain:%s, delete acl db fail.", aux::toHex(chain_id).c_str());
                return false;
            }

            // cancel
            auto it_chain_timer = m_chain_timers.find(chain_id);
            if (it_chain_timer != m_chain_timers.end()) {
                it_chain_timer->second.cancel();
            }
//            auto it_chain_status_timer = m_chain_status_timers.find(chain_id);
//            if (it_chain_status_timer != m_chain_status_timers.end()) {
//                it_chain_status_timer->second.cancel();
//            }
            // remove chain cache
            clear_chain_cache(chain_id);
            // todo: clear data in db?
        }

        return true;
    }

    void blockchain::peer_preparation(const bytes &chain_id) {
        // add peer into acl
        std::set<dht::public_key> peers = m_repository->get_all_peer_in_acl_db(chain_id);
        if (peers.size() < blockchain_acl_max_peers) {
            if (!is_empty_chain(chain_id)) {
                // get 8 peers from miner
                auto blk = m_head_blocks[chain_id];
                for (int i = 0; i < CHAIN_EPOCH_BLOCK_SIZE; i++) {
                    log(LOG_INFO, "INFO: chain[%s] acl block[%s]",
                        aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                    if (blk.miner() != *m_ses.pubkey()) {
                        peers.insert(blk.miner());
                    }
                    blk = m_repository->get_block_by_hash(chain_id, blk.previous_block_hash());

                    if (peers.size() >= blockchain_acl_max_peers / 2 || blk.empty()) {
                        break;
                    }
                }
            }

            if (peers.size() < blockchain_acl_max_peers) {
                std::size_t size = blockchain_acl_max_peers - peers.size();

                for (int i = 0; i < size; i++) {
                    auto peer = m_repository->get_peer_from_state_db_randomly(chain_id);
                    log(LOG_INFO, "INFO: chain[%s] add peer[%s] from state db into acl",
                        aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                    if (!peer.is_all_zeros() && peer != *m_ses.pubkey()) {
                        peers.insert(peer);
                    }
                }
            }

            if (peers.size() < blockchain_acl_max_peers) {
                std::size_t size = blockchain_acl_max_peers - peers.size();
                for (int i = 0; i < size; i++) {
                    auto peer = m_repository->get_peer_from_peer_db_randomly(chain_id);
                    log(LOG_INFO, "INFO: chain[%s] add peer[%s] from peer db into acl",
                        aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
                    if (!peer.is_all_zeros() && peer != *m_ses.pubkey()) {
                        peers.insert(peer);
                    }
                }
            }
        }

        for (auto const& peer: peers) {
            log(LOG_INFO, "INFO: chain[%s] add peer[%s] into acl",
                aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
            add_peer_into_acl(chain_id, peer, 0);
        }
    }

    bool blockchain::init_chain(const bytes &chain_id) {
        aux::bytes short_chain_id;
        if (chain_id.size() > short_chain_id_length) {
            short_chain_id.insert(short_chain_id.end(), chain_id.begin(), chain_id.begin() + short_chain_id_length);
        } else {
            short_chain_id = chain_id;
        }
        m_short_chain_id_table[short_chain_id] = chain_id;

        m_chain_getting_times[chain_id] = 0;

        // create tx pool
        m_tx_pools[chain_id] = tx_pool(m_repository.get());

        // TODO: remove in the future
        if (!m_repository->create_acl_db(chain_id)) {
            log(LOG_ERR, "INFO: chain:[%s] create acl db fail.", aux::toHex(chain_id).c_str());
            return false;
        }

        // load key point block in memory
        // load head/tail/consensus block
        auto head_block = m_repository->get_head_block(chain_id);
        if (!head_block.empty()) {
            m_head_blocks[chain_id] = head_block;
            log(LOG_INFO, "INFO: Head block: %s", head_block.to_string().c_str());
        }

        return true;
    }

    bool blockchain::connect_chain(const aux::bytes &chain_id) {
        log(LOG_INFO, "INFO: connect chain[%s]", aux::toHex(chain_id).c_str());

        if (!m_chain_connected[chain_id]) {
            peer_preparation(chain_id);

//        get_pool_from_peer(chain_id, *m_ses.pubkey());
            get_transfer_transaction(chain_id, *m_ses.pubkey());

            // create chain status timer
//        m_chain_status_timers.emplace(chain_id, aux::deadline_timer(m_ioc));
//        // set chain status
//        auto i = m_chain_status_timers.find(chain_id);
//        if (i != m_chain_status_timers.end()) {
//            i->second.expires_after(milliseconds (100));
//            i->second.async_wait(std::bind(&blockchain::refresh_chain_status, self(), _1, chain_id));
//        }

            // create chain timer
            m_chain_timers.emplace(chain_id, aux::deadline_timer(m_ioc));
            // start mining
            auto it = m_chain_timers.find(chain_id);
            if (it != m_chain_timers.end()) {
                it->second.expires_after(milliseconds(150));
                it->second.async_wait(std::bind(&blockchain::refresh_mining_timeout, self(), _1, chain_id));
            }

            m_chain_connected[chain_id] = true;
        }

        send_online_signal(chain_id);

        auto const& acl = m_access_list[chain_id];
        for (auto const& item: acl) {
            // get note tx
            get_note_pool_root(chain_id, item.first, 0);
        }

        return true;
    }

//    void blockchain::try_to_get_again() {
//        auto now = get_total_milliseconds();
//        for (auto it = m_get_item_info.begin(); it != m_get_item_info.end();) {
//            if (it->second.m_times >= 3) {
//                m_get_item_info.erase(it++);
//
//                // remove from acl
//                m_access_list[it->first.m_chain_id].erase(it->first.m_peer);
//            } else {
//                if (now > it->second.m_timestamp + blockchain_get_timeout) {
//                    subscribe(it->first.m_chain_id, it->first.m_peer, it->first.m_salt, it->first.m_type);
//                }
//
//                it++;
//            }
//        }
//    }

//    void blockchain::manage_peers_in_acl_ban_list(const aux::bytes &chain_id) {
//        auto now = get_total_milliseconds();

        // calc score
//        auto &acl = m_access_list[chain_id];
//        for (auto &item: acl) {
//            auto &requests_time = item.second.m_requests_time;
//            for (auto it = requests_time.begin(); it != requests_time.end();) {
//                if (now > it->second + blockchain_request_timeout) {
//                    item.second.m_score = item.second.m_score - 8;
//                    requests_time.erase(it++);
//                } else {
//                    it++;
//                }
//            }
//        }

        // kick out bad peer from acl and add it into ban list
//        for (auto it = acl.begin(); it != acl.end();) {
//            if (it->second.m_score <= 0 ||
//                (it->second.m_stage == NORMAL && now > it->second.m_last_seen + 210 * 1000)) {
//                auto &ban_list = m_ban_list[chain_id];
//                ban_list[it->first] = ban_info(now + blockchain_min_ban_time);
//
//                acl.erase(it++);
//            } else {
//                it++;
//            }
//        }

        // remove surplus peers
//        if (acl.size() > blockchain_acl_max_peers) {
//            // find out min score peer
//            auto min_it = acl.begin();
//            for (auto iter = acl.begin(); iter != acl.end(); iter++) {
//                if (iter->second.m_score < min_it->second.m_score) {
//                    min_it = iter;
//                }
//            }
//
//            acl.erase(min_it);
//        }
//    }

//    void blockchain::add_and_access_peers_in_acl(const aux::bytes &chain_id) {
//        auto now = get_total_milliseconds();
//
//        auto &acl = m_access_list[chain_id];
//        auto size = acl.size();
//        if (size < blockchain_acl_min_peers) {
//            std::set<dht::public_key> peers;
//            for (auto i = blockchain_acl_min_peers - size; i > 0; i--) {
//                auto peer = select_peer_randomly(chain_id);
////              log("INFO: Chain[%s] select peer[%s]", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
//                // if peer is not in acl, not been banned
//                if (!peer.is_all_zeros() &&
//                    acl.find(peer) == acl.end() & peer != *m_ses.pubkey()) {
//                    peers.insert(peer);
//                }
//            }
//
//            // all peers those added into acl should request head block
//            for (auto const &peer: peers) {
//                acl[peer] = peer_info();
//            }
//        }

        // check if need to request on current stage
//        for (auto &item: acl) {
//            if (item.second.m_stage == HEAD_BLOCK) {
//                if (item.second.m_requests_time.find(
//                        std::make_unique<common::head_block_request_entry>(chain_id))
//                    == item.second.m_requests_time.end()) {
//                    common::head_block_request_entry headBlockRequestEntry(chain_id);
//                    send_to(item.first, headBlockRequestEntry.get_entry());
//
//                    item.second.m_requests_time[std::make_unique<common::head_block_request_entry>(chain_id)] = now;
//                }
//            } else if (item.second.m_stage == NORMAL) {
//                if (!item.second.m_gossip_done) {
//                    introduce_gossip_peers(chain_id, item.first);
//
//                    item.second.m_gossip_done = true;
//                }
//                if (!item.second.m_fee_tx_pool_sync_done) {
//                    common::fee_tx_pool_entry feeTxPoolEntry(chain_id, m_tx_pools[chain_id].get_hash_prefix_array_by_fee());
//                    send_to(item.first, feeTxPoolEntry.get_entry());
//
//                    item.second.m_fee_tx_pool_sync_done = true;
//                }
//                if (!item.second.m_time_tx_pool_sync_done) {
//                    common::time_tx_pool_entry txPoolEntry(chain_id, m_tx_pools[chain_id].get_hash_prefix_array_by_timestamp());
//                    send_to(item.first, txPoolEntry.get_entry());
//
//                    item.second.m_time_tx_pool_sync_done = true;
//                }
                // ping every minute
//                if (now > item.second.m_last_ping_time + 60 * 1000) {
//                    common::ping_entry pingEntry(chain_id);
//                    send_to(item.first, pingEntry.get_entry());
//
//                    item.second.m_last_ping_time = now;
//                }
//            }
//        }
//    }

    std::int64_t blockchain::get_total_milliseconds() {
        return total_milliseconds(system_clock::now().time_since_epoch());
    }

    std::int64_t blockchain::get_total_microseconds() {
        return total_microseconds(system_clock::now().time_since_epoch());
    }

    void blockchain::clear_all_cache() {
        m_chains.clear();
        m_tx_pools.clear();
//        m_chain_status.clear();
        m_chain_timers.clear();
//        m_chain_status_timers.clear();
        m_access_list.clear();
//        m_blocks.clear();
        m_head_blocks.clear();
//        m_gossip_peers.clear();
    }

    void blockchain::clear_chain_cache(const aux::bytes &chain_id) {
//        m_chains.erase(chain_id);
        m_tx_pools[chain_id].clear();
        m_chain_connected.erase(chain_id);
//        m_chain_status.erase(chain_id);
        m_chain_timers.erase(chain_id);
//        m_chain_status_timers.erase(chain_id);
        m_access_list.erase(chain_id);
//        m_blocks[chain_id].clear();
        m_head_blocks.erase(chain_id);
//        m_gossip_peers[chain_id].clear();
    }

//    void blockchain::try_to_clear_outdated_data_in_db(const aux::bytes &chain_id) {
//        auto const& head_block = m_head_blocks[chain_id];
//        if (!head_block.empty() && head_block.block_number() > OUTDATED_BLOCK_NUMBER) {
//            // remove outdated data from db
//            m_repository->delete_all_outdated_data(chain_id, head_block.block_number() - OUTDATED_BLOCK_NUMBER);
//        }
//    }


    void blockchain::refresh_timeout(const error_code &e) {
        if ((e.value() != 0 && e.value() != boost::asio::error::operation_aborted) || m_stop) return;

        try {
            bool found = false;
            // 随机挑选一条
            for (auto const &chain_id: m_chains) {
                if (!m_chain_connected[chain_id]) {
                    log(LOG_INFO, "INFO: Select chain:%s", aux::toHex(chain_id).c_str());
                    connect_chain(chain_id);

                    found = true;

                    break;
                }
            }

            if (found) {
                m_refresh_timer.expires_after(milliseconds(300));
                m_refresh_timer.async_wait(std::bind(&blockchain::refresh_timeout, self(), _1));
            }
        } catch (std::exception &e) {
            log(LOG_ERR, "Exception init [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    void blockchain::refresh_dht_task_timer(const error_code &e) {
        if ((e.value() != 0 && e.value() != boost::asio::error::operation_aborted) || m_stop) return;

        try {
            auto now = get_total_milliseconds();
            std::int64_t interval = blockchain_max_refresh_time;
//            log(LOG_INFO, "INFO: DHT item queue size[%" PRIu64 "]", m_tasks.size());
            if (!m_pause && !m_tasks.empty()) {
                if (now >= m_last_dht_time + blockchain_min_refresh_time) {
                    auto const &dhtItem = m_tasks.front();
//                log(LOG_INFO, "INFO: DHT item[%s]", dhtItem.to_string().c_str());
                    switch (dhtItem.m_type) {
                        case dht_item_type::DHT_GET: {

                            m_ses.dht()->get_item(dhtItem.m_peer,
                                                  std::bind(&blockchain::get_mutable_callback, self(),
                                                            dhtItem.m_chain_id, _1, _2, dhtItem.m_get_item_type,
                                                            dhtItem.m_timestamp, dhtItem.m_times),
                                                  1, 8, 16, dhtItem.m_salt, dhtItem.m_timestamp);

                            break;
                        }
                        case dht_item_type::DHT_PUT: {
                            m_ses.dht()->put_item(dhtItem.m_data,
                                                  std::bind(&blockchain::on_dht_put_mutable_item, self(), _1, _2),
                                                  1, 8, 16, dhtItem.m_salt);

                            break;
                        }
                        case dht_item_type::DHT_PUT_TX: {
                            m_ses.dht()->put_item(dhtItem.m_data,
                                                  std::bind(&blockchain::on_dht_put_transaction, self(),
                                                            dhtItem.m_chain_id, dhtItem.m_hash, _1, _2),
                                                  1, 8, 16, dhtItem.m_salt);

                            break;
                        }
                        case dht_item_type::DHT_SEND: {
                            m_ses.dht()->send(dhtItem.m_peer, dhtItem.m_data, 1, 8, 16, 1,
                                              std::bind(&blockchain::on_dht_relay_mutable_item, self(), _1, _2,
                                                        dhtItem.m_peer));

                            break;
                        }
                        default: {
                            log(LOG_ERR, "INFO: Unknown type[%d]", dhtItem.m_type);
                        }
                    }

//                m_tasks_set.erase(dhtItem);
                    m_tasks.pop();
//                if (m_tasks_set.size() != m_tasks.size()) {
//                    log(LOG_ERR, "================:%s", dhtItem.to_string().c_str());
//                }

                    interval = blockchain_min_refresh_time;
                    m_last_dht_time = now;
                } else {
                    interval = m_last_dht_time + blockchain_min_refresh_time - now;
                }
            }

            m_dht_tasks_timer.expires_after(milliseconds(interval));
            m_dht_tasks_timer.async_wait(std::bind(&blockchain::refresh_dht_task_timer, self(), _1));
        } catch (std::exception &e) {
            log(LOG_ERR, "Exception init [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

//    void blockchain::reset_chain_status(const aux::bytes &chain_id) {
//        m_chain_status[chain_id] = GET_GOSSIP_PEERS;
//    }

//    void blockchain::refresh_chain_status(const error_code &e, const aux::bytes &chain_id) {
//        if ((e.value() != 0 && e.value() != boost::asio::error::operation_aborted) || m_stop) return;
//
//        try {
//            // reset chain status
//            log(LOG_INFO, "INFO: reset chain[%s] status", aux::toHex(chain_id).c_str());
//            reset_chain_status(chain_id);
//
//            auto i = m_chain_status_timers.find(chain_id);
//            if (i != m_chain_status_timers.end()) {
//                i->second.expires_after(seconds(blockchain_status_reset_interval));
//                i->second.async_wait(std::bind(&blockchain::refresh_chain_status, self(), _1, chain_id));
//            }
//        } catch (std::exception &e) {
//            log(LOG_ERR, "Exception vote [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
//        }
//    }

    void blockchain::refresh_mining_timeout(const error_code &e, const aux::bytes &chain_id) {
        if ((e.value() != 0 && e.value() != boost::asio::error::operation_aborted) || m_stop) {
            log(LOG_ERR, "ERROR: refresh_mining_timeout:%d", e.value());
            return;
        }

        try {
//            log(LOG_INFO, "INFO: 1. Chain[%s] status[%d]", aux::toHex(chain_id).c_str(), m_chain_status[chain_id]);

            long refresh_time = DEFAULT_BLOCK_TIME * 1000;

            if (!m_pause) {
                // try to mine on the best chain
                if (m_counters[counters::dht_nodes] > 0) {
                    if (!is_empty_chain(chain_id)) {
                        dht::secret_key *sk = m_ses.serkey();
                        dht::public_key *pk = m_ses.pubkey();

                        const auto &head_block = m_head_blocks[chain_id];
                        log(LOG_INFO, "INFO: chain id[%s] head block[%s]",
                            aux::toHex(chain_id).c_str(), head_block.to_string().c_str());

                        block ancestor;
                        auto previous_hash = head_block.previous_block_hash();
                        if (head_block.block_number() % CHAIN_EPOCH_BLOCK_SIZE > 3) {
                            int i = 3;
                            while (i > 0) {
                                ancestor = m_repository->get_block_by_hash(chain_id, previous_hash);
                                previous_hash = ancestor.previous_block_hash();
                                i--;
                            }
                        }

                        auto base_target = consensus::calculate_required_base_target(head_block, ancestor);
                        auto act = m_repository->get_account(chain_id, *pk);
                        log(LOG_INFO, "INFO: chain id[%s] pk[%s] account[%s]",
                            aux::toHex(chain_id).c_str(), aux::toHex(pk->bytes).c_str(), act.to_string().c_str());
                        auto genSig = consensus::calculate_generation_signature(head_block.generation_signature(), *pk);
                        auto hit = consensus::calculate_random_hit(genSig);
                        auto interval = static_cast<std::int64_t>(consensus::calculate_mining_time_interval(hit,
                                                                                                            base_target,
                                                                                                            act.power()));
                        log(LOG_INFO,
                            "INFO: chain id[%s] generation signature[%s], base target[%" PRIu64 "], hit[%" PRIu64 "]",
                            aux::toHex(chain_id).c_str(), aux::toHex(genSig.to_string()).c_str(), base_target, hit);

                        auto cumulative_difficulty = consensus::calculate_cumulative_difficulty(
                                head_block.cumulative_difficulty(), base_target);

                        std::int64_t current_time = get_total_milliseconds() / 1000; // second
                        if (current_time >= head_block.timestamp() + interval) {
                            transaction tx = m_tx_pools[chain_id].get_best_fee_transaction();

                            if (tx.empty()) {
                                tx = m_tx_pools[chain_id].get_latest_note_transaction();
                            }

//                            auto ep = m_ses.external_udp_endpoint();
                            // mine block with current time instead of (head_block.timestamp() + interval)
                            if ((head_block.block_number() + 1) % CHAIN_EPOCH_BLOCK_SIZE == 0) {
                                sha1_hash stateRoot;
                                std::vector<state_array> stateArrays;
                                get_genesis_state(chain_id, stateRoot, stateArrays);
                                log(LOG_INFO, "INFO chain[%s] genesis block state root[%s]",
                                    aux::toHex(chain_id).c_str(), aux::toHex(stateRoot).c_str());
                                block b = block(chain_id, block_version::block_version1, current_time,
                                          head_block.block_number() + 1, head_block.sha1(), base_target,
                                          cumulative_difficulty, genSig, stateRoot, tx, *pk);

                                b.sign(*pk, *sk);

                                // process mined block
                                log(LOG_INFO, "INFO chain[%s] mined genesis block[%s]",
                                    aux::toHex(chain_id).c_str(), b.to_string().c_str());

                                process_genesis_block(chain_id, b, stateArrays);
                            } else if (head_block.block_number() % CHAIN_EPOCH_BLOCK_SIZE == 0) {
                                block b = block(chain_id, block_version::block_version1, current_time,
                                                head_block.block_number() + 1, head_block.sha1(), base_target,
                                                cumulative_difficulty, genSig, head_block.sha1(), tx, *pk);

                                b.sign(*pk, *sk);

                                // process mined block
                                log(LOG_INFO, "INFO Chain[%s] mined block[%s]",
                                    aux::toHex(chain_id).c_str(), b.to_string().c_str());

                                process_block(chain_id, b);
                            } else {
                                block b = block(chain_id, block_version::block_version1, current_time,
                                          head_block.block_number() + 1, head_block.sha1(), base_target,
                                          cumulative_difficulty, genSig, head_block.multiplex_hash(), tx, *pk);

                                b.sign(*pk, *sk);

                                // process mined block
                                log(LOG_INFO, "INFO chain[%s] mined block[%s]",
                                    aux::toHex(chain_id).c_str(), b.to_string().c_str());

                                process_block(chain_id, b);
                            }

                            refresh_time = 100;
                        } else {
                            log(LOG_INFO, "INFO: chain id[%s] left time[%" PRId64 "]s",
                                aux::toHex(chain_id).c_str(), head_block.timestamp() + interval - current_time);
                            refresh_time = (head_block.timestamp() + interval - current_time) * 1000;
                        }
                    } else {
                        if (m_chain_getting_times[chain_id] >= blockchain_max_getting_times) {
                            m_ses.alerts().emplace_alert<blockchain_fail_to_get_chain_data_alert>(chain_id);
                            return;
                        }

                        // select peer randomly to get chain data
                        auto peer = m_repository->get_peer_from_peer_db_randomly(chain_id);

                        m_chain_getting_times[chain_id]++;

                        if (!peer.is_all_zeros()) {
                            get_head_block_from_peer(chain_id, peer);
                        }

                        log(LOG_INFO, "Chain[%s] get head block for 15s", aux::toHex(chain_id).c_str());
                        refresh_time = 15000;
                    }
                } else {
                    log(LOG_INFO, "Chain[%s] stop mining", aux::toHex(chain_id).c_str());
                    refresh_time = 5000;
                }
            } else {
                log(LOG_INFO, "Blockchain is paused.");
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

    RESULT blockchain::verify_block(const aux::bytes &chain_id, const block &b, const block &previous_block) {

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
                aux::toHex(chain_id).c_str(), aux::toHex(b.sha1().to_string()).c_str());
            return FAIL;
        }

        block ancestor;
        auto previous_hash = previous_block.previous_block_hash();
        if (previous_block.block_number() % CHAIN_EPOCH_BLOCK_SIZE > 3) {
            int i = 3;
            while (i > 0) {
                ancestor = m_repository->get_block_by_hash(chain_id, previous_hash);
                if (ancestor.empty()) {
                    log(LOG_INFO, "INFO chain[%s] 2. Cannot find block[%s] in db, previous_block[%s]",
                        aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str(), previous_block.to_string().c_str());
                    return FAIL;
                }
                previous_hash = ancestor.previous_block_hash();

                i--;
            }
        }

        auto base_target = consensus::calculate_required_base_target(previous_block, ancestor);
        auto act = m_repository->get_account(chain_id, b.miner());

        log(LOG_INFO, "INFO chain[%s] Account[%s] in db",aux::toHex(chain_id).c_str(), act.to_string().c_str());

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

        auto necessary_interval = consensus::calculate_mining_time_interval(hit, base_target, act.power());
        if (b.timestamp() - previous_block.timestamp() < necessary_interval) {
            log(LOG_ERR, "ERROR: Time is too short! hit:%" PRIu64 ", base target:%" PRIu64 ", power:%" PRId64 ", necessary interval:%" PRIu64 ", real interval:%" PRId64 "",
                hit, base_target, act.power(), necessary_interval, b.timestamp() - previous_block.timestamp());
            return FAIL;
        }
        log(LOG_INFO, "hit:%" PRIu64 ", base target:%" PRIu64 ", power:%" PRId64 ", interval:%" PRIu64 ", real interval:%" PRId64 "",
            hit, base_target, act.power(), necessary_interval, b.timestamp() - previous_block.timestamp());
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
                    aux::toHex(chain_id).c_str(), aux::toHex(b.sha1().to_string()).c_str());
                return FAIL;
            }
        }

        if (!tx.empty() && tx.type() == tx_type::type_transfer) {
            auto sender_act = m_repository->get_account(chain_id, b.tx().sender());
            if (sender_act.balance() < tx.cost()) {
                log(LOG_ERR, "INFO chain[%s] sender account[%s] cannot cover cost:%" PRId64,
                    aux::toHex(chain_id).c_str(), sender_act.to_string().c_str(), tx.cost());
                return FAIL;
            }
        }

        return SUCCESS;
    }

    RESULT blockchain::process_genesis_block(const bytes &chain_id, const block &blk, const std::vector<state_array> &arrays) {
        log(LOG_ERR, "INFO: chain:%s process block[%s].",
            aux::toHex(chain_id).c_str(), blk.to_string().c_str());
        if (blk.empty())
            return FAIL;

        auto &head_block  = m_head_blocks[chain_id];
        if (!head_block.empty()) {
            if (blk.previous_block_hash() == head_block.sha1()) {
                std::set<dht::public_key> peers = blk.get_block_peers();

                auto result = verify_block(chain_id, blk, head_block);
                if (result != SUCCESS)
                    return result;

                m_repository->begin_transaction();

                if (!m_repository->clear_all_state(chain_id)) {
                    log(LOG_ERR, "INFO: chain:%s, clear all state fail.", aux::toHex(chain_id).c_str());
                    m_repository->rollback();
                    return FAIL;
                }
                for (auto const& stateArray: arrays) {
                    log(LOG_ERR, "INFO: chain:%s process state array[%s].",
                        aux::toHex(chain_id).c_str(), stateArray.to_string().c_str());
                    for (auto const& act: stateArray.StateArray()) {
                        if (!m_repository->save_account(chain_id, act)) {
                            log(LOG_ERR, "INFO: chain:%s, save account[%s] fail.",
                                aux::toHex(chain_id).c_str(), act.to_string().c_str());
                            m_repository->rollback();
                            return FAIL;
                        }
                    }
                }

                auto const& tx = blk.tx();
                if (!tx.empty() && tx.type() == type_transfer) {
                    std::map<dht::public_key, account> accounts;
                    for (auto const& peer: peers) {
                        accounts[peer] = m_repository->get_account(chain_id, peer);
                    }

                    accounts[blk.miner()].add_balance(tx.fee());
                    accounts[tx.receiver()].add_balance(tx.amount());
                    accounts[tx.sender()].subtract_balance(tx.cost());
                    accounts[tx.sender()].increase_nonce();
                    // add bonus to miner
                    accounts[blk.miner()].add_balance(MINER_BONUS);

                    for (auto const& item: accounts) {
                        if (!m_repository->save_account(chain_id, item.second)) {
                            log(LOG_ERR, "INFO: chain:%s, save account[%s] fail.",
                                aux::toHex(chain_id).c_str(), item.second.to_string().c_str());
                            m_repository->rollback();
                            return FAIL;
                        }
                    }
                } else {
                    // miner balance +=10, power++
                    auto miner_account = m_repository->get_account(chain_id, blk.miner());

                    miner_account.increase_power();
                    miner_account.add_balance(MINER_BONUS);

                    if (!m_repository->save_account(chain_id, miner_account)) {
                        log(LOG_ERR, "INFO: chain:%s, save miner account[%s] fail.",
                            aux::toHex(chain_id).c_str(), miner_account.to_string().c_str());
                        m_repository->rollback();
                        return FAIL;
                    }
                }

                if (!m_repository->save_main_chain_block(blk)) {
                    log(LOG_ERR, "INFO: chain:%s, save main chain block[%s] fail.",
                        aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                    m_repository->rollback();
                    return FAIL;
                }

                m_repository->commit();

                put_genesis_head_block(chain_id, blk, arrays);

                m_head_blocks[chain_id] = blk;

                // chain changed, re-check tx pool
                m_tx_pools[chain_id].recheck_account_txs(peers);
                m_tx_pools[chain_id].delete_tx_from_time_pool(blk.tx());

                m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(blk);
            }
        } else {
            std::set<dht::public_key> peers = blk.get_block_peers();

            m_repository->begin_transaction();

            if (!m_repository->clear_all_state(chain_id)) {
                log(LOG_ERR, "INFO: chain:%s, clear all state fail.", aux::toHex(chain_id).c_str());
                m_repository->rollback();
                return FAIL;
            }
            for (auto const& stateArray: arrays) {
                for (auto const& act: stateArray.StateArray()) {
                    if (!m_repository->save_account(chain_id, act)) {
                        log(LOG_ERR, "INFO: chain:%s, save account[%s] fail.",
                            aux::toHex(chain_id).c_str(), act.to_string().c_str());
                        m_repository->rollback();
                        return FAIL;
                    }
                }
            }

            auto const& tx = blk.tx();
            if (!tx.empty() && tx.type() == type_transfer) {
                std::map<dht::public_key, account> accounts;
                for (auto const& peer: peers) {
                    accounts[peer] = m_repository->get_account(chain_id, peer);
                }

                accounts[blk.miner()].add_balance(tx.fee());
                accounts[tx.receiver()].add_balance(tx.amount());
                accounts[tx.sender()].subtract_balance(tx.cost());
                accounts[tx.sender()].increase_nonce();
                // add bonus to miner
                accounts[blk.miner()].add_balance(MINER_BONUS);

                for (auto const& item: accounts) {
                    if (!m_repository->save_account(chain_id, item.second)) {
                        log(LOG_ERR, "INFO: chain:%s, save account[%s] fail.",
                            aux::toHex(chain_id).c_str(), item.second.to_string().c_str());
                        m_repository->rollback();
                        return FAIL;
                    }
                }
            } else {
                // miner balance +=10, power++
                auto miner_account = m_repository->get_account(chain_id, blk.miner());

                miner_account.increase_power();
                miner_account.add_balance(MINER_BONUS);

                if (!m_repository->save_account(chain_id, miner_account)) {
                    log(LOG_ERR, "INFO: chain:%s, save miner account[%s] fail.",
                        aux::toHex(chain_id).c_str(), miner_account.to_string().c_str());
                    m_repository->rollback();
                    return FAIL;
                }
            }

            if (!m_repository->save_main_chain_block(blk)) {
                log(LOG_ERR, "INFO: chain:%s, save main chain block[%s] fail.",
                    aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                m_repository->rollback();
                return FAIL;
            }

            m_repository->commit();

            put_genesis_head_block(chain_id, blk, arrays);

            m_head_blocks[chain_id] = blk;

            // chain changed, re-check tx pool
            m_tx_pools[chain_id].recheck_account_txs(peers);
            m_tx_pools[chain_id].delete_tx_from_time_pool(blk.tx());

            m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(blk);
        }

        add_peer_into_acl(chain_id, blk.miner(), blk.timestamp());
        auto const &tx = blk.tx();
        if (!tx.empty()) {
            add_peer_into_acl(chain_id, tx.sender(), blk.timestamp());
        }

        return SUCCESS;
    }

    RESULT blockchain::process_block(const aux::bytes &chain_id, const block &blk) {
        log(LOG_ERR, "INFO: chain:%s process block[%s].",
            aux::toHex(chain_id).c_str(), blk.to_string().c_str());
        if (blk.empty())
            return FAIL;

        auto &head_block  = m_head_blocks[chain_id];
        if (!head_block.empty()) {
            if (blk.previous_block_hash() == head_block.sha1()) {
                std::set<dht::public_key> peers = blk.get_block_peers();

                auto result = verify_block(chain_id, blk, head_block);
                if (result != SUCCESS)
                    return result;

                m_repository->begin_transaction();

                auto const& tx = blk.tx();
                if (!tx.empty() && tx.type() == type_transfer) {
                    std::map<dht::public_key, account> accounts;
                    for (auto const& peer: peers) {
                        accounts[peer] = m_repository->get_account(chain_id, peer);
                    }

                    accounts[blk.miner()].add_balance(tx.fee());
                    accounts[tx.receiver()].add_balance(tx.amount());
                    accounts[tx.sender()].subtract_balance(tx.cost());
                    accounts[tx.sender()].increase_nonce();
                    // add bonus to miner
                    accounts[blk.miner()].add_balance(MINER_BONUS);

                    for (auto const& item: accounts) {
                        if (!m_repository->save_account(chain_id, item.second)) {
                            log(LOG_ERR, "INFO: chain:%s, save account[%s] fail.",
                                aux::toHex(chain_id).c_str(), item.second.to_string().c_str());
                            m_repository->rollback();
                            return FAIL;
                        }
                    }
                } else {
                    // miner balance +=10, power++
                    auto miner_account = m_repository->get_account(chain_id, blk.miner());

                    miner_account.increase_power();
                    miner_account.add_balance(MINER_BONUS);

                    if (!m_repository->save_account(chain_id, miner_account)) {
                        log(LOG_ERR, "INFO: chain:%s, save miner account[%s] fail.",
                            aux::toHex(chain_id).c_str(), miner_account.to_string().c_str());
                        m_repository->rollback();
                        return FAIL;
                    }
                }

                if (!m_repository->save_main_chain_block(blk)) {
                    log(LOG_ERR, "INFO: chain:%s, save main chain block[%s] fail.",
                        aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                    m_repository->rollback();
                    return FAIL;
                }

                m_repository->commit();

                put_head_block(chain_id, blk);

                m_head_blocks[chain_id] = blk;

                // chain changed, re-check tx pool
                m_tx_pools[chain_id].recheck_account_txs(peers);
                m_tx_pools[chain_id].delete_tx_from_time_pool(blk.tx());

                m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(blk);

                add_peer_into_acl(chain_id, blk.miner(), blk.timestamp());
                if (!tx.empty()) {
                    add_peer_into_acl(chain_id, tx.sender(), blk.timestamp());
                }
            }
        } else {
            return FAIL;
        }

        return SUCCESS;
    }

    void blockchain::block_reception_event(const aux::bytes &chain_id, const dht::public_key& peer, const block &blk) {
//        if (m_chain_status[chain_id] == MINING) {
//            auto now = get_total_milliseconds();

//            auto &block_map = m_blocks[chain_id];

            // 1. if empty chain, init chain with the best voting block
//            if (is_empty_chain(chain_id)) {
//                log(LOG_INFO, "INFO: chain[%s] is empty...", aux::toHex(chain_id).c_str());
//                auto &best_vote = m_best_votes[chain_id];
//                if (!best_vote.empty()) {
//                    process_block(chain_id, best_vote.voting_block());
//                }
//            }

            if (!is_empty_chain(chain_id)) {
                // 2. try to connect head/tail block
//                auto &head_block = m_head_blocks[chain_id];
//                if (head_block.empty() || blk.previous_block_hash() == head_block.sha1()) {
//                    log(LOG_INFO, "INFO: process block:%s", blk.to_string().c_str());
//                    auto ret = process_block(chain_id, blk);
//                    if (ret == FAIL) {
//                        log(LOG_ERR, "ERROR: process block fail!");
//                    }
//                }

                // 3. try to sync block
//                try_to_sync_block(chain_id);

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
                try_to_rebranch_to_most_difficult_chain(chain_id, peer);

                // 5. try to re-branch to best vote
//                try_to_rebranch_to_best_vote(chain_id);

                // 6. try to mine block
                auto it_timer = m_chain_timers.find(chain_id);
                if (it_timer != m_chain_timers.end()) {
                    it_timer->second.cancel();
                }
            } else {
                if (blk.block_number() % CHAIN_EPOCH_BLOCK_SIZE == 0) {
                    get_all_state_from_peer(chain_id, peer, blk.state_root());
                } else {
                    get_block(chain_id, peer, blk.genesis_block_hash());
                }
            }
//        }
    }

    void blockchain::state_reception_event(const bytes &chain_id, const dht::public_key &peer) {
        auto& acl = m_access_list[chain_id];
        auto it = acl.find(peer);
        if (it != acl.end()) {
            if (!it->second.m_genesis_block.empty() && !it->second.m_state_hash_array.empty() &&
                it->second.m_state_hash_array.sha1() == it->second.m_genesis_block.state_root()) {
                std::vector<state_array> arrays;
                for (auto const& hash: it->second.m_state_hash_array.HashArray()) {
                    auto stateArray = m_repository->get_state_array_by_hash(chain_id, hash);
                    if (!stateArray.empty()) {
                        arrays.push_back(stateArray);
                    } else {
                        return;
                    }
                }

                if ((it->second.m_head_block.cumulative_difficulty() > m_head_blocks[chain_id].cumulative_difficulty() ||
                    (it->second.m_head_block.cumulative_difficulty() == m_head_blocks[chain_id].cumulative_difficulty() && peer > *m_ses.pubkey())) &&
                    it->second.m_head_block.genesis_block_hash() != m_head_blocks[chain_id].genesis_block_hash()) {
                    clear_chain_all_state_in_cache_and_db(chain_id);
                }

                process_genesis_block(chain_id, it->second.m_genesis_block, arrays);

                if (it->second.m_head_block.cumulative_difficulty() > m_head_blocks[chain_id].cumulative_difficulty() ||
                    (it->second.m_head_block.cumulative_difficulty() == m_head_blocks[chain_id].cumulative_difficulty() && peer > *m_ses.pubkey())) {
                    try_to_rebranch(chain_id, it->second.m_head_block, false, peer);
                }
            }
        }
    }

    bool blockchain::is_empty_chain(const aux::bytes &chain_id) {
        // check if head block empty
        auto &head_block = m_head_blocks[chain_id];

        return head_block.empty();
    }

    bool blockchain::is_transaction_in_pool(const bytes &chain_id, const sha1_hash &txid) {
        return m_tx_pools[chain_id].is_transaction_in_pool(txid);
    }

//    bool blockchain::is_block_immutable_certainly(const aux::bytes &chain_id, const block &blk) {
//        if (blk.block_number() <= 0) {
//            return true;
//        }
//
//        auto &consensus_point_block = m_consensus_point_blocks[chain_id];
//        if (consensus_point_block.sha256() == blk.sha256())
//            return true;
//
//        return false;
//    }

    bool blockchain::clear_all_chain_data_in_db(const bytes &chain_id) {
        // TODO:commit
        m_repository->begin_transaction();
        if (!m_repository->clear_all_state(chain_id)) {
            log(LOG_ERR, "INFO: chain:%s, clear all state fail.", aux::toHex(chain_id).c_str());
            return false;
        }
        if (!m_repository->set_all_block_non_main_chain(chain_id)) {
            log(LOG_ERR, "INFO: chain:%s, set all block non main chain fail.", aux::toHex(chain_id).c_str());
            return false;
        }
        m_repository->commit();
        return true;
    }

    bool blockchain::clear_chain_all_state_in_cache_and_db(const aux::bytes &chain_id) {
        m_head_blocks.erase(chain_id);
        return clear_all_chain_data_in_db(chain_id);
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

    block blockchain::get_block_from_cache_or_db(const aux::bytes &chain_id, const sha1_hash &hash) {
//        auto &block_map = m_blocks[chain_id];
//        auto it = block_map.find(hash);
//        if (it != block_map.end()) {
//            if (!it->second.empty()) {
//                return it->second;
//            } else {
//                block_map.erase(it);
//            }
//        }

        return m_repository->get_block_by_hash(chain_id, hash);
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
//            if (!absolute) {
//                if (is_block_immutable_certainly(chain_id, main_chain_block)) {
//                    log(LOG_ERR, "INFO chain[%s] block[%s] is immutable.",
//                        aux::toHex(chain_id).c_str(), main_chain_block.to_string().c_str());
//                    return FAIL;
//                }
//            }

            rollback_blocks.push_back(main_chain_block);

            auto previous_hash = main_chain_block.previous_block_hash();
            main_chain_block = m_repository->get_block_by_hash(chain_id, previous_hash);
            if (main_chain_block.empty()) {
                if(absolute) {
                    log(LOG_INFO, "INFO chain[%s] has no fork point", aux::toHex(chain_id).c_str());
                    return NO_FORK_POINT;
                }
                log(LOG_INFO, "INFO chain[%s] 3. Cannot find block[%s] in db",
                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                get_block(chain_id, peer, previous_hash);
                return MISSING;
            }
        }

        block reference_block = target;
        while (head_block.block_number() < reference_block.block_number()) {
            if (absolute && (target.block_number() - reference_block.block_number()) >= CHAIN_EPOCH_BLOCK_SIZE) {
                log(LOG_INFO, "INFO chain[%s] has no fork point", aux::toHex(chain_id).c_str());
                return NO_FORK_POINT;
            }

            log(LOG_INFO, "INFO chain[%s] add block to be connected:%s",
                aux::toHex(chain_id).c_str(), reference_block.to_string().c_str());

            connect_blocks.push_back(reference_block);

            // find branch block from cache and db
            auto previous_hash = reference_block.previous_block_hash();
            reference_block = m_repository->get_block_by_hash(chain_id, previous_hash);
//                reference_block = get_block_from_cache_or_db(chain_id, previous_hash);

            if (reference_block.empty()) {
                log(LOG_INFO, "INFO chain[%s] 4. Cannot find block[%s]",
                    aux::toHex(chain_id).c_str(), aux::toHex(previous_hash.to_string()).c_str());
                get_block(chain_id, peer, previous_hash);
                return MISSING;
            }
        }

//        log("----1. main chain block:%s, reference block:%s", main_chain_block.to_string().c_str(), reference_block.to_string().c_str());
        // find out common ancestor
        while (main_chain_block.sha1() != reference_block.sha1()) {
//            if (!absolute) {
//                if (is_block_immutable_certainly(chain_id, main_chain_block)) {
//                    log(LOG_ERR, "INFO chain[%s] block[%s] is immutable",
//                        aux::toHex(chain_id).c_str(), main_chain_block.to_string().c_str());
//                    return FAIL;
//                }
//            }

            rollback_blocks.push_back(main_chain_block);

            auto main_chain_previous_hash = main_chain_block.previous_block_hash();
            main_chain_block = m_repository->get_block_by_hash(chain_id, main_chain_previous_hash);
            if (main_chain_block.empty()) {
                if(absolute) {
                    log(LOG_INFO, "INFO chain[%s] has no fork point", aux::toHex(chain_id).c_str());
                    return NO_FORK_POINT;
                }
                log(LOG_INFO, "INFO chain[%s] 5.1 Cannot find main chain block[%s]",
                    aux::toHex(chain_id).c_str(), aux::toHex(main_chain_previous_hash.to_string()).c_str());
                get_block(chain_id, peer, main_chain_previous_hash);
                return MISSING;
            }

            if (absolute && (target.block_number() - reference_block.block_number()) >= CHAIN_EPOCH_BLOCK_SIZE) {
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
                get_block(chain_id, peer, previous_hash);
                return MISSING;
            }
        }

        log(LOG_INFO, "INFO: try to rebranch from main chain block[%s] to target block[%s], fork point block:%s",
            head_block.to_string().c_str(), target.to_string().c_str(), reference_block.to_string().c_str());

        // reference block is fork point block
        connect_blocks.push_back(reference_block);

        std::set<dht::public_key> peers;

        m_repository->begin_transaction();

        // Rollback blocks
        for (auto &blk: rollback_blocks) {
//            log("INFO: try to rollback block:%s", blk.to_string().c_str());
            // chain changed, re-check tx pool
            auto block_peers = blk.get_block_peers();
            peers.insert(block_peers.begin(), block_peers.end());

            auto const& tx = blk.tx();
            if (!tx.empty() && tx.type() == type_transfer) {
                std::map<dht::public_key, account> accounts;
                for (auto const& block_peer: block_peers) {
                    accounts[block_peer] = m_repository->get_account(chain_id, block_peer);
                }

                accounts[blk.miner()].subtract_balance(tx.fee());
                accounts[tx.receiver()].subtract_balance(tx.amount());
                accounts[tx.sender()].add_balance(tx.cost());
                accounts[tx.sender()].decrease_nonce();
                // subtract bonus
                accounts[blk.miner()].subtract_balance(MINER_BONUS);

                for (auto const& item: accounts) {
                    if (!m_repository->save_account(chain_id, item.second)) {
                        log(LOG_ERR, "INFO: chain:%s, save account[%s] fail.",
                            aux::toHex(chain_id).c_str(), item.second.to_string().c_str());
                        m_repository->rollback();
                        return FAIL;
                    }
                }
            } else {
                // miner balance -=10, power--
                auto miner_account = m_repository->get_account(chain_id, blk.miner());

                miner_account.decrease_power();
                miner_account.subtract_balance(MINER_BONUS);

                if (!m_repository->save_account(chain_id, miner_account)) {
                    log(LOG_ERR, "INFO: chain:%s, save miner account[%s] fail.",
                        aux::toHex(chain_id).c_str(), miner_account.to_string().c_str());
                    m_repository->rollback();
                    return FAIL;
                }
            }

            if (!m_repository->set_block_non_main_chain(chain_id, blk.sha1())) {
                log(LOG_ERR, "INFO: chain:%s, set block non main chain[%s] fail.",
                    aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                m_repository->rollback();
                return FAIL;
            }
        }

        // connect new branch blocks
        for (auto i = connect_blocks.size(); i > 1; i--) {
            auto &blk = connect_blocks[i - 2];
            auto &previous_block = connect_blocks[i - 1];

//            log("INFO: try to connect block:%s", blk.to_string().c_str());
            auto result = verify_block(chain_id, blk, previous_block);
            if (result != SUCCESS) {
                m_repository->rollback();
                return result;
            }

            auto block_peers = blk.get_block_peers();
            peers.insert(block_peers.begin(), block_peers.end());

            auto const& tx = blk.tx();
            if (!tx.empty() && tx.type() == type_transfer) {
                std::map<dht::public_key, account> accounts;
                for (auto const& block_peer: block_peers) {
                    accounts[block_peer] = m_repository->get_account(chain_id, block_peer);
                }

                accounts[blk.miner()].add_balance(tx.fee());
                accounts[tx.receiver()].add_balance(tx.amount());
                accounts[tx.sender()].subtract_balance(tx.cost());
                accounts[tx.sender()].increase_nonce();
                // add bonus to miner
                accounts[blk.miner()].add_balance(MINER_BONUS);

                for (auto const& item: accounts) {
                    if (!m_repository->save_account(chain_id, item.second)) {
                        log(LOG_ERR, "INFO: chain:%s, save account[%s] fail.",
                            aux::toHex(chain_id).c_str(), item.second.to_string().c_str());
                        m_repository->rollback();
                        return FAIL;
                    }
                }
            } else {
                // miner balance +=10, power++
                auto miner_account = m_repository->get_account(chain_id, blk.miner());

                miner_account.increase_power();
                miner_account.add_balance(MINER_BONUS);

                if (!m_repository->save_account(chain_id, miner_account)) {
                    log(LOG_ERR, "INFO: chain:%s, save miner account[%s] fail.",
                        aux::toHex(chain_id).c_str(), miner_account.to_string().c_str());
                    m_repository->rollback();
                    return FAIL;
                }
            }

            if (!m_repository->set_block_main_chain(chain_id, blk.sha1())) {
                log(LOG_ERR, "INFO: chain:%s, set block main chain[%s] fail.",
                    aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                m_repository->rollback();
                return FAIL;
            }
        }

        m_repository->commit();

        // after all above is success
        m_head_blocks[chain_id] = target;

        // chain changed, re-check tx pool
        m_tx_pools[chain_id].recheck_account_txs(peers);

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
        add_peer_into_acl(chain_id, target.miner(), target.timestamp());
//        m_ses.alerts().emplace_alert<blockchain_new_head_block_alert>(target);
//        m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(tail_block);
        m_ses.alerts().emplace_alert<blockchain_fork_point_block_alert>(reference_block);

        return SUCCESS;
    }

//    void blockchain::try_to_rebranch_to_best_vote(const aux::bytes &chain_id) {
//        auto &best_vote = m_best_votes[chain_id];
//        if (!best_vote.empty()) {
//            if (!is_empty_chain(chain_id)) {
//                // 4. check if need to re-branch to the best vote
//
//                if (!best_vote.empty()) {
////                    log("INFO chain[%s] current best vote[%s]", aux::toHex(chain_id).c_str(),
////                        best_vote.to_string().c_str());
//
//                    auto &consensus_point_block = m_consensus_point_blocks[chain_id];
//                    if (consensus_point_block != best_vote.voting_block()) {
//                        auto hash = m_repository->get_main_chain_block_hash_by_number(chain_id,
//                                                                                      best_vote.voting_block().block_number());
//                        // if current main chain block hash and voting block hash mismatch
//                        if (hash != best_vote.voting_block().sha256()) {
//                            log(LOG_INFO, "INFO chain[%s] main chain block[%s] mismatch the best vote",
//                                aux::toHex(chain_id).c_str(), aux::toHex(hash.to_string()).c_str());
//                            // re-branch
//                            const auto &best_voting_block = best_vote.voting_block();
//                            if (!best_voting_block.empty()) {
//                                log(LOG_INFO, "INFO chain[%s] try to re-branch to best voting block[%s]",
//                                    aux::toHex(chain_id).c_str(), best_voting_block.to_string().c_str());
//                                auto result = try_to_rebranch(chain_id, best_voting_block, true);
//                                // clear block cache if re-branch success/fail
//                                if (result == SUCCESS) {
//                                    // clear all ancestor blocks
//                                    remove_all_ancestor_blocks_from_cache(best_voting_block);
//
//                                    // update consensus point block hash as best voting block
//                                    m_consensus_point_blocks[chain_id] = best_voting_block;
//                                    m_repository->set_consensus_point_block_hash(chain_id,
//                                                                                 best_vote.voting_block().sha256());
//
//                                    m_ses.alerts().emplace_alert<blockchain_new_consensus_point_block_alert>(
//                                            best_voting_block);
//                                } else if (result == FAIL) {
//                                    remove_all_same_chain_blocks_from_cache(best_voting_block);
//                                } else if (result == NO_FORK_POINT) {
//                                    clear_chain_all_state_in_cache_and_db(chain_id);
//                                    m_repository->delete_peer_db(chain_id);
//                                    m_repository->create_peer_db(chain_id);
//                                    block_reception_event(chain_id, best_voting_block);
//                                    reset_chain_status(chain_id);
//                                    // cancel
//                                    auto it_chain_timer = m_chain_timers.find(chain_id);
//                                    if (it_chain_timer != m_chain_timers.end()) {
//                                        it_chain_timer->second.cancel();
//                                    }
//                                }
//                            }
//                        } else {
//                            // update consensus point block hash as main chain hash
//                            auto blk = m_repository->get_block_by_hash(chain_id, hash);
//                            m_consensus_point_blocks[chain_id] = blk;
//                            m_repository->set_consensus_point_block_hash(chain_id, hash);
//
//                            m_ses.alerts().emplace_alert<blockchain_new_consensus_point_block_alert>(blk);
//                        }
//                    }
//                }
//            } else {
//                process_block(chain_id, best_vote.voting_block());
//            }
//        }
//    }

    void blockchain::try_to_rebranch_to_most_difficult_chain(const aux::bytes &chain_id, const dht::public_key& peer) {

        log(LOG_ERR, "INFO: chain:%s, try to rebranch to peer[%s] chain.",
            aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());

        auto &head_block = m_head_blocks[chain_id];
        auto &acl = m_access_list[chain_id];

        auto it = acl.find(peer);
        if (it == acl.end()) {
            log(LOG_ERR, "INFO: chain:%s, Cannot find peer[%s] in acl.",
                aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
            return;
        }

        log(LOG_ERR, "INFO: chain:%s, remote head block[%s] local head block[%s].",
            aux::toHex(chain_id).c_str(), it->second.m_head_block.to_string().c_str(), head_block.to_string().c_str());

        if (it->second.m_head_block.cumulative_difficulty() > head_block.cumulative_difficulty() ||
                (it->second.m_head_block.cumulative_difficulty() == head_block.cumulative_difficulty() && peer > *m_ses.pubkey())) {
            log(LOG_ERR, "INFO: chain:%s, remote head block genesis block hash[%s] local head block genesis block hash[%s].",
                aux::toHex(chain_id).c_str(), aux::toHex(it->second.m_head_block.genesis_block_hash()).c_str(),
                aux::toHex(head_block.genesis_block_hash()).c_str());
            if (it->second.m_head_block.genesis_block_hash() == head_block.genesis_block_hash()) {
                auto peer_head_block = it->second.m_head_block;
                auto result = try_to_rebranch(chain_id, peer_head_block, false, it->first);
                // clear block cache if re-branch success/fail
                if (result == FAIL) {
                    log(LOG_ERR, "INFO: chain:%s, rebranch fail.", aux::toHex(chain_id).c_str());
                    // clear all blocks on the same chain
                    remove_all_same_chain_blocks_from_cache(peer_head_block);

                    acl.erase(it);
                } else if (result == SUCCESS) {
                    // clear all ancestor blocks
                    remove_all_ancestor_blocks_from_cache(peer_head_block);
                }
            } else {
                block blk = it->second.m_head_block;
                if (blk.block_number() % CHAIN_EPOCH_BLOCK_SIZE != 0) {
                    auto genesis_block_hash = blk.genesis_block_hash();
                    blk = m_repository->get_block_by_hash(chain_id, genesis_block_hash);
                    if (blk.empty()) {
                        get_block(chain_id, peer, genesis_block_hash);
                    } else {
                        get_all_state_from_peer(chain_id, peer, blk.state_root());
                    }
                } else {
                    get_all_state_from_peer(chain_id, peer, blk.state_root());
                }
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

            return lhs.voting_block().sha1() < rhs.voting_block().sha1();
        }
    }

//    void blockchain::count_votes(const aux::bytes &chain_id) {
//        std::set<vote> votes;
//        auto & peer_votes = m_votes[chain_id];
//
//        // vote for myself
//        if (is_sync_completed(chain_id)) {
//            auto &voting_point_block = m_voting_point_blocks[chain_id];
//            peer_votes[*m_ses.pubkey()] = vote(voting_point_block);
//        }
//
//        // count votes
//        for (auto const& v: peer_votes) {
//            auto it = votes.find(v.second);
//            if (it != votes.end()) {
//                auto cv = *it;
//                cv.vote_up();
//                votes.erase(it);
//                votes.insert(cv);
//            } else {
//                votes.insert(v.second);
//            }
//        }
//
//        std::set<vote, decltype(sort_votes)*> sorted_votes(votes.begin(), votes.end(), sort_votes);
//
////        vote best_vote;
////        // if no voting result or best vote count is 1, use local voting point block
////        if ((votes.empty() || votes.rbegin()->count() == 1) && is_sync_completed(chain_id)) {
////            auto &voting_point_block = m_voting_point_blocks[chain_id];
////            best_vote = vote(voting_point_block.sha1(), voting_point_block.block_number());
////        } else {
////            if (!votes.empty()) {
////                // use the best vote
////                best_vote = *votes.rbegin();
////            }
////        }
//
//        if (!sorted_votes.empty()) {
//            m_best_votes[chain_id] = *sorted_votes.begin();
//            log(LOG_INFO, "INFO: chain[%s] best vote[%s]",
//                aux::toHex(chain_id).c_str(), sorted_votes.begin()->to_string().c_str());
//        }
//
//
//        for (auto const &sorted_vote: sorted_votes) {
//            log(LOG_INFO, "INFO: sorted vote:%s", sorted_vote.to_string().c_str());
//        }
//
//        // select top three votes
//        std::vector<vote> top_three_votes;
//        int i = 0;
//        for (const auto & sorted_vote : sorted_votes) {
//            if (i >= 3)
//                break;
//
//            log(LOG_INFO, "INFO chain[%s] top three vote[%s]",
//                aux::toHex(chain_id).c_str(), sorted_vote.to_string().c_str());
//
//            top_three_votes.push_back(sorted_vote);
//            i++;
//        }
//
//        if (!top_three_votes.empty()) {
//            m_ses.alerts().emplace_alert<blockchain_top_three_votes_alert>(chain_id, top_three_votes);
//        }
//
//        // clear history votes for next round
//        m_votes[chain_id].clear();
//    }

    void blockchain::on_dht_put_mutable_item(const dht::item &i, int n) {
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


    void blockchain::on_dht_put_transaction(bytes chain_id, sha1_hash hash, const dht::item &i, int n) {
        if (n > 0) {
            m_ses.alerts().emplace_alert<blockchain_tx_arrived_alert>(chain_id, hash, get_total_milliseconds() / 1000);
        }
    }

    void blockchain::on_dht_relay_mutable_item(const entry &payload,
                                               const std::vector<std::pair<dht::node_entry, bool>> &nodes,
                                               dht::public_key peer) {
        // data type id
//        if (auto* i = const_cast<entry *>(payload.find_key(common::entry_type)))
//        {
//            auto data_type_id = i->integer();
//            if (data_type_id == common::transaction_entry::data_type_id) {
//                for (auto const &n: nodes) {
//                    log(LOG_DEBUG, "INFO: nodes:%s, bool:%d", n.first.addr().to_string().c_str(), n.second);
//                }
//
//                common::transaction_entry txEntry(payload);
//                auto now = get_total_milliseconds();
//                m_ses.alerts().emplace_alert<blockchain_tx_sent_alert>(peer, txEntry.m_tx.sha1(), now);
//                for (auto const &n: nodes) {
//                    if (n.second) {
//                        m_ses.alerts().emplace_alert<blockchain_tx_arrived_alert>(peer, txEntry.m_tx.sha1(), now);
//                        break;
//                    }
//                }
//            }
//        }
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
                target.push_back(tx.sha1()[0]);
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

    void blockchain::get_genesis_state(const bytes &chain_id, sha1_hash &stateRoot, std::vector<state_array> &arrays) {
        auto all_state = m_repository->get_all_effective_state(chain_id);
        if (!all_state.empty()) {
            std::vector<account> states;
            for (auto const &state: all_state) {
                states.push_back(state);
                if (states.size() == MAX_STATE_ARRAY_SIZE) {
                    state_array stateArray(states);
                    arrays.push_back(stateArray);

                    states.clear();
                }
            }

            // the last one
            if (!states.empty()) {
                state_array stateArray(states);
                arrays.push_back(stateArray);

                states.clear();
            }

            if (!arrays.empty()) {
                std::vector<sha1_hash> hashArray;
                for (auto const &array: arrays) {
                    hashArray.push_back(array.sha1());
                }
                state_hash_array stateHashArray(hashArray);
                stateRoot = stateHashArray.sha1();
            }
        }
    }

//    std::string blockchain::make_salt(const aux::bytes &chain_id, std::int64_t data_type_id) {
//        common::protocol_entry protocolEntry(chain_id, data_type_id);
//        sha1_hash hash = hasher(protocolEntry.get_encode()).final();
//        return hash.to_string();
//    }

    std::string blockchain::make_salt(const sha1_hash &hash) {
        return hash.to_string();
    }

    void blockchain::publish(const std::string &salt, const entry& data) {
        if (!m_ses.dht()) return;
        log(LOG_INFO, "INFO: Publish salt[%s], data[%s]", aux::toHex(salt).c_str(), data.to_string(true).c_str());
//        m_ses.dht()->put_item(data, std::bind(&blockchain::on_dht_put_mutable_item, self(), _1, _2), 1, 8, 16, salt);
        dht_item dhtItem(salt, data);
        add_into_dht_task_queue(dhtItem);
    }

    void blockchain::publish_transaction(const bytes &chain_id, const sha1_hash &hash, const std::string &salt, const entry &data) {
        if (!m_ses.dht()) return;
        log(LOG_INFO, "INFO: Publish salt[%s], data[%s]", aux::toHex(salt).c_str(), data.to_string(true).c_str());
//        m_ses.dht()->put_item(data, std::bind(&blockchain::on_dht_put_transaction, self(), chain_id, hash, _1, _2), 1, 8, 16, salt);
        dht_item dhtItem(chain_id, hash, salt, data);
        add_into_dht_task_queue(dhtItem);
    }

    void blockchain::subscribe(aux::bytes const& chain_id, const dht::public_key &peer, const std::string &salt,
                               GET_ITEM_TYPE type, std::int64_t timestamp, int times) {
        if (!m_ses.dht()) return;

//        m_ses.dht()->get_item(peer, std::bind(&blockchain::get_mutable_callback, self(), chain_id, _1, _2, type, timestamp, times), 1, 8, 16, salt, timestamp);
        dht_item dhtItem(chain_id, peer, salt, type, timestamp, times);
        add_into_dht_task_queue(dhtItem);
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
//        m_ses.dht()->send(peer, data, 1, 8, 16, 1
//                , std::bind(&blockchain::on_dht_relay_mutable_item, self(), _1, _2, peer));
        dht_item dhtItem(peer, data);
        add_into_dht_task_queue(dhtItem);
    }

    void blockchain::add_into_dht_task_queue(const dht_item &dhtItem) {
//        log(LOG_INFO, "Try to add dht item [%s]", dhtItem.to_string().c_str());
//        if (m_tasks_set.find(dhtItem) == m_tasks_set.end()) {
            if (m_tasks.size() < 10000) {
                log(LOG_INFO, "Add dht item [%s]", dhtItem.to_string().c_str());
                m_tasks.push(dhtItem);

                m_dht_tasks_timer.cancel();
            }
//            m_tasks_set.insert(dhtItem);
//        }
    }

//    void blockchain::transfer_to_acl_peers(const aux::bytes &chain_id, const entry &data,
//                                           const dht::public_key &incoming_peer) {
//        std::set<dht::public_key> peers;
//        auto &acl = m_access_list[chain_id];
//        for (auto const &item: acl) {
//            peers.insert(item.first);
//        }
//
//        auto size = acl.size();
//        if (size < blockchain_acl_max_peers) {
//            for (int i = 0; i < blockchain_acl_max_peers - size; i++) {
//                auto peer = m_repository->get_peer_from_state_db_randomly(chain_id);
//                peers.insert(peer);
//            }
//        }
//
//        peers.erase(incoming_peer);
//
//        for (auto const& peer: peers) {
//            send_to(peer, data);
//        }
//    }

//    void blockchain::transfer_head_block(const bytes &chain_id, const block &blk) {
//        std::set<dht::public_key> peers;
//        auto &acl = m_access_list[chain_id];
//        for (auto const &item: acl) {
//            if (item.second.m_head_block != blk) {
//                peers.insert(item.first);
//            }
//        }
//
//        auto size = acl.size();
//        if (size < blockchain_acl_max_peers) {
//            for (int i = 0; i < blockchain_acl_max_peers - size; i++) {
//                auto peer = m_repository->get_peer_from_state_db_randomly(chain_id);
//                peers.insert(peer);
//            }
//        }
//
//        common::head_block_entry blockEntry(blk);
//
//        for (auto const& peer: peers) {
//            send_to(peer, blockEntry.get_entry());
//        }
//    }

//    void blockchain::transfer_transaction(const bytes &chain_id, const transaction &tx) {
//        std::set<dht::public_key> peers;
//        auto &acl = m_access_list[chain_id];
//        for (auto const &item: acl) {
//            if (item.second.m_latest_tx != tx) {
//                peers.insert(item.first);
//            }
//        }
//
//        auto size = acl.size();
//        if (size < blockchain_acl_max_peers) {
//            for (int i = 0; i < blockchain_acl_max_peers - size; i++) {
//                auto peer = m_repository->get_peer_from_state_db_randomly(chain_id);
//                peers.insert(peer);
//            }
//        }
//
//        common::transaction_entry transactionEntry(tx);
//
//        for (auto const& peer: peers) {
//            send_to(peer, transactionEntry.get_entry());
//        }
//    }

//    void blockchain::get_gossip_peers(const aux::bytes &chain_id, const dht::public_key &peer) {
//        // salt is x pubkey when request signal
//        auto salt = make_salt(chain_id, common::gossip_cache_peers_entry::data_type_id);
//
//        log(LOG_INFO, "INFO: Request gossip peers from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
//            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
//        subscribe(chain_id, peer, salt);
//    }

//    void blockchain::get_voting_block(const aux::bytes &chain_id, const dht::public_key &peer) {
//        // salt is x pubkey when request signal
//        auto salt = make_salt(chain_id, common::voting_block_cache_entry::data_type_id);
//
//        log(LOG_INFO, "INFO: Request vote from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
//            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
//        subscribe(chain_id, peer, salt);
//    }

//    void blockchain::put_voting_block(const aux::bytes &chain_id, const block &blk) {
//        if (!blk.empty()) {
//            common::voting_block_cache_entry votingBlockCacheEntry(blk);
//
//            // salt is y pubkey when publish signal
//            auto salt = make_salt(chain_id, common::voting_block_cache_entry::data_type_id);
//
//            log(LOG_INFO, "INFO: Chain id[%s] Cache voting block salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
//            publish(salt, votingBlockCacheEntry.get_entry());
//        }
//    }

    void blockchain::request_chain_all_data(const bytes &chain_id, const dht::public_key &peer) {
        common::signal_entry signalEntry(common::BLOCKCHAIN_ALL_DATA, chain_id, get_total_milliseconds() / 1000);

        send_to(peer, signalEntry.get_entry());
    }

    void blockchain::put_chain_all_data(const bytes &chain_id) {
        if (m_chains.find(chain_id) == m_chains.end()) {
            log(LOG_INFO, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
        }

        if (!m_chain_connected[chain_id]) {
            log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
        }

        log(LOG_INFO, "Chain[%s] Put all chain data", aux::toHex(chain_id).c_str());

        auto now = get_total_milliseconds();
        if (now < m_all_data_last_put_time[chain_id] + blockchain_min_put_interval) {
            log(LOG_INFO, "Chain[%s] Already put it", aux::toHex(chain_id).c_str());
            return;
        }
        m_all_data_last_put_time[chain_id] = now;

        if (!is_empty_chain(chain_id)) {
            auto blk = m_head_blocks[chain_id];
            while (blk.block_number() % CHAIN_EPOCH_BLOCK_SIZE != 0) {
                put_block(chain_id, blk);
                blk = m_repository->get_block_by_hash(chain_id, blk.previous_block_hash());
            }
            sha1_hash stateRoot;
            std::vector<state_array> stateArrays;
            get_genesis_state(chain_id, stateRoot, stateArrays);
            put_block_with_all_state(chain_id, blk, stateArrays);
            put_head_block_hash(chain_id, m_head_blocks[chain_id].sha1());
        }
    }

    void blockchain::put_chain_all_state(const bytes &chain_id) {
        if (m_chains.find(chain_id) == m_chains.end()) {
            log(LOG_INFO, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
        }

        if (!m_chain_connected[chain_id]) {
            log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
        }

        log(LOG_INFO, "Chain[%s] Put all chain state", aux::toHex(chain_id).c_str());

        auto now = get_total_milliseconds();
        if (now < m_all_state_last_put_time[chain_id] + blockchain_min_put_interval) {
            log(LOG_INFO, "Chain[%s] Already put it", aux::toHex(chain_id).c_str());
            return;
        }
        m_all_state_last_put_time[chain_id] = now;

        if (!is_empty_chain(chain_id)) {
            auto blk = m_repository->get_block_by_hash(chain_id, m_head_blocks[chain_id].genesis_block_hash());
            sha1_hash stateRoot;
            std::vector<state_array> stateArrays;
            get_genesis_state(chain_id, stateRoot, stateArrays);
            put_block_with_all_state(chain_id, blk, stateArrays);
        }
    }

    void blockchain::put_chain_all_blocks(const bytes &chain_id) {
        if (m_chains.find(chain_id) == m_chains.end()) {
            log(LOG_INFO, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
        }

        if (!m_chain_connected[chain_id]) {
            log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
        }

        log(LOG_INFO, "Chain[%s] Put chain blocks", aux::toHex(chain_id).c_str());

        auto now = get_total_milliseconds();
        if (now < m_all_blocks_last_put_time[chain_id] + blockchain_min_put_interval) {
            log(LOG_INFO, "Chain[%s] Already put it", aux::toHex(chain_id).c_str());
            return;
        }
        m_all_blocks_last_put_time[chain_id] = now;

        if (!is_empty_chain(chain_id)) {
            auto blk = m_head_blocks[chain_id];
            while (blk.block_number() % CHAIN_EPOCH_BLOCK_SIZE != 0) {
                put_block(chain_id, blk);
                blk = m_repository->get_block_by_hash(chain_id, blk.previous_block_hash());
            }
            put_block(chain_id, blk);

            put_head_block_hash(chain_id, m_head_blocks[chain_id].sha1());
        }
    }

    void blockchain::request_all_blocks(const bytes &chain_id, const dht::public_key &peer) {
        common::signal_entry signalEntry(common::BLOCKCHAIN_ALL_BLOCKS, chain_id, get_total_milliseconds() / 1000);
        auto e = signalEntry.get_entry();
        log(LOG_INFO, "Chain[%s] Send peer[%s] all blocks request signal[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), e.to_string(true).c_str());
        send_to(peer, e);
    }

    void blockchain::request_all_state(const bytes &chain_id, const dht::public_key &peer) {
        common::signal_entry signalEntry(common::BLOCKCHAIN_ALL_STATE, chain_id, get_total_milliseconds() / 1000);
        auto e = signalEntry.get_entry();
        log(LOG_INFO, "Chain[%s] Send peer[%s] all state request signal[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), e.to_string(true).c_str());
        send_to(peer, e);
    }

    void blockchain::send_online_signal(const aux::bytes &chain_id) {
        auto peer = select_peer_randomly_from_acl(chain_id);
        log(LOG_INFO, "Chain[%s] select gossip peer[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str());
        common::signal_entry signalEntry(common::BLOCKCHAIN_ONLINE, chain_id, get_total_milliseconds() / 1000, peer);

        auto e = signalEntry.get_entry();
        auto const& acl = m_access_list[chain_id];
        for (auto const& item: acl) {
            log(LOG_INFO, "Chain[%s] Send peer[%s] online signal[%s]", aux::toHex(chain_id).c_str(),
                aux::toHex(item.first.bytes).c_str(), e.to_string(true).c_str());
            send_to(item.first, e);
        }
    }

    void blockchain::send_new_head_block_signal(const bytes &chain_id, const sha1_hash &hash) {
        auto peer = select_peer_randomly_from_acl(chain_id);
        log(LOG_INFO, "Chain[%s] select gossip peer[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str());
        common::signal_entry signalEntry(common::BLOCKCHAIN_NEW_HEAD_BLOCK, chain_id, get_total_milliseconds() / 1000, hash, peer);
        auto e = signalEntry.get_entry();
        auto const& acl = m_access_list[chain_id];
        for (auto const& item: acl) {
            log(LOG_INFO, "Chain[%s] Send peer[%s] new head block signal[%s]", aux::toHex(chain_id).c_str(),
                aux::toHex(item.first.bytes).c_str(), e.to_string(true).c_str());
            send_to(item.first, e);
        }
    }

    void blockchain::send_new_transfer_tx_signal(const bytes &chain_id, const dht::public_key& tx_receiver) {
        auto peer = select_peer_randomly_from_acl(chain_id);
        log(LOG_INFO, "Chain[%s] select gossip peer[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str());
        common::signal_entry signalEntry(common::BLOCKCHAIN_NEW_TRANSFER_TX, chain_id, get_total_milliseconds() / 1000, peer);
        auto e = signalEntry.get_entry();
        auto encode = signalEntry.get_encode();
        auto const& acl = m_access_list[chain_id];
        std::set<dht::public_key> peers;
        for (auto const& item: acl) {
            peers.insert(item.first);
        }
        if (tx_receiver != *m_ses.pubkey()) {
            peers.insert(tx_receiver);
        }
        for (auto const& peer: peers) {
            log(LOG_INFO, "Chain[%s] Send peer[%s] new transfer tx signal[%s]", aux::toHex(chain_id).c_str(),
                aux::toHex(peer.bytes).c_str(), e.to_string(true).c_str());
            send_to(peer, e);
        }
    }

    void blockchain::send_new_note_tx_signal(const bytes &chain_id, const sha1_hash &hash) {
        auto peer = select_peer_randomly_from_acl(chain_id);
        log(LOG_INFO, "Chain[%s] select gossip peer[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str());
        common::signal_entry signalEntry(common::BLOCKCHAIN_NEW_NOTE_TX, chain_id, get_total_milliseconds() / 1000, hash, peer);
        auto e = signalEntry.get_entry();
        auto encode = signalEntry.get_encode();
        auto const& acl = m_access_list[chain_id];
        for (auto const& item: acl) {
            log(LOG_INFO, "Chain[%s] Send peer[%s] new note tx signal[%s]", aux::toHex(chain_id).c_str(),
                aux::toHex(item.first.bytes).c_str(), e.to_string(true).c_str());
            send_to(item.first, e);
        }
    }

    void blockchain::get_head_block_from_peer(const bytes &chain_id, const dht::public_key &peer, std::int64_t timestamp) {
        log(LOG_INFO, "Chain[%s] get head block from peer[%s]", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
        get_head_block_hash(chain_id, peer, timestamp);
    }

    void blockchain::put_head_block(const bytes &chain_id, const block &blk) {
        if (!blk.empty()) {
            put_block(chain_id, blk);
            put_head_block_hash(chain_id, blk.sha1());

            send_new_head_block_signal(chain_id, blk.sha1());
        }
    }

    void blockchain::put_genesis_head_block(const bytes &chain_id, const block &blk, const std::vector<state_array> &arrays) {
        for (auto const& stateArray: arrays) {
            if (!stateArray.empty()) {
                m_ses.alerts().emplace_alert<blockchain_state_array_alert>(chain_id, stateArray.StateArray());
            }
        }

        if (!blk.empty() && !arrays.empty()) {
            put_block_with_all_state(chain_id, blk, arrays);

            put_head_block_hash(chain_id, blk.sha1());

            send_new_head_block_signal(chain_id, blk.sha1());
        }
    }

    void blockchain::get_pool_from_peer(const bytes &chain_id, const dht::public_key &peer, std::int64_t timestamp) {
        log(LOG_INFO, "Chain[%s] get pool from peer[%s]", aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str());
        get_transfer_transaction(chain_id, peer);
        get_note_pool_root(chain_id, peer, timestamp);
    }

    void blockchain::get_transfer_transaction(const bytes &chain_id, const dht::public_key &peer, std::int64_t timestamp) {
        // salt is x pubkey when request signal
        std::string data(chain_id.begin(), chain_id.end());
        data.insert(data.end(), key_suffix_transfer_tx.begin(), key_suffix_transfer_tx.end());
        auto key = hasher(data).final();
        auto salt = make_salt(key);

        log(LOG_INFO, "INFO: Get transfer tx from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::TRANSFER_TX, timestamp);
    }

    void blockchain::put_transfer_transaction(const bytes &chain_id, const transaction &tx) {
        if (!tx.empty()) {
            // salt is y pubkey when publish signal
            std::string data(chain_id.begin(), chain_id.end());
            data.insert(data.end(), key_suffix_transfer_tx.begin(), key_suffix_transfer_tx.end());
            auto key = hasher(data).final();
            auto salt = make_salt(key);

            log(LOG_INFO, "INFO: Chain id[%s] Put transfer tx salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
//            publish(salt, tx.get_entry());
            publish_transaction(chain_id, tx.sha1(), salt, tx.get_entry());

            send_new_transfer_tx_signal(chain_id, tx.receiver());
        }
    }

    void blockchain::put_note_transaction(const bytes &chain_id, const transaction &tx) {
        if (!tx.empty()) {
            // salt is y pubkey when publish signal
//            transaction_wrapper txWrapper(m_current_tx_wrapper[chain_id].sha1(), tx);
//            m_current_tx_wrapper[chain_id] = txWrapper;
            put_transaction(chain_id, tx);
            put_note_pool_hash_set(chain_id);
//            put_note_pool_root(chain_id, tx.sha1());
//
//            send_new_note_tx_signal(chain_id, tx.sha1());
        }
    }

    void blockchain::get_all_state_from_peer(const bytes &chain_id, const dht::public_key &peer, const sha1_hash &hash) {
        get_state_hash_array(chain_id, peer, hash);
    }

//    void blockchain::put_all_state(const bytes &chain_id) {
//        auto all_state_arrays = m_repository->get_all_state_arrays(chain_id);
//        std::vector<sha1_hash> all_hash;
//        for (auto const& states: all_state_arrays) {
//            put_state_array(chain_id, states);
//
//            all_hash.push_back(states.sha1());
//        }
//
//        if (!all_hash.empty()) {
//            state_hash_array hashArray(all_hash);
//            put_state_hash_array(chain_id, hashArray);
//        }
//    }

    void blockchain::get_head_block_hash(const bytes &chain_id, const dht::public_key &peer, std::int64_t timestamp) {
        // salt is x pubkey when request signal
        std::string data(chain_id.begin(), chain_id.end());
        data.insert(data.end(), key_suffix_head_block_hash.begin(), key_suffix_head_block_hash.end());
        auto key = hasher(data).final();
        auto salt = make_salt(key);

        log(LOG_INFO, "INFO: Get head block hash from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::HEAD_BLOCK_HASH, timestamp);
    }

    void blockchain::put_head_block_hash(const bytes &chain_id, const sha1_hash &hash) {
        if (!hash.is_all_zeros()) {
            // salt is y pubkey when publish signal
            std::string data(chain_id.begin(), chain_id.end());
            data.insert(data.end(), key_suffix_head_block_hash.begin(), key_suffix_head_block_hash.end());
            auto key = hasher(data).final();
            auto salt = make_salt(key);

            log(LOG_INFO, "INFO: Chain id[%s] Put head block hash salt[%s], hash[%s]",
                aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str(), aux::toHex(hash.to_string()).c_str());
            publish(salt, hash.to_string());
        }
    }

    void blockchain::get_note_pool_root(const bytes &chain_id, const dht::public_key &peer, std::int64_t timestamp) {
        // salt is x pubkey when request signal
        std::string data(chain_id.begin(), chain_id.end());
        data.insert(data.end(), key_suffix_note_pool_root.begin(), key_suffix_note_pool_root.end());
        auto key = hasher(data).final();
        auto salt = make_salt(key);

        log(LOG_INFO, "INFO: Get note pool root from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::NOTE_POOL_ROOT, timestamp);
    }

    void blockchain::put_note_pool_root(const bytes &chain_id, const sha1_hash &hash) {
        if (!hash.is_all_zeros()) {
            // salt is y pubkey when publish signal
            std::string data(chain_id.begin(), chain_id.end());
            data.insert(data.end(), key_suffix_note_pool_root.begin(), key_suffix_note_pool_root.end());
            auto key = hasher(data).final();
            auto salt = make_salt(key);

            log(LOG_INFO, "INFO: Chain id[%s] Put note pool root salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
            publish(salt, hash.to_string());
        }
    }

//    void blockchain::get_pool_root(const bytes &chain_id, const dht::public_key &peer) {
//        // salt is x pubkey when request signal
//        std::string data(chain_id.begin(), chain_id.end());
//        data.insert(data.end(), key_suffix_pool_root.begin(), key_suffix_pool_root.end());
//        auto key = hasher(data).final();
//        auto salt = make_salt(key);
//
//        log(LOG_INFO, "INFO: Request pool root from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
//            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
//        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::POOL_ROOT);
//    }
//
//    void blockchain::put_pool_root(const bytes &chain_id, const sha1_hash &hash) {
//        if (!hash.is_all_zeros()) {
//            // salt is y pubkey when publish signal
//            std::string data(chain_id.begin(), chain_id.end());
//            data.insert(data.end(), key_suffix_pool_root.begin(), key_suffix_pool_root.end());
//            auto key = hasher(data).final();
//            auto salt = make_salt(key);
//
//            log(LOG_INFO, "INFO: Chain id[%s] Cache pool root salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
//            publish(salt, hash.to_string());
//        }
//    }

    void blockchain::get_block(const bytes &chain_id, const dht::public_key &peer, const sha1_hash &hash) {
        // salt is x pubkey when request signal
        auto salt = make_salt(hash);

        log(LOG_INFO, "INFO: Get block from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::BLOCK);
    }

    void blockchain::get_head_block(const bytes &chain_id, const dht::public_key &peer, const sha1_hash &hash, int times) {
        // salt is x pubkey when request signal
        auto salt = make_salt(hash);

        log(LOG_INFO, "INFO: Get head block from chain[%s] peer[%s], salt:[%s], times[%d]",
            aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str(), times);
        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::HEAD_BLOCK, 0, times);
    }

    void blockchain::put_block(const bytes &chain_id, const block &blk) {
        if (!blk.empty()) {
            // salt is y pubkey when publish signal
            auto salt = make_salt(blk.sha1());

            log(LOG_INFO, "INFO: Chain id[%s] Put block salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
            publish(salt, blk.get_entry());
        }
    }

    void blockchain::put_block_with_all_state(const bytes &chain_id, const block &blk, const std::vector<state_array> &arrays) {
        if (!blk.empty() && !arrays.empty()) {

            put_block(chain_id, blk);

            std::vector<sha1_hash> hashArray;
            for (auto const& stateArray: arrays) {
                hashArray.push_back(stateArray.sha1());
                put_state_array(chain_id, stateArray);
            }
            state_hash_array stateHashArray(hashArray);
            put_state_hash_array(chain_id, stateHashArray);
        }
    }

//    void blockchain::get_transaction_wrapper(const bytes &chain_id, const dht::public_key &peer, const sha1_hash &hash, int times) {
//        // salt is x pubkey when request signal
//        auto salt = make_salt(hash);
//
//        log(LOG_INFO, "INFO: Get tx from chain[%s] peer[%s], salt:[%s], times[%d]", aux::toHex(chain_id).c_str(),
//            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str(), times);
//        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::TX_WRAPPER, 0, times);
//    }

//    void blockchain::put_transaction_wrapper(const bytes &chain_id, const transaction_wrapper &txWrapper) {
//        if (!txWrapper.empty()) {
//            // salt is y pubkey when publish signal
//            auto salt = make_salt(txWrapper.sha1());
//
//            log(LOG_INFO, "INFO: Chain id[%s] Put tx salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
//            publish_transaction(chain_id, txWrapper.sha1(), salt, txWrapper.get_entry());
//        }
//    }

    void blockchain::get_transaction(const bytes &chain_id, const dht::public_key &peer, const sha1_hash &hash, int times) {
        // salt is x pubkey when request signal
        auto salt = make_salt(hash);

        log(LOG_INFO, "INFO: Get tx from chain[%s] peer[%s], salt:[%s], times[%d]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str(), times);
        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::NOTE_TX, 0, times);
    }

    void blockchain::put_transaction(const bytes &chain_id, const transaction &tx) {
        if (!tx.empty()) {
            // salt is y pubkey when publish signal
            auto salt = make_salt(tx.sha1());

            log(LOG_INFO, "INFO: Chain id[%s] Put tx salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
            publish_transaction(chain_id, tx.sha1(), salt, tx.get_entry());
        }
    }

    void blockchain::get_state_array(const bytes &chain_id, const dht::public_key &peer, const sha1_hash &hash) {
        // salt is x pubkey when request signal
        auto salt = make_salt(hash);

        log(LOG_INFO, "INFO: Get state array from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::STATE_ARRAY);
    }

    void blockchain::put_state_array(const bytes &chain_id, const state_array &stateArray) {
        if (!stateArray.empty()) {
            // salt is y pubkey when publish signal
            auto salt = make_salt(stateArray.sha1());

            log(LOG_INFO, "INFO: Chain id[%s] Put state array salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
            publish(salt, stateArray.get_entry());
        }
    }

    void blockchain::get_note_pool_hash_set(const bytes &chain_id, const dht::public_key &peer, const sha1_hash &hash, int times) {
        // salt is x pubkey when request signal
        auto salt = make_salt(hash);

        log(LOG_INFO, "INFO: Get note pool hash set from chain[%s] peer[%s], salt:[%s], times[%d]",
            aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str(), times);
        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::NOTE_POOL_HASH_SET, 0, times);
    }

    void blockchain::put_note_pool_hash_set(const bytes &chain_id) {
        auto hash_set = m_tx_pools[chain_id].get_top_40_note_txid();
        pool_hash_set poolHashSet(hash_set);

        if (!poolHashSet.empty()) {
            auto salt = make_salt(poolHashSet.sha1());

            log(LOG_INFO, "INFO: Chain id[%s] Cache note pool hash set salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
            publish(salt, poolHashSet.get_entry());

            put_note_pool_root(chain_id, poolHashSet.sha1());

            send_new_note_tx_signal(chain_id, poolHashSet.sha1());
        }
    }

    void blockchain::get_state_hash_array(const bytes &chain_id, const dht::public_key &peer, const sha1_hash &hash) {
        // salt is x pubkey when request signal
        auto salt = make_salt(hash);

        log(LOG_INFO, "INFO: Get state hash array from chain[%s] peer[%s], salt:[%s]", aux::toHex(chain_id).c_str(),
            aux::toHex(peer.bytes).c_str(), aux::toHex(salt).c_str());
        subscribe(chain_id, peer, salt, GET_ITEM_TYPE::STATE_HASH_ARRAY);
    }

    void blockchain::put_state_hash_array(const bytes &chain_id, const state_hash_array &hashArray) {
        if (!hashArray.empty()) {
            // salt is y pubkey when publish signal
            auto salt = make_salt(hashArray.sha1());

            log(LOG_INFO, "INFO: Chain id[%s] Put state hash array salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
            publish(salt, hashArray.get_entry());
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
    void blockchain::get_mutable_callback(aux::bytes chain_id, dht::item const& i
            , bool const authoritative, GET_ITEM_TYPE type, std::int64_t timestamp, int times)
    {
        TORRENT_ASSERT(i.is_mutable());

        if(!authoritative)
            return; 

        // construct mutable data wrapper from entry
        try {
            const auto& peer = i.pk();
            const auto& salt = i.salt();
//            GET_ITEM getItem(chain_id, peer, salt, type);

            log(LOG_INFO, "=====INFO: Got callback[%s], type[%d],salt[%s], timestamp:%" PRId64,
                i.value().to_string(true).c_str(), type, aux::toHex(i.salt()).c_str(), timestamp);

            if (!i.empty()) {
                add_peer_into_acl(chain_id, peer, i.ts().value);
//                m_get_item_info.erase(getItem);

                switch (type) {
                    case GET_ITEM_TYPE::HEAD_BLOCK_HASH: {
                        sha1_hash head_block_hash(i.value().string().c_str());
                        log(LOG_INFO, "INFO: Got head block hash[%s]", aux::toHex(head_block_hash).c_str());
                        if (!head_block_hash.is_all_zeros()) {
                            auto blk = m_repository->get_block_by_hash(chain_id, head_block_hash);
                            if (blk.empty()) {
                                log(LOG_INFO, "INFO: Cannot get block hash[%s] in local", aux::toHex(head_block_hash).c_str());
                                get_head_block(chain_id, peer, head_block_hash);
                            } else {
                                block_reception_event(chain_id, peer, blk);
                            }
                        }

                        break;
                    }
                    case GET_ITEM_TYPE::HEAD_BLOCK: {
                        block blk(i.value());

                        if (!blk.empty()) {
                            log(LOG_INFO, "INFO: Got head block[%s], time:%" PRId64,
                                blk.to_string().c_str(), get_total_milliseconds());

                            auto &acl = m_access_list[chain_id];
                            auto it = acl.find(peer);
                            if (it != acl.end()) {
                                // only peer in acl is allowed
                                it->second.m_head_block = blk;
                                if (blk.block_number() % CHAIN_EPOCH_BLOCK_SIZE == 0) {
                                    it->second.m_genesis_block = blk;
                                }
                            }

                            if (blk.block_number() % CHAIN_EPOCH_BLOCK_SIZE == 0) {
                                get_all_state_from_peer(chain_id, peer, blk.state_root());
                            }

                            if (!m_repository->save_block_if_not_exist(blk)) {
                                log(LOG_ERR, "INFO: chain:%s, save remote head block[%s] fail.",
                                    aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                            }

                            // notify ui tx from block
                            if (!blk.tx().empty()) {
                                m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(blk.tx());
                            }

                            if (blk.cumulative_difficulty() > m_head_blocks[chain_id].cumulative_difficulty()) {
                                m_ses.alerts().emplace_alert<blockchain_syncing_head_block_alert>(peer, blk);
                            }

                            block_reception_event(chain_id, peer, blk);
                        }

                        break;
                    }
                    case GET_ITEM_TYPE::BLOCK: {
                        block blk(i.value());

                        if (!blk.empty()) {
                            log(LOG_INFO, "INFO: Got block[%s], time:%" PRId64,
                                blk.to_string().c_str(), get_total_milliseconds());

                            auto &acl = m_access_list[chain_id];
                            auto it = acl.find(peer);
                            if (it != acl.end()) {
                                // only peer in acl is allowed
                                if (blk.block_number() % CHAIN_EPOCH_BLOCK_SIZE == 0) {
                                    it->second.m_genesis_block = blk;
                                }
                            }

                            if (blk.block_number() % CHAIN_EPOCH_BLOCK_SIZE == 0) {
                                get_all_state_from_peer(chain_id, peer, blk.state_root());
                            }

                            if (!m_repository->save_block_if_not_exist(blk)) {
                                log(LOG_ERR, "INFO: chain:%s, save block[%s] fail.",
                                    aux::toHex(chain_id).c_str(), blk.to_string().c_str());
                            }

                            // notify ui tx from block
                            if (!blk.tx().empty()) {
                                m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(blk.tx());
                            }

                            m_ses.alerts().emplace_alert<blockchain_syncing_block_alert>(peer, blk);

                            block_reception_event(chain_id, peer, blk);
                        }

                        break;
                    }
//                    case GET_ITEM_TYPE::TX_WRAPPER: {
//                        transaction_wrapper txWrapper(i.value());
//
//                        log(LOG_INFO, "INFO: Got transaction wrapper[%s].", txWrapper.to_string().c_str());
//
//                        auto const& tx = txWrapper.tx();
//                        if (!tx.empty() && tx.verify_signature() && tx.type() == tx_type::type_note) {
//
//                            log(LOG_INFO, "INFO: Got note transaction[%s].", tx.to_string().c_str());
//
//                            m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(tx);
//
//                            auto &pool = m_tx_pools[chain_id];
//
//                            // get history tx
//                            if (times < 10 && !txWrapper.previousHash().is_all_zeros() && !pool.is_transaction_in_time_pool(txWrapper.previousHash())) {
//                                get_transaction_wrapper(chain_id, peer, txWrapper.previousHash(), times + 1);
//                            }
//
//                            if (pool.add_tx_to_time_pool(txWrapper.tx())) {
//                                put_note_transaction(chain_id, txWrapper.tx());
//
////                                if (peer != *m_ses.pubkey()) {
////                                    put_note_transaction(chain_id, txWrapper.tx());
////                                } else {
////                                    // update last tx wrapper
////                                    if (m_current_tx_wrapper[chain_id].empty()) {
////                                        m_current_tx_wrapper[chain_id] = txWrapper;
////                                    }
////
////                                    // get history tx
////                                    if (times < 10 && !txWrapper.previousHash().is_all_zeros() && !pool.is_transaction_in_time_pool(txWrapper.previousHash())) {
////                                        get_transaction_wrapper(chain_id, peer, txWrapper.previousHash(), times + 1);
////                                    }
////                                }
//                            }
//                        }
//
//                        break;
//                    }
                    case GET_ITEM_TYPE::NOTE_POOL_HASH_SET: {
                        pool_hash_set poolHashSet(i.value());
                        log(LOG_INFO, "INFO: Got pool hash set[%s].", poolHashSet.to_string().c_str());

                        auto const& hashSet = poolHashSet.PoolHashSet();
                        for (auto const& hash: hashSet) {
                            // get history tx
                            if (!hash.is_all_zeros() && !m_tx_pools[chain_id].is_transaction_in_time_pool(hash)) {
                                get_transaction(chain_id, peer, hash);
                            }
                        }

                        break;
                    }
                    case GET_ITEM_TYPE::NOTE_TX: {
                        transaction tx(i.value());

                        log(LOG_INFO, "INFO: Got note transaction [%s].", tx.to_string().c_str());

                        if (!tx.empty() && tx.verify_signature() && tx.type() == tx_type::type_note) {

                            log(LOG_INFO, "INFO: Got note transaction[%s].", tx.to_string().c_str());

                            m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(tx);

                            auto &pool = m_tx_pools[chain_id];

                            if (pool.add_tx_to_time_pool(tx)) {
                                put_note_transaction(chain_id, tx);
                            }
                        }

                        break;
                    }
                    case GET_ITEM_TYPE::TRANSFER_TX: {
                        transaction tx(i.value());

                        if (!tx.empty() && tx.verify_signature() && tx.type() == tx_type::type_transfer) {

                            log(LOG_INFO, "INFO: Got transfer transaction[%s].", tx.to_string().c_str());

                            m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(tx);

                            auto &pool = m_tx_pools[chain_id];
                            if (pool.add_tx_to_fee_pool(tx)) {
                                auto self_tx = pool.get_transaction_by_account(*m_ses.pubkey());
                                auto best_tx = pool.get_best_fee_transaction();
                                if (self_tx.empty() && best_tx == tx) {
                                    // transfer tx only when self tx is not in pool and this tx is not the best
                                    put_transfer_transaction(chain_id, tx);
                                }
                            }
                        }

                        break;
                    }
                    case GET_ITEM_TYPE::NOTE_POOL_ROOT: {
                        sha1_hash note_pool_root(i.value().string().c_str());
                        log(LOG_INFO, "INFO: Got note pool root[%s]", aux::toHex(note_pool_root).c_str());

                        if (!note_pool_root.is_all_zeros()) {
                            get_note_pool_hash_set(chain_id, peer, note_pool_root);
                        }

                        break;
                    }
                    case GET_ITEM_TYPE::STATE_HASH_ARRAY: {
                        state_hash_array hashArray(i.value());
                        log(LOG_INFO, "INFO: Got state hash array[%s].", hashArray.to_string().c_str());

                        auto& acl = m_access_list[chain_id];
                        auto it = acl.find(peer);
                        if (it != acl.end()) {
                            // only peer in acl is allowed
                            it->second.m_state_hash_array = hashArray;
                        }

                        for (auto const& hash: hashArray.HashArray()) {
                            if (!m_repository->is_state_array_in_db(chain_id, hash)) {
                                get_state_array(chain_id, peer, hash);
                            }
                        }

                        state_reception_event(chain_id, peer);

                        break;
                    }
                    case GET_ITEM_TYPE::STATE_ARRAY: {
                        state_array stateArray(i.value());
                        log(LOG_INFO, "INFO: Got state array[%s].", stateArray.to_string().c_str());

                        if (!stateArray.empty()) {
                            m_ses.alerts().emplace_alert<blockchain_state_array_alert>(chain_id, stateArray.StateArray());
                        }

                        if (!m_repository->save_state_array(chain_id, stateArray)) {
                            log(LOG_ERR, "INFO: chain:%s, save state array[%s] fail.",
                                aux::toHex(chain_id).c_str(), stateArray.to_string().c_str());
                        }

                        state_reception_event(chain_id, peer);

                        break;
                    }
                    default: {
                        log(LOG_ERR, "INFO: Unknown type.");
                    }
                }
            } else {
                log(LOG_INFO, "INFO: Chain[%s] Fail to get item: type[%d],salt[%s], timestamp:%" PRId64,
                    aux::toHex(chain_id).c_str(), type, aux::toHex(i.salt()).c_str(), timestamp);

                switch (type) {
                    case GET_ITEM_TYPE::HEAD_BLOCK_HASH:
                    case GET_ITEM_TYPE::HEAD_BLOCK: {
                        if (times == 1) {
                            get_head_block(chain_id, peer, sha1_hash(salt.data()), times + 1);
                        } else if (times >= 2) {
                            request_all_blocks(chain_id, peer);
                        }
                        break;
                    }
                    case GET_ITEM_TYPE::BLOCK: {
                        request_all_blocks(chain_id, peer);
                        break;
                    }
                    case GET_ITEM_TYPE::NOTE_TX: {
                        if (times == 1) {
                            get_transaction(chain_id, peer, sha1_hash(salt.data()), times + 1);
                        }
                        break;
                    }
//                    case GET_ITEM_TYPE::TX_WRAPPER: {
//                        if (times == 1) {
//                            get_transaction_wrapper(chain_id, peer, sha1_hash(salt.data()), times + 1);
//                        }
//                        break;
//                    }
                    case GET_ITEM_TYPE::NOTE_POOL_HASH_SET: {
                        if (times == 1) {
                            get_note_pool_hash_set(chain_id, peer, sha1_hash(salt.data()), times + 1);
                        }
                        break;
                    }
                    case GET_ITEM_TYPE::STATE_HASH_ARRAY:
                    case GET_ITEM_TYPE::STATE_ARRAY: {
                        request_all_state(chain_id, peer);
                        break;
                    }
                    default: {
                        log(LOG_DEBUG, "INFO: ignored type.");
                    }
                }

//                auto it = m_get_item_info.find(getItem);
//                if (it != m_get_item_info.end()) {
//                    it->second.increase_get_times();
//                    if (it->second.m_times < 3) {
//                        m_ses.dht()->get_item(peer, std::bind(&blockchain::get_mutable_callback, self(), chain_id, _1, _2, type, timestamp), salt, timestamp);
//                    } else {
//                        m_access_list[chain_id].erase(peer);
//                    }
//                } else {
//                    m_get_item_info[getItem] = GET_INFO();
//                }
            }
        } catch (std::exception &e) {
            log(LOG_ERR, "ERROR: Exception in get mutable callback [CHAIN] %s in file[%s], func[%s], line[%d]",
                e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    // key is a 32-byte binary string, the public key to look up.
    // the salt is optional
//    void blockchain::dht_get_mutable_item(aux::bytes const& chain_id, std::array<char, 32> key, std::string salt)
//    {
//        if (!m_ses.dht()) return;
//        m_ses.dht()->get_item(dht::public_key(key.data()), std::bind(&blockchain::get_mutable_callback
//                , self(), chain_id, _1, _2), std::move(salt));
//    }

//    void blockchain::dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target)
//    {
//        if (!m_ses.dht()) return;
//        m_ses.dht()->put_item(data,  eps, std::bind(&on_dht_put_immutable_item, std::ref(m_ses.alerts())
//                , target, _1));
//    }

//    void blockchain::dht_put_mutable_item(std::array<char, 32> key
//            , std::function<void(entry&, std::array<char,64>&
//            , std::int64_t&, std::string const&)> cb
//            , std::int8_t alpha, std::int8_t beta, std::int8_t invoke_limit
//            , std::string salt, const dht::public_key &peer, bool cache)
//    {
//        if (!m_ses.dht()) return;
////        m_ses.dht()->put_item(dht::public_key(key.data())
////                , std::bind(&on_dht_put_mutable_item, std::ref(m_ses.alerts()), _1, _2)
////                , std::bind(&put_mutable_callback, _1, std::move(cb)), std::move(salt), peer);
//        m_ses.dht()->put_item(dht::public_key(key.data())
//                , std::bind(&blockchain::on_dht_put_mutable_item, self(), _1, _2, peer)
//                , std::bind(&put_mutable_callback, _1, std::move(cb))
//                , alpha, beta, invoke_limit, salt, peer, cache);
//    }

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


    aux::bytes blockchain::create_chain_id(aux::bytes type, std::string community_name) {
        libTAU::aux::bytes chain_id;
        dht::public_key * pk = m_ses.pubkey();
        std::int64_t now = get_total_milliseconds();

        std::string spk(pk->bytes.begin(), pk->bytes.end());
        std::stringstream data;
        data << spk << now;
        sha1_hash hash = hasher(data.str()).final();
        chain_id.insert(chain_id.end(), hash.begin(), hash.begin() + CHAIN_ID_HASH_MAX_LENGTH);

        chain_id.insert(chain_id.end(), type.begin(), type.end());

        if (community_name.length() > CHAIN_ID_COMMUNITY_NAME_MAX_LENGTH) {
            chain_id.insert(chain_id.end(), community_name.begin(), community_name.begin() + CHAIN_ID_COMMUNITY_NAME_MAX_LENGTH);
        } else {
            chain_id.insert(chain_id.end(), community_name.begin(), community_name.end());
        }

        log(LOG_INFO, "INFO Create chain id[%s] with community name[%s]", aux::toHex(chain_id).c_str(), community_name.c_str());

        return chain_id;
    }

//    bool blockchain::create_TAU_chain() {
//        log(LOG_INFO, "INFO: create tau chain.");
//        std::int64_t size = TAU_CHAIN_GENESIS_ACCOUNT.size();
//        std::int64_t block_number = -1 * size + 1;
//        sha256_hash previous_hash;
//
//        dht::secret_key *sk = m_ses.serkey();
//        dht::public_key *pk = m_ses.pubkey();
//        std::set<dht::public_key> peers;
//
//
//        std::string data(TAU_CHAIN_ID.begin(), TAU_CHAIN_ID.end());
//        auto genSig = hasher(data).final();
//
//        auto ep = m_ses.external_udp_endpoint();
//
//        for (auto const &act: TAU_CHAIN_GENESIS_ACCOUNT) {
//            auto miner = act;
//            peers.insert(miner);
//
//            block b;
//            if (ep.port() != 0) {
//                b = block(TAU_CHAIN_ID, block_version::block_version1, TAU_CHAIN_GENESIS_TIMESTAMP, 0,
//                                sha1_hash(), GENESIS_BASE_TARGET, 0, genSig, transaction(), miner, ep);
//            } else {
//                b = block(TAU_CHAIN_ID, block_version::block_version1, TAU_CHAIN_GENESIS_TIMESTAMP, 0,
//                                sha1_hash(), GENESIS_BASE_TARGET, 0, genSig, transaction(), miner);
//            }
//            b.sign(*pk, *sk);
//
//            blocks.push_back(b);
//
//            previous_hash = b.sha256();
//            block_number++;
//        }
//
//        // follow and load chain
//        followChain(TAU_CHAIN_ID, peers);
//
//        for (auto it = blocks.rbegin(); it != blocks.rend(); ++it) {
//            log(LOG_INFO, "Process tau chain block:%s", it->to_string().c_str());
//            process_block(TAU_CHAIN_ID, *it);
//        }
//
//        return true;
//    }

    bool blockchain::createNewCommunity(const aux::bytes &chain_id, const std::set<account>& accounts) {
        if (!create_chain_db(chain_id))
            return false;

        std::int64_t now = get_total_milliseconds() / 1000; // second

        dht::secret_key *sk = m_ses.serkey();
        dht::public_key *pk = m_ses.pubkey();

        std::string data(pk->bytes.begin(), pk->bytes.end());
        data.insert(data.end(), chain_id.begin(), chain_id.end());
        auto genSig = hasher(data).final();

        std::int64_t total_balance = 0;

//        auto ep = m_ses.external_udp_endpoint();

        int i = 0;
        for (auto const &act: accounts) {
            if (i < MAX_ACCOUNT_SIZE) {
                log(LOG_INFO, "INFO: chain[%s] save account:%s", aux::toHex(chain_id).c_str(), act.to_string().c_str());
                if (!m_repository->save_account(chain_id, act)) {
                    log(LOG_ERR, "INFO: chain:%s, save account[%s] fail.",
                        aux::toHex(chain_id).c_str(), act.to_string().c_str());
                }
                total_balance += act.balance();

                i++;
            } else {
                break;
            }
        }

        std::int64_t genesis_balance = GENESIS_BLOCK_BALANCE > total_balance ? GENESIS_BLOCK_BALANCE - total_balance : 0;
        account genesis_account(*pk, genesis_balance, 0, 1);
        log(LOG_INFO, "INFO: chain[%s] save account:%s", aux::toHex(chain_id).c_str(), genesis_account.to_string().c_str());
        if (!m_repository->save_account(chain_id, genesis_account)) {
            log(LOG_ERR, "INFO: chain:%s, save account[%s] fail.",
                aux::toHex(chain_id).c_str(), genesis_account.to_string().c_str());
        }

        sha1_hash stateRoot;
        std::vector<state_array> stateArrays;
        get_genesis_state(chain_id, stateRoot, stateArrays);

        block b = block(chain_id, block_version::block_version1, now, 0, sha1_hash(),
                  GENESIS_BASE_TARGET, 0, genSig, stateRoot, transaction(), *pk);

        b.sign(*pk, *sk);

        // follow and load chain
        std::set<dht::public_key> peers;
        peers.insert(*pk);
        followChain(chain_id, peers);

        process_genesis_block(chain_id, b, stateArrays);

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

                if (m_chains.find(chain_id) == m_chains.end()) {
                    log(LOG_INFO, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
                    return false;
                }

                if (!m_chain_connected[chain_id]) {
                    log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
                    return false;
                }

                m_tx_pools[chain_id].add_tx(tx);

                if (tx.type() == tx_type::type_transfer) {
                    put_transfer_transaction(chain_id, tx);
                } else if (tx.type() == tx_type::type_note) {
                    put_note_transaction(chain_id, tx);
                }

                return true;
            }
        } catch (std::exception &e) {
            log(LOG_ERR, "Exception add new tx [CHAIN] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
            return false;
        }

        return false;
    }

    bool blockchain::is_transaction_in_fee_pool(const aux::bytes &chain_id, const sha1_hash &txid) {
        if (m_chains.find(chain_id) == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return false;
        }

        if (!m_chain_connected[chain_id]) {
            log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
            return false;
        }

        return m_tx_pools[chain_id].is_transaction_in_fee_pool(txid);
    }

    account blockchain::getAccountInfo(const aux::bytes &chain_id, dht::public_key publicKey) {
        return m_repository->get_account(chain_id, publicKey);
    }

    block blockchain::getBlock(const aux::bytes &chain_id, std::int64_t block_number) {
        return m_repository->get_main_chain_block_by_number(chain_id, block_number);
    }

    block blockchain::getBlock(const aux::bytes &chain_id, sha1_hash block_hash) {
        return m_repository->get_block_by_hash(chain_id, block_hash);
    }

    std::vector<block> blockchain::getTopTipBlocks(const aux::bytes &chain_id, int topNum) {
        if (m_chains.find(chain_id) == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return std::vector<block>();
        }

        if (!m_chain_connected[chain_id]) {
            log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
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
                    auto b = m_repository->get_block_by_hash(chain_id, previous_hash);
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
        if (m_chains.find(chain_id) == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return 0;
        }

        if (!m_chain_connected[chain_id]) {
            log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
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
        if (m_chains.find(chain_id) == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return -1;
        }

        if (!m_chain_connected[chain_id]) {
            log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
            return -1;
        }

        dht::public_key *pk = m_ses.pubkey();

        const auto &head_block = m_head_blocks[chain_id];

        if (!head_block.empty()) {
            if (head_block.block_number() < 0) {
                return -1;
            }

            block ancestor;
            auto previous_hash = head_block.previous_block_hash();
            if (head_block.block_number() % CHAIN_EPOCH_BLOCK_SIZE > 3) {
                int i = 3;
                while (i > 0) {
                    ancestor = m_repository->get_block_by_hash(chain_id, previous_hash);
                    previous_hash = ancestor.previous_block_hash();
                    i--;
                }
            }

            auto base_target = consensus::calculate_required_base_target(head_block, ancestor);
            auto act = m_repository->get_account(chain_id, *pk);
            log(LOG_INFO, "INFO: chain id[%s] account[%s], head block[%s]", aux::toHex(chain_id).c_str(),
                act.to_string().c_str(), head_block.to_string().c_str());
            auto genSig = consensus::calculate_generation_signature(head_block.generation_signature(), *pk);
            auto hit = consensus::calculate_random_hit(genSig);
            auto interval = static_cast<std::int64_t>(consensus::calculate_mining_time_interval(hit, base_target, act.power()));

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
        if (m_chains.find(chain_id) == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return std::set<dht::public_key>();
        }

        if (!m_chain_connected[chain_id]) {
            log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
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
        if (m_chains.find(chain_id) == m_chains.end()) {
            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
            return std::set<dht::public_key>();
        }

        if (!m_chain_connected[chain_id]) {
            log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
            return std::set<dht::public_key>();
        }

        std::set<dht::public_key> peers;
//        auto& ban_list = m_ban_list[chain_id];
//        for (auto const& item: ban_list) {
//            peers.insert(item.first);
//        }

        return peers;
    }

//    std::set<dht::public_key> blockchain::get_gossip_peers(const aux::bytes &chain_id) {
//        auto it = std::find(m_chains.begin(), m_chains.end(), chain_id);
//        if (it == m_chains.end()) {
//            log(LOG_ERR, "INFO: Unfollowed chain[%s]", aux::toHex(chain_id).c_str());
//            return std::set<dht::public_key>();
//        }
//
//        auto gossip_peers = m_gossip_peers[chain_id];
//        if (!gossip_peers.empty()) {
//            return gossip_peers;
//        }
//
//        return m_repository->get_all_gossip_peers(chain_id);
//    }

//    void blockchain::set_blockchain_loop_interval(int milliseconds) {
//        log("INFO: Set block chain loop interval:%d(ms)", milliseconds);
//        m_refresh_time = milliseconds;
//        m_refresh_timer.cancel();
//    }

//    void blockchain::introduce_gossip_peers(const aux::bytes &chain_id, const dht::public_key &peer) {
//        auto const& acl = m_access_list[chain_id];
//        std::set<dht::public_key> peers;
//        int i = 0;
//        for (auto iter = acl.begin(); iter != acl.end() && i < blockchain_acl_max_peers; iter++, i++) {
//            peers.insert(iter->first);
//        }
//
//        peers.erase(peer);
//
//        if (!peers.empty()) {
//            introduce_peers(chain_id, peer, peers);
//        }
//    }

//    void blockchain::introduce_peers(const aux::bytes &chain_id, const dht::public_key &peer, const std::set<dht::public_key>& peers) {
//        auto act = m_repository->get_account(chain_id, peer);
//        if (act.empty()) {
//            common::gossip_peers_entry gossipPeersEntry(chain_id, peers);
//            send_to(peer, gossipPeersEntry.get_entry());
//        } else {
//            account balance_account(act.balance());
//            common::gossip_peers_entry gossipPeersEntry(chain_id, peers, balance_account.balance());
//            send_to(peer, gossipPeersEntry.get_entry());
//        }
//    }

//    void blockchain::put_gossip_peers_to_cache(const aux::bytes &chain_id) {
//        auto const& acl = m_access_list[chain_id];
//        std::set<dht::public_key> peers;
//        int i = 0;
//        for (auto iter = acl.begin(); iter != acl.end() && i < blockchain_acl_max_peers; iter++, i++) {
//            peers.insert(iter->first);
//        }
//
//        if (peers.size() < blockchain_acl_max_peers) {
//            auto gossip_peers = m_repository->get_all_gossip_peers(chain_id);
//            int m = blockchain_acl_max_peers - peers.size();
//            int k = 0;
//            for (const auto & gossip_peer : gossip_peers) {
//                if (k < m) {
//                    peers.insert(gossip_peer);
//                } else {
//                    break;
//                }
//
//                k++;
//            }
//        }
//
//        if (peers.size() < blockchain_acl_max_peers) {
//            int m = blockchain_acl_max_peers - peers.size();
//            for (int k = 0; k < m; k++) {
//                auto pubKey = m_repository->get_peer_randomly(chain_id);
//                if (!pubKey.is_all_zeros()) {
//                    peers.insert(pubKey);
//                }
//            }
//
//        }
//
//        if (!peers.empty()) {
//            common::gossip_cache_peers_entry gossipCachePeersEntry(peers);
//
//            dht::public_key * pk = m_ses.pubkey();
//            dht::secret_key * sk = m_ses.serkey();
//
//            // salt is y pubkey when publish signal
//            auto salt = make_salt(chain_id, common::gossip_cache_peers_entry::data_type_id);
//
//            log(LOG_INFO, "INFO: Chain id[%s] Cache gossip peers salt[%s]", aux::toHex(chain_id).c_str(), aux::toHex(salt).c_str());
//            publish(salt, gossipCachePeersEntry.get_entry());
//        }
//    }

//    void blockchain::add_gossip_peers(const aux::bytes &chain_id, const std::set<dht::public_key> &peers) {
//        m_gossip_peers[chain_id].insert(peers.begin(), peers.end());
//        auto& gossip_peers = m_gossip_peers[chain_id];
//        while (gossip_peers.size() > 10) {
//            srand(get_total_microseconds());
//            auto index = rand() % gossip_peers.size();
//            int i = 0;
//            for (auto it = gossip_peers.begin(); it != gossip_peers.end(); it++) {
//                if (i == index) {
//                    gossip_peers.erase(it);
//                    break;
//                }
//                i++;
//            }
//        }
//    }

    void blockchain::add_peer_into_acl(const aux::bytes &chain_id, const dht::public_key& peer, std::int64_t timestamp) {
        if (peer == *m_ses.pubkey()) {
            return;
        }

//        bool is_new = false;
        
        auto &acl = m_access_list[chain_id];

        log(LOG_INFO, "INFO: chain[%s] update peer[%s] time:%" PRId64,
            aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str(), timestamp);
        auto it = acl.find(peer);
        if (it != acl.end()) {
            if (timestamp > it->second.m_last_seen) {
                it->second.m_last_seen = timestamp;
            }
        } else {
            acl[peer] = peer_info(timestamp);

//            is_new = true;
        }

        if (acl.size() > blockchain_acl_max_peers) {
            std::map<dht::public_key, peer_info> on_chain_peers;
            std::set<dht::public_key> off_chain_peers;
            for (auto const& item: acl) {
                if (m_repository->is_account_existed(chain_id, item.first)) {
                    on_chain_peers.insert(item);
                } else {
                    off_chain_peers.insert(item.first);
                }
            }


            // remove the oldest peer
            if (on_chain_peers.size() > blockchain_acl_max_peers * 2 / 3) {
                auto min_it = on_chain_peers.begin();
                for (auto iter = on_chain_peers.begin(); iter != on_chain_peers.end(); iter++) {
                    if (iter->second.m_last_seen < min_it->second.m_last_seen) {
                        min_it = iter;
                    }
                }

                // remove from acl
                acl.erase(min_it->first);
            }

            // remove randomly
            if (off_chain_peers.size() > blockchain_acl_max_peers / 3) {

                srand(get_total_microseconds());
                auto index = rand() % off_chain_peers.size();
                int i = 0;
                for (const auto & pubkey : off_chain_peers) {
                    if (i == index) {
                        // remove from acl
                        acl.erase(pubkey);
                        break;
                    }
                    i++;
                }
            }
        }

//        if (is_new) {
//            auto iter = acl.find(peer);
//            if (iter != acl.end()) {
//                // get note tx
//                get_new_note_tx_hash(chain_id, peer, 0);
//            }
//        }
    }

    dht::public_key blockchain::select_peer_randomly_from_acl(const bytes &chain_id) {
        auto const &acl = m_access_list[chain_id];
        srand(get_total_microseconds());
        // note: acl may be empty, if acl size == 0, maybe crush
        if (!acl.empty()) {
            auto index = rand() % acl.size();
            int i = 0;
            for (const auto &it : acl) {
                if (i == index) {
                    return it.first;
                }
                i++;
            }
        }

        return dht::public_key();
    }

    void blockchain::on_dht_relay(dht::public_key const& peer, entry const& payload) {
        if (m_pause) {
            log(LOG_INFO, "INFO: Block chain is paused.");
            return;
        }

//        if(payload.type() != entry::dictionary_t){
//            log(LOG_ERR, "ERROR: relay data not dict. to string: %s", payload.to_string().c_str());
//            return;
//        }

        try {
            common::signal_entry signalEntry(payload);

            auto &chain_id = m_short_chain_id_table[signalEntry.m_short_chain_id];

            if (m_chains.find(chain_id) == m_chains.end()) {
                log(LOG_INFO, "INFO: Data from unfollowed chain chain[%s]", aux::toHex(chain_id).c_str());
                return;
            }

            if (!m_chain_connected[chain_id]) {
                log(LOG_ERR, "INFO: Unconnected chain[%s]", aux::toHex(chain_id).c_str());
                return;
            }

            m_ses.alerts().emplace_alert<blockchain_online_peer_alert>(chain_id, peer, signalEntry.m_timestamp);

            log(LOG_INFO, "INFO: chain[%s] Got signal[%s] from peer[%s]",
                aux::toHex(chain_id).c_str(), payload.to_string(true).c_str(), aux::toHex(peer.bytes).c_str());

            switch (signalEntry.m_pid) {
                case common::BLOCKCHAIN_ALL_DATA: {
                    //update time
                    add_peer_into_acl(chain_id, peer, signalEntry.m_timestamp);
                    put_chain_all_data(chain_id);
                    break;
                }
                case common::BLOCKCHAIN_ALL_BLOCKS: {
                    //update time
                    add_peer_into_acl(chain_id, peer, signalEntry.m_timestamp);
                    put_chain_all_blocks(chain_id);
                    break;
                }
                case common::BLOCKCHAIN_ALL_STATE: {
                    //update time
                    add_peer_into_acl(chain_id, peer, signalEntry.m_timestamp);
                    put_chain_all_state(chain_id);
                    break;
                }
                case common::BLOCKCHAIN_ONLINE: {
                    //update time
                    add_peer_into_acl(chain_id, peer, signalEntry.m_timestamp);
                    if (!signalEntry.m_gossip_peer.is_all_zeros()) {
                        add_peer_into_acl(chain_id, signalEntry.m_gossip_peer, 1);
                    }
                    break;
                }
                case common::BLOCKCHAIN_NEW_HEAD_BLOCK: {
                    add_peer_into_acl(chain_id, peer, signalEntry.m_timestamp);
                    if (!signalEntry.m_gossip_peer.is_all_zeros()) {
                        add_peer_into_acl(chain_id, signalEntry.m_gossip_peer, 1);
                    }

                    auto head_block_hash = signalEntry.m_hash;
                    if (!head_block_hash.is_all_zeros()) {
                        auto blk = m_repository->get_block_by_hash(chain_id, head_block_hash);
                        if (blk.empty()) {
                            log(LOG_INFO, "INFO: Cannot get block hash[%s] in local", aux::toHex(head_block_hash).c_str());
                            get_head_block(chain_id, peer, head_block_hash);
                        } else {
                            block_reception_event(chain_id, peer, blk);
                        }
                    }

//                    get_head_block_from_peer(chain_id, peer, signalEntry.m_timestamp - 3);
                    break;
                }
                case common::BLOCKCHAIN_NEW_TRANSFER_TX: {
                    add_peer_into_acl(chain_id, peer, signalEntry.m_timestamp);
                    if (!signalEntry.m_gossip_peer.is_all_zeros()) {
                        add_peer_into_acl(chain_id, signalEntry.m_gossip_peer, 1);
                    }

                    get_transfer_transaction(chain_id, peer, signalEntry.m_timestamp - 3);
                    break;
                }
                case common::BLOCKCHAIN_NEW_NOTE_TX: {
                    add_peer_into_acl(chain_id, peer, signalEntry.m_timestamp);
                    if (!signalEntry.m_gossip_peer.is_all_zeros()) {
                        add_peer_into_acl(chain_id, signalEntry.m_gossip_peer, 1);
                    }

                    auto note_pool_root = signalEntry.m_hash;
                    if (!note_pool_root.is_all_zeros()) {
                        get_note_pool_hash_set(chain_id, peer, note_pool_root);
                    }

//                    get_new_note_tx_hash(chain_id, peer, signalEntry.m_timestamp - 3);
                    break;
                }
                default: {
                }
            }
        } catch (std::exception &e) {
            log(LOG_ERR, "ERROR: Exception on_dht_relay [CHAIN] %s in file[%s], func[%s], line[%d]",
                e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }

    }

    void blockchain::print_acl_info(const aux::bytes &chain_id) {
        // peer list log
        // acl
        auto &acl = m_access_list[chain_id];
        for (auto const &item: acl) {
            log(LOG_INFO, "-----ACL: peer[%s], info[%s]", aux::toHex(item.first.bytes).c_str(),
                item.second.to_string().c_str());
        }
    }

}
