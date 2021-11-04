/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/blockchain.hpp"
#include "libTAU/blockchain/consensus.hpp"
#include "libTAU/kademlia/dht_tracker.hpp"


using namespace std::placeholders;

namespace libTAU::blockchain {

    bool blockchain::init() {
        // get all chains
        auto chains = m_repository->get_all_chains();
        m_chains.insert(m_chains.end(), chains.begin(), chains.end());

        // load all chains
        for(auto const& chain_id: m_chains) {
            load_chain(chain_id);
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
            m_repository->create_peer_db(chain_id);
            m_repository->create_gossip_peer_db(chain_id);

            for (auto const &peer: peers) {
                m_repository->add_peer_in_gossip_peer_db(chain_id, peer);
            }

            load_chain(chain_id);

            m_repository->add_new_chain(chain_id);
            m_chains.push_back(chain_id);

            return true;
        } else {
            return false;
        }
    }

    bool blockchain::unfollowChain(const aux::bytes &chain_id) {
        for (auto it = m_chains.begin(); it != m_chains.end(); ++it) {
            if (chain_id == *it) {
                m_chains.erase(it);
                break;
            }
        }

        m_repository->delete_chain(chain_id);
        clear_chain_cache(chain_id);
        // todo: clear data in db?

        return false;
    }

    bool blockchain::load_chain(const aux::bytes &chain_id) {
        // create tx pool
        m_tx_pools.insert(std::pair<aux::bytes, tx_pool>(chain_id, tx_pool(m_repository)));

        // get all peers
//        m_chain_peers[chain_id] = m_repository->get_all_peers(chain_id);
//        m_chain_gossip_peers[chain_id] = m_repository->get_all_gossip_peers(chain_id);

        // get tip/tail block
        auto tip_block_hash = m_repository->get_best_tip_block_hash(chain_id);
        auto tail_block_hash = m_repository->get_best_tail_block_hash(chain_id);
        if (!tip_block_hash.is_all_zeros() && !tail_block_hash.is_all_zeros()) {
            auto tip_block = m_repository->get_block_by_hash(tip_block_hash);
            auto tail_block = m_repository->get_block_by_hash(tail_block_hash);
            if (!tip_block.empty() && !tail_block.empty()) {
                m_best_tip_blocks[chain_id] = tip_block;
                m_best_tail_blocks[chain_id] = tail_block;

                try_to_update_consensus_point_block(chain_id);
            }
        }

        return true;
    }

    void blockchain::clear_all_cache() {
        m_chains.clear();
        m_tx_pools.clear();
//        m_chain_peers.clear();
//        m_chain_gossip_peers.clear();
        m_unchoked_peers.clear();
        m_unchoked_peer_signal.clear();
        m_update_peer_time.clear();
        m_blocks.clear();
        m_best_tip_blocks.clear();
        m_best_tail_blocks.clear();
        m_consensus_point_blocks.clear();
        m_best_votes.clear();
        m_votes.clear();
        m_latest_signal_time.clear();
    }

    void blockchain::clear_chain_cache(const aux::bytes &chain_id) {
//        m_chains.erase(chain_id);
        m_tx_pools[chain_id].clear();
//        m_chain_peers[chain_id].clear();
//        m_chain_gossip_peers[chain_id].clear();
        m_unchoked_peers[chain_id].clear();
        m_unchoked_peer_signal[chain_id].clear();
        m_update_peer_time.erase(chain_id);
        m_blocks[chain_id].clear();
        m_best_tip_blocks.erase(chain_id);
        m_best_tail_blocks.erase(chain_id);
        m_consensus_point_blocks.erase(chain_id);
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

                auto &best_tip_block = m_best_tip_blocks[chain_id];
                auto &best_tail_block = m_best_tail_blocks[chain_id];
                auto &block_map = m_blocks[chain_id];
                for(auto it = block_map.begin(); it != block_map.end(); ++it) {
                    if (best_tip_block.empty() || it->second.previous_block_hash() == best_tip_block.sha256() ||
                        it->second.sha256() == best_tail_block.previous_block_hash()) {
                        process_block(chain_id, it->second);
                        block_map.erase(it);
                    }
                }

                auto &best_vote = m_best_votes[chain_id];
                if (!best_vote.empty()) {
                    auto hash = m_repository->get_main_chain_block_hash_by_number(chain_id, best_vote.block_number());
                    if (hash != best_vote.block_hash()) {
                        // re-branch
                        auto vote_block = m_blocks[chain_id][best_vote.block_hash()];
                        if (!vote_block.empty()) {
                            auto result = try_to_rebranch(chain_id, vote_block);
                            if (result == MISSING) {
                                m_blocks[chain_id].clear();
                            }
                        }
                    }
                }

                // mine
                block b = try_to_mine_block(chain_id);

                if (!b.empty()) {
                    process_block(chain_id, b);
                }

                try_to_refresh_unchoked_peers(chain_id);

                auto& unchoked_peers = m_unchoked_peers[chain_id];
                std::vector<dht::public_key> peers(unchoked_peers.begin(), unchoked_peers.end());
                auto p = select_peer_randomly(chain_id);
                if (!(p == dht::public_key())) {
                    peers.push_back(p);
                }
                if (!peers.empty())
                {
                    // 产生随机数
                    srand(total_microseconds(system_clock::now().time_since_epoch()));
                    auto index = rand() % peers.size();
                    request_signal(chain_id, peers[index]);
                }


                publish_signal(chain_id);
            }

            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(
                    std::bind(&blockchain::refresh_timeout, self(), _1));
        } catch (std::exception &e) {
            log("Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    void blockchain::refresh_vote_timeout(const error_code &e) {
        if (e || m_stop) return;

        try {
            for (auto const& chain_id: m_chains) {
                refresh_vote(chain_id);
            }

            m_vote_timer.expires_after(seconds(DEFAULT_BLOCK_TIME));
            m_vote_timer.async_wait(std::bind(&blockchain::refresh_vote_timeout, self(), _1));
        } catch (std::exception &e) {
            log("Exception vote [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    void blockchain::try_to_refresh_unchoked_peers(const aux::bytes &chain_id) {
        std::int64_t now = total_seconds(system_clock::now().time_since_epoch());
        if (now / DEFAULT_BLOCK_TIME != m_update_peer_time[chain_id]) {
            auto peers = select_unchoked_peers(chain_id);
            m_unchoked_peers[chain_id] = peers;

            m_update_peer_time[chain_id] = now / DEFAULT_BLOCK_TIME;

            m_unchoked_peer_signal[chain_id].clear();
        }
    }

    aux::bytes blockchain::select_chain_randomly() {
        aux::bytes chain_id;

        if (!m_chains.empty())
        {
            // 产生随机数
            srand(total_microseconds(system_clock::now().time_since_epoch()));
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
//            srand(total_microseconds(system_clock::now().time_since_epoch()));
//            auto index = rand() % peers.size();
//            peer = peers[index];
//        }
//
//        return peer;
        return m_repository->get_peer_randomly(chain_id);
    }

    dht::public_key blockchain::select_unchoked_peer_randomly(const aux::bytes &chain_id) {
        dht::public_key peer{};
        auto& unchoked_peers = m_unchoked_peers[chain_id];
        std::vector<dht::public_key> peers(unchoked_peers.begin(), unchoked_peers.end());

        if (!peers.empty())
        {
            // 产生随机数
            srand(total_microseconds(system_clock::now().time_since_epoch()));
            auto index = rand() % peers.size();
            peer = peers[index];
        }

        return peer;
    }

    std::set<dht::public_key> blockchain::select_unchoked_peers(const aux::bytes &chain_id) {
        std::set<dht::public_key> peers;
        auto chain_peers = m_repository->get_all_peers(chain_id);

        // todo: insert in set?
        dht::public_key *pk = m_ses.pubkey();
        chain_peers.insert(*pk);
        if (chain_peers.size() > 1) {
            auto r_iterator = chain_peers.find(*pk);
            auto l_iterator = r_iterator;
            std::int64_t now = total_seconds(system_clock::now().time_since_epoch());
            auto offset = (now / DEFAULT_BLOCK_TIME) % chain_peers.size();
            for (auto i = 0; i < offset; i++) {
                r_iterator++;
                if (r_iterator == chain_peers.end()) {
                    r_iterator = chain_peers.begin();
                }

                if (l_iterator == chain_peers.begin()) {
                    l_iterator = chain_peers.end();
                }
                l_iterator--;
            }

            peers.insert(*r_iterator);
            peers.insert(*l_iterator);
            r_iterator++;
            if (r_iterator == chain_peers.end()) {
                r_iterator = chain_peers.begin();
            }

            if (l_iterator == chain_peers.begin()) {
                l_iterator = chain_peers.end();
            }
            l_iterator--;

            peers.insert(*r_iterator);
            peers.insert(*l_iterator);
        }

        return peers;
    }

    block blockchain::try_to_mine_block(const aux::bytes &chain_id) {
        dht::secret_key *sk = m_ses.serkey();
        dht::public_key *pk = m_ses.pubkey();

        block b;
        auto best_tip_block = m_best_tip_blocks[chain_id];
        if (!best_tip_block.empty()) {
            block ancestor1 = m_repository->get_block_by_hash(best_tip_block.previous_block_hash());
            if (ancestor1.empty()) {
                return b;
            }

            block ancestor2 = m_repository->get_block_by_hash(ancestor1.previous_block_hash());
            if (ancestor2.empty()) {
                return b;
            }

            block ancestor3 = m_repository->get_block_by_hash(ancestor2.previous_block_hash());
            if (ancestor3.empty()) {
                return b;
            }

            std::int64_t base_target = consensus::calculate_required_base_target(best_tip_block, ancestor3);
            std::int64_t power = m_repository->get_effective_power(chain_id, *pk);
            if (power <= 0) {
                return b;
            }
            auto genSig = consensus::calculate_generation_signature(best_tip_block.generation_signature(), *pk);
            auto hit = consensus::calculate_random_hit(genSig);
            auto interval = consensus::calculate_mining_time_interval(hit, base_target, power);

            std::int64_t now = total_seconds(system_clock::now().time_since_epoch());
            if (now - best_tip_block.timestamp() >= interval) {
                auto tx = m_tx_pools[chain_id].get_best_transaction();
                auto cumulative_difficulty = consensus::calculate_cumulative_difficulty(best_tip_block.cumulative_difficulty(), base_target);
                auto miner_account = m_repository->get_account(chain_id, *pk);
                std::int64_t sender_balance = 0;
                std::int64_t sender_nonce = 0;
                std::int64_t receiver_balance = 0;
                std::int64_t receiver_nonce = 0;
                if (!tx.empty()) {
                    auto sender_account = m_repository->get_account(chain_id, tx.sender());
                    sender_balance = sender_account.balance();
                    sender_nonce = sender_account.nonce();
                    auto receiver_account = m_repository->get_account(chain_id, tx.receiver());
                    receiver_balance = receiver_account.balance();
                    receiver_nonce = receiver_account.nonce();
                }
                b = block(chain_id, block_version::block_version1,(best_tip_block.timestamp() + interval),
                          best_tip_block.block_number() + 1, best_tip_block.sha256(), base_target,
                          cumulative_difficulty, genSig, tx, *pk, miner_account.balance(), miner_account.nonce(),
                          sender_balance, sender_nonce, receiver_balance, receiver_nonce);
                b.sign(*pk, *sk);
            }
        }

        return b;
    }

    RESULT blockchain::verify_block(const aux::bytes &chain_id, block &b, block &previous_block, repository *repo) {
        if (b.empty())
            return FALSE;

        if (!b.verify_signature())
            return FALSE;

        block ancestor1 = repo->get_block_by_hash(previous_block.previous_block_hash());
        if (ancestor1.empty())
            return MISSING;

        block ancestor2 = repo->get_block_by_hash(ancestor1.previous_block_hash());
        if (ancestor2.empty())
            return MISSING;

        block ancestor3 = repo->get_block_by_hash(ancestor2.previous_block_hash());
        if (ancestor3.empty())
            return MISSING;

        std::int64_t base_target = consensus::calculate_required_base_target(previous_block, ancestor3);
        std::int64_t power = repo->get_effective_power(chain_id, b.miner());
        if (power <= 0)
            return MISSING;

        auto genSig = consensus::calculate_generation_signature(previous_block.generation_signature(), b.miner());
        auto hit = consensus::calculate_random_hit(genSig);
        auto interval = consensus::calculate_mining_time_interval(hit, base_target, power);
        if (!consensus::verify_hit(hit, base_target, power, interval))
            return FALSE;

        return TRUE;
    }

    void blockchain::try_to_update_consensus_point_block(const aux::bytes &chain_id) {
        auto& tip_block = m_best_tip_blocks[chain_id];
        auto& tail_block = m_best_tail_blocks[chain_id];

        auto block_number = (tip_block.block_number() / 100 - 1) * 100;
        if (block_number < 0) {
            block_number = 0;
        }

        auto& consensus_block = m_consensus_point_blocks[chain_id];
        if (consensus_block.empty() || consensus_block.block_number() != block_number) {
            auto b = m_repository->get_main_chain_block_by_number(chain_id, block_number);
            if (!b.empty()) {
                m_consensus_point_blocks[chain_id] = consensus_block;
            }
        }
    }

    RESULT blockchain::process_block(const aux::bytes &chain_id, block &b) {
        if (b.empty())
            return FALSE;

        auto &best_tip_block  = m_best_tip_blocks[chain_id];
        if (best_tip_block.empty()) {
            auto track = m_repository->start_tracking();
            track->connect_tip_block(b);
            track->set_best_tip_block_hash(chain_id, b.sha256());
            track->set_best_tail_block_hash(chain_id, b.sha256());
            // update peer set
            track->add_block_peer_in_peer_db(b);
            track->commit();
            m_repository->flush();

            m_tx_pools[chain_id].process_block(b);

            m_best_tip_blocks[chain_id] = b;
            m_best_tail_blocks[chain_id] = b;

            m_ses.alerts().emplace_alert<blockchain_new_tip_block_alert>(b);
        } else {
            if (b.previous_block_hash() == best_tip_block.sha256()) {
                auto track = m_repository->start_tracking();

                auto result = verify_block(chain_id, b, best_tip_block, track);
                if (result != TRUE)
                    return result;

                track->connect_tip_block(b);
                track->set_best_tip_block_hash(chain_id, b.sha256());

                block best_tail_block;
                if (b.block_number() - m_best_tail_blocks[chain_id].block_number() > EFFECTIVE_BLOCK_NUMBER) {
                    m_repository->expire_block(m_best_tail_blocks[chain_id]);
                    // get main chain block
                    best_tail_block = m_repository->get_main_chain_block_by_number(chain_id, b.block_number() - EFFECTIVE_BLOCK_NUMBER);
                    track->set_best_tail_block_hash(chain_id, best_tail_block.sha256());
                }
                // update peer set
                track->add_block_peer_in_peer_db(b);
                track->commit();
                m_repository->flush();

                m_tx_pools[chain_id].process_block(b);

                m_best_tip_blocks[chain_id] = b;
                if (!best_tail_block.empty()) {
                    m_best_tail_blocks[chain_id] = best_tail_block;
                }

                m_ses.alerts().emplace_alert<blockchain_new_tip_block_alert>(b);
            }

            if (m_best_tip_blocks[chain_id].block_number() - m_best_tail_blocks[chain_id].block_number() < EFFECTIVE_BLOCK_NUMBER &&
                    b.sha256() == m_best_tail_blocks[chain_id].previous_block_hash()) {
                auto track = m_repository->start_tracking();
                track->connect_tail_block(b);
                track->set_best_tail_block_hash(chain_id, b.sha256());

                // update peer set
                track->add_block_peer_in_peer_db(b);
                track->commit();
                m_repository->flush();

                m_best_tail_blocks[chain_id] = b;

                m_ses.alerts().emplace_alert<blockchain_new_tail_block_alert>(b);
            }
        }

        try_to_update_consensus_point_block(chain_id);

        return TRUE;
    }

    bool blockchain::is_empty_chain(const aux::bytes &chain_id) {
        auto &best_tip_block = m_best_tip_blocks[chain_id];

        return best_tip_block.empty();
    }

    bool blockchain::is_consensus_point_immutable(const aux::bytes &chain_id) {
        auto &best_vote = m_best_votes[chain_id];
        auto &consensus_block = m_consensus_point_blocks[chain_id];
        if (!best_vote.empty() && !consensus_block.empty() && best_vote.block_hash() != consensus_block.sha256())
            return false;

        return true;
    }

    bool blockchain::is_sync_completed(const aux::bytes &chain_id) {
        auto &best_tail_block = m_best_tail_blocks[chain_id];
        auto &best_tip_block = m_best_tip_blocks[chain_id];

        if (best_tail_block.block_number() < 0 && best_tail_block.previous_block_hash().is_all_zeros())
            return true;

        if (best_tip_block.block_number() - best_tail_block.block_number() >= EFFECTIVE_BLOCK_NUMBER)
            return true;

        return false;
    }

    RESULT blockchain::try_to_rebranch(const aux::bytes &chain_id, block &target) {
        auto &best_tip_block = m_best_tip_blocks[chain_id];
        auto &block_maps = m_blocks[chain_id];

        std::vector<block> undo_blocks;
        std::vector<block> new_blocks;

        bool is_consensus_immutable = is_consensus_point_immutable(chain_id);
        auto consensus_point_block = m_consensus_point_blocks[chain_id];

        block main_chain_block = best_tip_block;
        while (main_chain_block.block_number() > target.block_number()) {
            if (is_consensus_immutable && main_chain_block.sha256() == consensus_point_block.sha256()) {
                m_blocks[chain_id].clear();
                return FALSE;
            }

            undo_blocks.push_back(main_chain_block);

            main_chain_block = m_repository->get_block_by_hash(main_chain_block.previous_block_hash());
            if (main_chain_block.empty())
                return MISSING;
        }

        block reference_block = target;
        while (best_tip_block.block_number() < reference_block.block_number()) {
            new_blocks.push_back(reference_block);

            auto it = block_maps.find(reference_block.previous_block_hash());
            if (it != block_maps.end()) {
                reference_block = it->second;
            } else {
                reference_block = m_repository->get_block_by_hash(reference_block.previous_block_hash());
            }

            if (reference_block.empty())
                return MISSING;
        }

        while (main_chain_block.sha256() != reference_block.sha256()) {
            if (is_consensus_immutable && main_chain_block.sha256() == consensus_point_block.sha256()) {
                m_blocks[chain_id].clear();
                return FALSE;
            }

            undo_blocks.push_back(main_chain_block);

            main_chain_block = m_repository->get_block_by_hash(main_chain_block.previous_block_hash());
            if (main_chain_block.empty())
                return MISSING;

            new_blocks.push_back(reference_block);

            auto it = block_maps.find(reference_block.previous_block_hash());
            if (it != block_maps.end()) {
                reference_block = it->second;
            } else {
                reference_block = m_repository->get_block_by_hash(reference_block.previous_block_hash());
            }

            if (reference_block.empty())
                return MISSING;

            if (main_chain_block.block_number() <= 0)
                return FALSE;
        }

        new_blocks.push_back(reference_block);

        auto track = m_repository->start_tracking();
        auto best_tail_block = m_best_tail_blocks[chain_id];
        bool tail_missing = false;
        for (auto &b: undo_blocks) {
            track->rollback_block(b);
            if (!tail_missing) {
                auto previous_block = track->get_block_by_hash(best_tail_block.previous_block_hash());
                if (!previous_block.empty()) {
                    best_tail_block = previous_block;
                    track->connect_tail_block(previous_block);
                } else {
                    tail_missing = true;
                }
            }

            m_tx_pools[chain_id].process_block(b);

            m_ses.alerts().emplace_alert<blockchain_rollback_block_alert>(b);
        }

        for (auto i = new_blocks.size(); i > 1; i--) {
            auto &b = new_blocks[i - 2];
            auto &previous_block = new_blocks[i - 1];

            if (!tail_missing) {
                auto result = verify_block(chain_id, b, previous_block, track);
                if (result != TRUE)
                    return result;
            }

            track->connect_tip_block(b);
            // update peer set
            track->add_block_peer_in_peer_db(b);

            m_tx_pools[chain_id].process_block(b);

            m_ses.alerts().emplace_alert<blockchain_new_tip_block_alert>(b);
        }

        m_ses.alerts().emplace_alert<blockchain_fork_point_block_alert>(reference_block);

        while (target.block_number() - best_tail_block.block_number() > EFFECTIVE_BLOCK_NUMBER) {
            track->expire_block(best_tail_block);
            // get main chain block
            best_tail_block = track->get_main_chain_block_by_number(chain_id, best_tail_block.block_number() + 1);
            track->set_best_tail_block_hash(chain_id, best_tail_block.sha256());
        }
        track->set_best_tip_block_hash(chain_id, target.sha256());

        track->commit();
        m_repository->flush();

        m_best_tip_blocks[chain_id] = target;
        m_best_tail_blocks[chain_id] = best_tail_block;

        try_to_update_consensus_point_block(chain_id);

        return TRUE;
    }

    void blockchain::refresh_vote(const aux::bytes &chain_id) {
        std::set<vote> votes;
        auto & peer_votes = m_votes[chain_id];
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

        if (!votes.empty()) {
            m_best_votes[chain_id] = *votes.rbegin();

            std::vector<vote> top_three_votes;
            int i = 0;
            for (auto it = votes.rbegin(); it != votes.rend(); ++it) {
                if (i >= 3)
                    break;

                top_three_votes.push_back(*it);
                i++;
            }
            m_ses.alerts().emplace_alert<blockchain_top_three_votes_alert>(top_three_votes);

        }
        m_votes[chain_id].clear();
    }

    namespace {

        void on_dht_put_immutable_item(aux::alert_manager& alerts, sha256_hash target, int num)
        {
        }

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
                                        std::vector<transaction> &missing_txs,
                                        std::vector<sha256_hash> &confirmation_roots) {
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
            for (auto &tx: txs) {
                target.push_back(tx.sha256()[0]);
            }

            const size_t sourceLength = source.size();
            const size_t targetLength = size;

            log("INFO: tx array: source array[%s], target array[%s]", aux::toHex(source).c_str(), aux::toHex(target).c_str());
            // 如果source和target一样，则直接跳过Levenshtein数组匹配计算
            if (source == target) {
                for (auto &tx: txs) {
//                        log("INFO: Confirm message hash[%s]", aux::toHex(msg.sha256().to_string()).c_str());
                    confirmation_roots.push_back(tx.sha256());
                }
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
                    } else {
//                            log("INFO: Confirm message hash[%s]", aux::toHex(messages[j - 1].sha256().to_string()).c_str());
                        confirmation_roots.push_back(txs[j - 1].sha256());
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
            for(; j > 0; j--) {
//                    log("INFO: Confirm message hash[%s]", aux::toHex(messages[j - 1].sha256().to_string()).c_str());
                confirmation_roots.push_back(txs[j - 1].sha256());
            }

            // reverse missing messages
//                std::reverse(missing_messages.begin(), missing_messages.end());
        }
    }

    std::string blockchain::make_salt(const aux::bytes &chain_id) {
        std::string salt(chain_id.begin(), chain_id.begin() + blockchain_salt_length);

        return salt;
    }

    void blockchain::request_signal(const aux::bytes &chain_id, const dht::public_key &peer) {
        // salt is x pubkey when request signal
        auto salt = make_salt(chain_id);

//        log("INFO: Get mutable data: peer[%s], salt:[%s]", aux::toHex(peer.bytes.data()).c_str(), aux::toHex(salt).c_str());
        dht_get_mutable_item(chain_id, peer.bytes, salt);
    }

    void blockchain::publish_signal(const aux::bytes &chain_id) {
        auto &consensus_point_block = m_consensus_point_blocks[chain_id];
        vote consensus_point_vote;
        if (!consensus_point_block.empty()) {
            consensus_point_vote.setBlockHash(consensus_point_block.sha256());
            consensus_point_vote.setBlockNumber(consensus_point_block.block_number());
        }

        auto &best_tip_block = m_best_tip_blocks[chain_id];
        immutable_data_info best_tip_block_info;
        if (!best_tip_block.empty()) {
//        m_ses.alerts().emplace_alert<communication_syncing_message_alert>
//                (peer, missing_message.sha256(), total_milliseconds(system_clock::now().time_since_epoch()));

            std::vector<dht::node_entry> entries;
            m_ses.dht()->find_live_nodes(best_tip_block.sha256(), entries);
            while (entries.size() > 1) {
                entries.pop_back();
            }
            log("INFO: Put immutable best tip block target[%s], entries[%zu]",
                aux::toHex(best_tip_block.sha256().to_string()).c_str(), entries.size());
            dht_put_immutable_item(best_tip_block.get_entry(), entries, best_tip_block.sha256());

            best_tip_block_info = immutable_data_info(best_tip_block.sha256(), entries);
        }

        immutable_data_info consensus_point_block_info;
        if (!consensus_point_block.empty()) {
//        m_ses.alerts().emplace_alert<communication_syncing_message_alert>
//                (peer, missing_message.sha256(), total_milliseconds(system_clock::now().time_since_epoch()));

            std::vector<dht::node_entry> entries;
            m_ses.dht()->find_live_nodes(consensus_point_block.sha256(), entries);
            while (entries.size() > 1) {
                entries.pop_back();
            }
            log("INFO: Put immutable consensus point tip block target[%s], entries[%zu]",
                aux::toHex(consensus_point_block.sha256().to_string()).c_str(), entries.size());
            dht_put_immutable_item(consensus_point_block.get_entry(), entries, consensus_point_block.sha256());

            consensus_point_block_info = immutable_data_info(consensus_point_block.sha256(), entries);
        }

        auto peer = select_unchoked_peer_randomly(chain_id);
        auto peer_signal = m_unchoked_peer_signal[chain_id][peer];

        std::set<immutable_data_info> block_set;
        if (!peer_signal.demand_block_hash_set().empty())
        {
            auto& demand_block_hash_set = peer_signal.demand_block_hash_set();
            std::vector<sha256_hash> block_hashes(demand_block_hash_set.begin(), demand_block_hash_set.end());
            // 产生随机数
            srand(total_microseconds(system_clock::now().time_since_epoch()));
            auto index = rand() % block_hashes.size();
            auto demand_block_hash = block_hashes[index];
            auto demand_block = m_repository->get_block_by_hash(demand_block_hash);
            if (!demand_block.empty()) {
                //        m_ses.alerts().emplace_alert<communication_syncing_message_alert>
//                (peer, missing_message.sha256(), total_milliseconds(system_clock::now().time_since_epoch()));

                std::vector<dht::node_entry> entries;
                m_ses.dht()->find_live_nodes(demand_block.sha256(), entries);
                while (entries.size() > 1) {
                    entries.pop_back();
                }
                log("INFO: Put immutable consensus point tip block target[%s], entries[%zu]",
                    aux::toHex(demand_block.sha256().to_string()).c_str(), entries.size());
                dht_put_immutable_item(demand_block.get_entry(), entries, demand_block.sha256());

                immutable_data_info demand_block_info(demand_block.sha256(), entries);
                block_set.insert(demand_block_info);
            }
        }

        std::set<immutable_data_info> tx_set;
        // find out missing messages and confirmation root
        std::vector<transaction> missing_txs;
        std::vector<sha256_hash> confirmation_roots;
        std::vector<transaction> txs = m_tx_pools[chain_id].get_top_ten_transactions();
        log("INFO: Txs size:%zu", txs.size());
        find_best_solution(txs, peer_signal.tx_hash_prefix_array(),missing_txs, confirmation_roots);

        log("INFO: Found missing tx size %zu", missing_txs.size());

        if (!missing_txs.empty()) {
            // 产生随机数
            srand(total_microseconds(system_clock::now().time_since_epoch()));
            auto index = rand() % missing_txs.size();
            auto miss_tx = missing_txs[index];
            if (!miss_tx.empty()) {
                //        m_ses.alerts().emplace_alert<communication_syncing_message_alert>
//                (peer, missing_message.sha256(), total_milliseconds(system_clock::now().time_since_epoch()));

                std::vector<dht::node_entry> entries;
                m_ses.dht()->find_live_nodes(miss_tx.sha256(), entries);
                while (entries.size() > 1) {
                    entries.pop_back();
                }
                log("INFO: Put immutable consensus point tip block target[%s], entries[%zu]",
                    aux::toHex(miss_tx.sha256().to_string()).c_str(), entries.size());
                dht_put_immutable_item(miss_tx.get_entry(), entries, miss_tx.sha256());

                immutable_data_info demand_tx_info(miss_tx.sha256(), entries);
                tx_set.insert(demand_tx_info);
            }
        }

        std::set<sha256_hash> demand_block_hash_set;
        auto &best_vote = m_best_votes[chain_id];
        if (is_empty_chain(chain_id)) {
            if (!best_vote.empty()) {
                demand_block_hash_set.insert(best_vote.block_hash());
            } else {
                // select randomly
                auto &votes = m_votes[chain_id];
                auto it = votes.begin();
                if (it != votes.end()) {
                    demand_block_hash_set.insert(it->second.block_hash());
                }
            }
        } else {
            if (!best_vote.empty()) {
                auto hash = m_repository->get_main_chain_block_hash_by_number(chain_id, best_vote.block_number());
                if (hash != best_vote.block_hash()) {
                    demand_block_hash_set.insert(best_vote.block_hash());
                } else {
                    auto &block_map = m_blocks[chain_id];
                    for (auto & item: block_map) {
                        auto b = item.second;
                        if (b.cumulative_difficulty() > best_tip_block.cumulative_difficulty()) {
                            auto previous_hash = b.previous_block_hash();
                            auto it = block_map.find(previous_hash);
                            while (true) {
                                if (it != block_map.end()) {
                                    b = it->second;
                                    if (b.empty()) {
                                        demand_block_hash_set.insert(previous_hash);
                                        break;
                                    } else {
                                        previous_hash = b.previous_block_hash();
                                        it = block_map.find(previous_hash);
                                    }
                                } else {
                                    demand_block_hash_set.insert(previous_hash);
                                    break;
                                }
                            }
                        }
                    }
                    if (!is_sync_completed(chain_id)) {
                        auto &best_tail_block = m_best_tail_blocks[chain_id];
                        if (!best_tail_block.empty()) {
                            demand_block_hash_set.insert(best_tail_block.previous_block_hash());
                        }
                    }
                }
            } else {
                auto &block_map = m_blocks[chain_id];
                for (auto & item: block_map) {
                    auto b = item.second;
                    if (b.cumulative_difficulty() > best_tip_block.cumulative_difficulty()) {
                        auto previous_hash = b.previous_block_hash();
                        auto it = block_map.find(previous_hash);
                        while (true) {
                            if (it != block_map.end()) {
                                b = it->second;
                                if (b.empty()) {
                                    demand_block_hash_set.insert(previous_hash);
                                    break;
                                } else {
                                    previous_hash = b.previous_block_hash();
                                    it = block_map.find(previous_hash);
                                }
                            } else {
                                demand_block_hash_set.insert(previous_hash);
                                break;
                            }
                        }
                    }
                }
                if (!is_sync_completed(chain_id)) {
                    auto &best_tail_block = m_best_tail_blocks[chain_id];
                    if (!best_tail_block.empty()) {
                        demand_block_hash_set.insert(best_tail_block.previous_block_hash());
                    }
                }
            }
        }

        aux::bytes tx_hash_prefix_array = m_tx_pools[chain_id].get_hash_prefix_array();

        auto p = select_peer_randomly(chain_id);

        blockchain_signal signal(total_milliseconds(system_clock::now().time_since_epoch()), consensus_point_vote,
                                 best_tip_block_info, consensus_point_block_info,
                                 block_set, tx_set, demand_block_hash_set,
                                 tx_hash_prefix_array, p);

//        log("INFO: Publish online signal: peer[%s], salt[%s], online signal[%s]", aux::toHex(pk->bytes).c_str(),
//            aux::toHex(salt).c_str(), onlineSignal.to_string().c_str());

        dht::public_key * pk = m_ses.pubkey();
        dht::secret_key * sk = m_ses.serkey();

        auto salt = make_salt(chain_id);
        dht_put_mutable_item(pk->bytes, std::bind(&put_mutable_data, _1, _2, _3, _4
                , pk->bytes, sk->bytes, signal.get_entry()), salt);
    }

    // callback for dht_immutable_get
    void blockchain::get_immutable_block_callback(aux::bytes const& chain_id, sha256_hash target, dht::item const& i)
    {
        log("DEBUG: Immutable block callback");
        TORRENT_ASSERT(!i.is_mutable());
        if (!i.empty()) {
            log("INFO: Got immutable block callback, target[%s].", aux::toHex(target.to_string()).c_str());

            block b(i.value());
            if (!b.empty()) {
                m_blocks[chain_id][b.sha256()] = b;
            }
        }
    }

    void blockchain::dht_get_immutable_block_item(aux::bytes const& chain_id, sha256_hash const& target, std::vector<dht::node_entry> const& eps)
    {
        if (!m_ses.dht()) return;
        log("INFO: Get immutable block, target[%s], entries size[%zu]", aux::toHex(target.to_string()).c_str(), eps.size());
        m_ses.dht()->get_item(target, eps, std::bind(&blockchain::get_immutable_block_callback
                , this, chain_id, target, _1));
    }

    // callback for dht_immutable_get
    void blockchain::get_immutable_tx_callback(aux::bytes const& chain_id, sha256_hash target, dht::item const& i)
    {
        log("DEBUG: Immutable tx callback");
        TORRENT_ASSERT(!i.is_mutable());
        if (!i.empty()) {
            log("INFO: Got immutable tx callback, target[%s].", aux::toHex(target.to_string()).c_str());

            transaction tx(i.value());
            m_tx_pools[chain_id].add_tx(tx);

            m_ses.alerts().emplace_alert<blockchain_new_transaction_alert>(tx);
        }
    }

    void blockchain::dht_get_immutable_tx_item(aux::bytes const& chain_id, sha256_hash const& target, std::vector<dht::node_entry> const& eps)
    {
        if (!m_ses.dht()) return;
        log("INFO: Get immutable tx, target[%s], entries size[%zu]", aux::toHex(target.to_string()).c_str(), eps.size());
        m_ses.dht()->get_item(target, eps, std::bind(&blockchain::get_immutable_tx_callback
                , this, chain_id, target, _1));
    }

    // callback for dht_mutable_get
    void blockchain::get_mutable_callback(aux::bytes const& chain_id, dht::item const& i
            , bool const authoritative)
    {
        TORRENT_ASSERT(i.is_mutable());

        // construct mutable data wrapper from entry
        if (!i.empty()) {
            auto now = total_milliseconds(system_clock::now().time_since_epoch());

            auto peer = i.pk();

            blockchain_signal signal(i.value());

            // todo: latest signal time
            auto consensus_point_vote = signal.consensus_point_vote();
            if (!consensus_point_vote.empty() && now < signal.timestamp() + DEFAULT_BLOCK_TIME * 1000) {
                m_votes[chain_id][peer] = consensus_point_vote;
            }

            auto &best_tip_block_info = signal.best_tip_block_info();
            if (!best_tip_block_info.empty()) {
                // get immutable message
//                log("INFO: Payload:%s", payload.to_string().c_str());
                dht_get_immutable_block_item(chain_id, best_tip_block_info.target(), best_tip_block_info.entries());
            }

            auto &consensus_point_block_info = signal.consensus_point_block_info();
            if (!consensus_point_block_info.empty()) {
                // get immutable message
//                log("INFO: Payload:%s", payload.to_string().c_str());
                dht_get_immutable_block_item(chain_id, consensus_point_block_info.target(), consensus_point_block_info.entries());
            }

            auto &block_info_set = signal.block_info_set();
            for (auto const & block_info: block_info_set) {
                if (!block_info.empty()) {
                    dht_get_immutable_block_item(chain_id, block_info.target(), block_info.entries());
                }
            }

            auto &tx_info_set = signal.tx_info_set();
            for (auto const & tx_info: tx_info_set) {
                if (!tx_info.empty()) {
                    dht_get_immutable_tx_item(chain_id, tx_info.target(), tx_info.entries());
                }
            }

            auto &gossip_peer = signal.peer();
            if (gossip_peer != dht::public_key()) {
                m_repository->add_peer_in_gossip_peer_db(chain_id, gossip_peer);
            }

            // save signal
            auto it = m_unchoked_peers[chain_id].find(peer);
            if (it != m_unchoked_peers[chain_id].end()) {
                m_unchoked_peer_signal[chain_id][peer] = signal;
            }
        }
    }

    // key is a 32-byte binary string, the public key to look up.
    // the salt is optional
    void blockchain::dht_get_mutable_item(aux::bytes const& chain_id, std::array<char, 32> key
            , std::string salt)
    {
        if (!m_ses.dht()) return;
        m_ses.dht()->get_item(dht::public_key(key.data()), std::bind(&blockchain::get_mutable_callback
                , this, chain_id, _1, _2), std::move(salt));
    }

    void blockchain::dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target)
    {
        if (!m_ses.dht()) return;
        log("INFO: Put immutable item target[%s], entries[%zu], data[%s]",
            aux::toHex(target.to_string()).c_str(), eps.size(), data.to_string().c_str());

        m_ses.dht()->put_item(data,  eps, std::bind(&on_dht_put_immutable_item, std::ref(m_ses.alerts())
                , target, _1));
    }

    void blockchain::dht_put_mutable_item(std::array<char, 32> key
            , std::function<void(entry&, std::array<char,64>&
            , std::int64_t&, std::string const&)> cb
            , std::string salt)
    {
        if (!m_ses.dht()) return;
        m_ses.dht()->put_item(dht::public_key(key.data())
                , std::bind(&on_dht_put_mutable_item, std::ref(m_ses.alerts()), _1, _2)
                , std::bind(&put_mutable_callback, _1, std::move(cb)), salt);
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
        std::int64_t now = total_microseconds(system_clock::now().time_since_epoch());

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

        return chain_id;
    }

    bool blockchain::createNewCommunity(const aux::bytes &chain_id, const std::map<dht::public_key, account>& accounts) {
        std::int64_t now = total_seconds(system_clock::now().time_since_epoch());

        dht::secret_key *sk = m_ses.serkey();
        dht::public_key *pk = m_ses.pubkey();

        std::int64_t base_target = GENESIS_BASE_TARGET;
        std::string data(pk->bytes.begin(), pk->bytes.end());
        auto genSig = dht::item_target_id(data);
        std::int64_t cumulative_difficulty = 0;

        std::int64_t size = accounts.size();
        std::int64_t block_number = -1 * size;
        sha256_hash previous_hash;

        std::set<dht::public_key> peers;
        std::vector<block> blocks;
        for (auto const &act: accounts) {
            auto miner = act.first;
            peers.insert(miner);
            std::int64_t miner_balance = act.second.balance();

            block b = block(chain_id, block_version::block_version1, now, block_number, previous_hash,
                            base_target, cumulative_difficulty, genSig, transaction(), miner, miner_balance,
                            0, 0, 0, 0, 0);
            b.sign(*pk, *sk);

            blocks.push_back(b);

            previous_hash = b.sha256();
            block_number++;
        }

        block b = block(chain_id, block_version::block_version1, now, block_number, previous_hash,
                        base_target, cumulative_difficulty, genSig, transaction(), *pk, GENESIS_BLOCK_BALANCE,
                        0, 0, 0, 0, 0);
        b.sign(*pk, *sk);

        blocks.push_back(b);

        // follow and load chain
        followChain(chain_id, peers);

        for (auto &blk: blocks) {
            process_block(chain_id, blk);
        }

        return true;
    }

    bool blockchain::submitTransaction(transaction tx) {
        if (!tx.empty()) {
            auto &chain_id = tx.chain_id();
            return m_tx_pools[chain_id].add_tx(tx);
        }

        return false;
    }

    account blockchain::getAccountInfo(const aux::bytes &chain_id, dht::public_key publicKey) {
        return m_repository->get_account_with_effective_power(chain_id, publicKey);
    }

    std::vector<block> blockchain::getTopTipBlock(const aux::bytes &chain_id, int topNum) {
        std::vector<block> blocks;
        if (topNum > 0) {
            auto best_tip_block = m_best_tip_blocks[chain_id];
            if (!best_tip_block.empty()) {
                blocks.push_back(best_tip_block);
                topNum--;
                auto previous_hash = best_tip_block.previous_block_hash();
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

    std::int64_t blockchain::getMedianTxFree(const aux::bytes &chain_id) {
        std::vector<transaction> txs = m_tx_pools[chain_id].get_top_ten_transactions();
        auto size = txs.size();
        if (size > 0) {
            return txs[size / 2].fee();
        }

        return 0;
    }

}