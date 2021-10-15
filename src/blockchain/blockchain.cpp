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

        // get all peers
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

        return true;
    }

    bool blockchain::stop()
    {
        m_stop = true;

        clear();

        log("INFO: Stop BlockChain...");

        return true;
    }

    bool blockchain::follow_chain(const aux::bytes &chain_id) {
        return true;
    }

    bool blockchain::load_chain(const aux::bytes &chain_id) {
        auto peers = m_repository->get_all_peers(chain_id);
        m_chain_peers[chain_id] = peers;

        auto tip_block_hash = m_repository->get_best_tip_block_hash(chain_id);
        auto tail_block_hash = m_repository->get_best_tail_block_hash(chain_id);
        if (!tip_block_hash.is_all_zeros() && !tail_block_hash.is_all_zeros()) {
            auto tip_block = m_repository->get_block_by_hash(tip_block_hash);
            auto tail_block = m_repository->get_block_by_hash(tail_block_hash);
            if (!tip_block.empty() && !tail_block.empty()) {
                m_best_tip_blocks[chain_id] = tip_block;
                m_best_tail_blocks[chain_id] = tail_block;
            }
        }

        return true;
    }

    void blockchain::clear() {

    }

    void blockchain::refresh_timeout(const error_code &e) {
        if (e || m_stop) return;

        try {
            // 随机挑选一条
            aux::bytes chain_id = select_chain_randomly();
            if (!chain_id.empty()) {
                log("INFO: Select chain:%s", aux::toHex(chain_id).c_str());
                try_to_refresh_unchoked_peers(chain_id);
                auto& unchoked_peers = m_unchoked_peers[chain_id];
                std::set<dht::public_key> peers(unchoked_peers.begin(), unchoked_peers.end());
                auto p = select_peer_randomly(chain_id);
                peers.insert(p);
                for (auto const& peer: peers) {
                    request_signal(chain_id, peer);
//                    publish_signal(peer);
                }
            }

            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(
                    std::bind(&blockchain::refresh_timeout, self(), _1));
        } catch (std::exception &e) {
            log("Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
        }
    }

    void blockchain::try_to_refresh_unchoked_peers(const aux::bytes &chain_id) {
        std::int64_t now = total_seconds(system_clock::now().time_since_epoch());
        if (now / DEFAULT_BLOCK_TIME != m_update_peer_time[chain_id]) {
            auto peers = select_unchoked_peers(chain_id);
            m_unchoked_peers[chain_id] = peers;

            m_update_peer_time[chain_id] = now / DEFAULT_BLOCK_TIME;
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
        dht::public_key peer{};
        auto& chain_peers = m_chain_peers[chain_id];
        std::vector<dht::public_key> peers(chain_peers.begin(), chain_peers.end());

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
        auto chain_peers = m_chain_peers[chain_id];

        // todo: insert in set?
        dht::public_key *pk = m_ses.pubkey();
        chain_peers.insert(*pk);
        if (chain_peers.size() > 1) {
            auto r_iterator = chain_peers.find(*pk);
            auto l_iterator = r_iterator;
            std::int64_t second = total_seconds(system_clock::now().time_since_epoch());
            auto offset = (second / DEFAULT_BLOCK_TIME) % chain_peers.size();
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
            block ancestor1 = m_repository->get_block_by_hash(best_tip_block.sha256());
            if (ancestor1.empty()) {
                // todo:request
                return b;
            }

            block ancestor2 = m_repository->get_block_by_hash(ancestor1.sha256());
            if (ancestor2.empty()) {
                // todo:request
                return b;
            }

            block ancestor3 = m_repository->get_block_by_hash(ancestor2.sha256());
            if (ancestor3.empty()) {
                // todo:request
                return b;
            }

            std::int64_t base_target = consensus::calculate_required_base_target(best_tip_block, ancestor3);
            std::int64_t power = m_repository->get_effective_power(chain_id, *pk);
            if (power <= 0) {
                // todo:request
                return b;
            }
            auto genSig = consensus::calculate_generation_signature(best_tip_block.generation_signature(), *pk);
            auto hit = consensus::calculate_random_hit(genSig);
            auto interval = consensus::calculate_mining_time_interval(hit, base_target, power);

            std::int64_t now = total_seconds(system_clock::now().time_since_epoch());
            if (now - best_tip_block.timestamp() >= interval) {
                auto miner_account = m_repository->get_account(chain_id, *pk);
                b = block(block_version::block_version1, chain_id,
                          (best_tip_block.timestamp() + interval), best_tip_block.block_number() + 1,
                          best_tip_block.sha256(), base_target, 0, genSig, transaction(), *pk,
                          miner_account.balance(), miner_account.nonce(), 0, 0, 0, 0);
                b.sign(*pk, *sk);
            }
        }

        return b;
    }

    std::string blockchain::make_salt(const aux::bytes &chain_id) {
        std::string salt(chain_id.begin(), chain_id.begin() + blockchain_salt_length);

        return salt;
    }

    void blockchain::request_signal(const aux::bytes &chain_id, const dht::public_key &peer) {
//        dht::public_key * my_pk = m_ses.pubkey();
//        aux::bytes public_key(my_pk->bytes.begin(), my_pk->bytes.end());
//
//        // salt is x pubkey when request signal
//        auto salt = make_salt(public_key);
//
//        std::array<char, 32> pk{};
//        std::copy(peer.begin(), peer.end(), pk.begin());
//
//        log("INFO: Get mutable data: peer[%s], salt:[%s]", aux::toHex(peer).c_str(), aux::toHex(salt).c_str());
//        dht_get_mutable_item(pk, salt);
    }

    void blockchain::publish_signal(const aux::bytes &peer) {

    }

    // callback for dht_immutable_get
    void blockchain::get_immutable_callback(aux::bytes const& peer, sha256_hash target
            , dht::item const& i)
    {
        log("DEBUG: Immutable callback");
        TORRENT_ASSERT(!i.is_mutable());
        if (!i.empty()) {
            log("INFO: Got immutable data callback, target[%s].", aux::toHex(target.to_string()).c_str());

//            message msg(i.value());
//
//            add_new_message(peer, msg, true);
        }
    }

    void blockchain::dht_get_immutable_item(aux::bytes const& peer, sha256_hash const& target, std::vector<dht::node_entry> const& eps)
    {
        if (!m_ses.dht()) return;
        log("INFO: Get immutable item, target[%s], entries size[%zu]", aux::toHex(target.to_string()).c_str(), eps.size());
        m_ses.dht()->get_item(target, eps, std::bind(&blockchain::get_immutable_callback
                , this, peer, target, _1));
    }

    // callback for dht_mutable_get
    void blockchain::get_mutable_callback(dht::item const& i
            , bool const authoritative)
    {
        TORRENT_ASSERT(i.is_mutable());

        // construct mutable data wrapper from entry
        if (!i.empty()) {
            dht::public_key * pk = m_ses.pubkey();
            aux::bytes public_key(pk->bytes.begin(), pk->bytes.end());

            aux::bytes peer(i.pk().bytes.begin(), i.pk().bytes.end());
        }
    }

    // key is a 32-byte binary string, the public key to look up.
    // the salt is optional
    void blockchain::dht_get_mutable_item(std::array<char, 32> key
            , std::string salt)
    {
        if (!m_ses.dht()) return;
        m_ses.dht()->get_item(dht::public_key(key.data()), std::bind(&blockchain::get_mutable_callback
                , this, _1, _2), std::move(salt));
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
        return m_ses.alerts().should_post<communication_log_alert>();
    }

    TORRENT_FORMAT(2,3)
    void blockchain::log(char const* fmt, ...) const noexcept try
    {
#ifndef TORRENT_DISABLE_LOGGING
        if (!should_log()) return;

        va_list v;
        va_start(v, fmt);
        m_ses.alerts().emplace_alert<communication_log_alert>(fmt, v);
        va_end(v);
#endif
    }
    catch (std::exception const&) {}

}