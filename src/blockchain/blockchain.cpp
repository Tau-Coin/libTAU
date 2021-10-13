/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/blockchain.hpp"


using namespace std::placeholders;

namespace libTAU::blockchain {

    bool blockchain::init() {
        // get all chains
        auto chains = m_repository->get_all_chains();
        m_chains.insert(m_chains.end(), chains.begin(), chains.end());

        // get all peers
        for(auto const& chain_id: m_chains) {
            auto peers = m_repository->get_all_peers(chain_id);
            m_chain_peers[chain_id] = peers;
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

        log("INFO: Stop Communication...");

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
//                request_signal(peer);
//                publish_signal(peer);
            }

            m_refresh_timer.expires_after(milliseconds(m_refresh_time));
            m_refresh_timer.async_wait(
                    std::bind(&blockchain::refresh_timeout, self(), _1));
        } catch (std::exception &e) {
            log("Exception init [COMM] %s in file[%s], func[%s], line[%d]", e.what(), __FILE__, __FUNCTION__ , __LINE__);
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

    std::set<dht::public_key> blockchain::select_unchoked_peers(const aux::bytes &chain_id, std::int64_t block_number) {
        std::set<dht::public_key> peers;
        auto chain_peers = m_chain_peers[chain_id];

        dht::public_key *pk = m_ses.pubkey();
        chain_peers.insert(*pk);
        if (chain_peers.size() > 1) {
            auto r_iterator = chain_peers.find(*pk);
            auto l_iterator = r_iterator;
            auto offset = block_number % chain_peers.size();
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