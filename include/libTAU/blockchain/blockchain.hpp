/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BLOCKCHAIN_HPP
#define LIBTAU_BLOCKCHAIN_HPP


#include <map>
#include <set>
#include <vector>

#include "libTAU/time.hpp"
#include "libTAU/aux_/alert_manager.hpp" // for alert_manager
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/deadline_timer.hpp"
#include "libTAU/aux_/session_interface.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/kademlia/node_entry.hpp"
#include "libTAU/blockchain/blockchain_signal.hpp"
#include "libTAU/blockchain/constants.hpp"
#include "libTAU/blockchain/repository.hpp"
#include "libTAU/blockchain/repository_impl.hpp"
#include "libTAU/blockchain/repository_track.hpp"
#include "libTAU/blockchain/tx_pool.hpp"

namespace libTAU::blockchain {

    using system_clock = std::chrono::system_clock;

    // default refresh time of main task(50)(ms)
    constexpr int blockchain_default_refresh_time = 50;

    // salt length (first 16 bytes of public key)
    constexpr int blockchain_salt_length = 16;

    enum RESULT {
        TRUE,
        FALSE,
        MISSING,
    };

    //#if !defined TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS
    // This is the basic logging and debug interface offered by the blockchain.
    // a release build with logging disabled (which is the default) will
    // not have this class at all
    struct TORRENT_EXTRA_EXPORT blockchain_logger {
        //#ifndef TORRENT_DISABLE_LOGGING
        virtual bool should_log() const = 0;
        virtual void log(char const* fmt, ...) const TORRENT_FORMAT(2,3) = 0;
        //#endif
            protected:
                ~blockchain_logger() {}
    };
    //#endif // TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS

    class TORRENT_EXPORT blockchain final:
            public std::enable_shared_from_this<blockchain>, blockchain_logger  {
    public:
        blockchain(io_context& mIoc, aux::session_interface &mSes) :
        m_ioc(mIoc), m_ses(mSes), m_refresh_timer(mIoc), m_vote_timer(mIoc) {
            m_repository = std::make_shared<repository_impl>(m_ses.sqldb(), m_ses.kvdb());
        }
        // start blockchain
        bool start();

        // stop
        bool stop();

        bool follow_chain(const aux::bytes &chain_id);

        bool load_chain(const aux::bytes &chain_id);

    private:
        // initialize member variables
        bool init();

        // clear all cache
        void clear();

        std::shared_ptr<blockchain> self()
        { return shared_from_this(); }

        //#ifndef TORRENT_DISABLE_LOGGING
        bool should_log() const override;
        void log(char const* fmt, ...) const noexcept override TORRENT_FORMAT(2,3);
        //#endif

        void refresh_timeout(error_code const& e);

        void refresh_vote_timeout(error_code const& e);

        void try_to_refresh_unchoked_peers(const aux::bytes &chain_id);

        // select a chain randomly
        aux::bytes select_chain_randomly();

        // select a peer randomly
        dht::public_key select_peer_randomly(const aux::bytes &chain_id);

        // select a peer randomly
        std::set<dht::public_key> select_unchoked_peers(const aux::bytes &chain_id);

        block try_to_mine_block(const aux::bytes &chain_id);

        void try_to_update_consensus_point_block(const aux::bytes &chain_id);

        RESULT verify_block(const aux::bytes &chain_id, block &b, block &previous_block, repository *repo);

        RESULT process_block(const aux::bytes &chain_id, block &b);

        bool is_consensus_point_immutable(const aux::bytes &chain_id);

        RESULT try_to_rebranch(const aux::bytes &chain_id, block &target);

        void seek_tail(const aux::bytes &chain_id);

        void refresh_vote(const aux::bytes &chain_id);

        // make a salt on mutable channel
        static std::string make_salt(const aux::bytes &chain_id);

        // request signal from a given peer
        void request_signal(const aux::bytes &chain_id, const dht::public_key& peer);

        // publish online/new message signal to a given peer
        void publish_signal(const aux::bytes &chain_id);

        // immutable data callback
        void get_immutable_callback(aux::bytes const& peer, sha256_hash target, dht::item const& i);

        // mutable data callback
        void get_mutable_callback(dht::item const& i, bool);

        // get immutable item from dht
        void dht_get_immutable_item(aux::bytes const& peer, sha256_hash const& target, std::vector<dht::node_entry> const& eps);

        // get mutable item from dht
        void dht_get_mutable_item(std::array<char, 32> key
                                  , std::string salt = std::string());

        // put immutable item to dht
        void dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target);

        // put mutable item to dht
        void dht_put_mutable_item(std::array<char, 32> key
                                  , std::function<void(entry&, std::array<char,64>&
                                          , std::int64_t&, std::string const&)> cb
                                          , std::string salt = std::string());

        // io context
        io_context& m_ioc;

        // session interface
        aux::session_interface& m_ses;

        // refresh time interval
        int m_refresh_time = blockchain_default_refresh_time;

        // deadline timer
        aux::deadline_timer m_refresh_timer;

        // vote timer
        aux::deadline_timer m_vote_timer;

        // blockchain db
        std::shared_ptr<repository> m_repository;

        bool m_stop = false;

        // all chains
        std::vector<aux::bytes> m_chains;

        // tx pool
        std::map<aux::bytes, tx_pool> m_tx_pools;

        // all chain peers
        std::map<aux::bytes, std::set<dht::public_key>> m_chain_peers;

        // un-choked peers
        std::map<aux::bytes, std::set<dht::public_key>> m_unchoked_peers;

        // update un-choked peers time
        std::map<aux::bytes, std::int64_t> m_update_peer_time;

        // block cache
        std::map<aux::bytes, std::map<sha256_hash, block>> m_blocks;

        // best tip blocks
        std::map<aux::bytes, block> m_best_tip_blocks;

        // best tail blocks
        std::map<aux::bytes, block> m_best_tail_blocks;

        // consensus point blocks
        std::map<aux::bytes, block> m_consensus_point_blocks;

        // current best votes
        std::map<aux::bytes, vote> m_best_votes;

        // votes
        std::map<aux::bytes, std::map<dht::public_key, vote>> m_votes;

        // current best votes
        std::map<aux::bytes, bool> m_sync_completed;

        // blockchain signal time(map:key1->chain id, key2->peer, value->signal time(ms))(1min)
        std::map<aux::bytes, std::map<aux::bytes, std::int64_t>> m_latest_signal_time;

        // blockchain hash prefix array(map:key1->chain id, key2->peer, value->hash prefix array)
        std::map<aux::bytes, std::map<aux::bytes, aux::bytes>> m_latest_hash_prefix_array;

    };
}


#endif //LIBTAU_BLOCKCHAIN_HPP
