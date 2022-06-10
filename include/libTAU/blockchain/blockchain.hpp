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
#include <queue>

#include "libTAU/time.hpp"
#include "libTAU/aux_/alert_manager.hpp" // for alert_manager
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/deadline_timer.hpp"
#include "libTAU/aux_/session_interface.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/kademlia/node_entry.hpp"
#include "libTAU/blockchain/blockchain_signal.hpp"
#include "libTAU/blockchain/constants.hpp"
#include "libTAU/blockchain/peer_info.hpp"
#include "libTAU/blockchain/repository.hpp"
#include "libTAU/blockchain/repository_impl.hpp"
#include "libTAU/blockchain/repository_track.hpp"
#include "libTAU/blockchain/tx_pool.hpp"
#include "libTAU/common/entry_type.hpp"

namespace libTAU {
namespace blockchain {

    using system_clock = std::chrono::system_clock;

    // default refresh time of main task(2000)(ms)
    constexpr int blockchain_default_refresh_time = 2000;

    // max task size
    constexpr int blockchain_max_task_size = 10000;

    // max access peer frequency(interval: 3000 ms)
    constexpr int blockchain_max_access_peer_interval = 3000;

    // max tx list size
    constexpr int blockchain_max_tx_list_size = 10;

    constexpr int blockchain_immutable_payload_put_node_size = 1;

    // vote interval(s)
    constexpr int blockchain_vote_interval = 60 * 60;

    // min response interval to the same request(ms)
    constexpr int blockchain_same_response_interval = 4 * 1000;

    // blockchain max focus time(5ms)
    constexpr std::int64_t blockchain_max_focus_time = 5 * 1000;

    // blockchain request timeout(1s)
    constexpr std::int64_t blockchain_request_timeout = 1000;

    // blockchain min peers in acl
    constexpr std::int64_t blockchain_acl_min_peers = 3;

    // blockchain max peers in acl
    constexpr std::int64_t blockchain_acl_max_peers = 5;

    // blockchain min ban time(5min)
    constexpr std::int64_t blockchain_min_ban_time = 5 * 60 * 1000;

    // blockchain max ban time(30min)
    constexpr std::int64_t blockchain_max_ban_time = 30 * 60 * 1000;

    enum RESULT {
        SUCCESS,
        FAIL,
        MISSING,
        NO_FORK_POINT,
    };

    enum CHAIN_STATUS {
        GET_GOSSIP_PEERS,
        COLLECT_GOSSIP_PEERS,
        VOTE,
        COUNT_VOTES,
        MINE,
    };

    //#if !defined TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS
    // This is the basic logging and debug interface offered by the blockchain.
    // a release build with logging disabled (which is the default) will
    // not have this class at all
    struct TORRENT_EXTRA_EXPORT blockchain_logger {
        //#ifndef TORRENT_DISABLE_LOGGING
        virtual bool should_log(aux::LOG_LEVEL log_level) const = 0;
        virtual void log(aux::LOG_LEVEL log_level, char const* fmt, ...) const TORRENT_FORMAT(3,4) = 0;
        //#endif
            protected:
                ~blockchain_logger() {}
    };
    //#endif // TORRENT_DISABLE_LOGGING || TORRENT_USE_ASSERTS

    class TORRENT_EXPORT blockchain final:
            public std::enable_shared_from_this<blockchain>, blockchain_logger  {
    public:
        blockchain(io_context& mIoc, aux::session_interface &mSes, counters &mCounters) :
        m_ioc(mIoc), m_ses(mSes), m_counters(mCounters), m_refresh_timer(mIoc) {
            m_repository = std::make_shared<repository_impl>(m_ses.sqldb(), m_ses.kvdb());
        }
        // start blockchain
        bool start();

        // stop
        bool stop();

        // create chain id
        aux::bytes create_chain_id(std::string community_name);

        // create new community with tx
        bool createNewCommunity(const aux::bytes &chain_id, const std::map<dht::public_key, account>& accounts);

        std::set<aux::bytes> get_all_chains();

        // follow a chain by chain id and peers
        bool followChain(const aux::bytes &chain_id, const std::set<dht::public_key>& peers);

        // add new bootstrap peers
        bool add_new_bootstrap_peers(const aux::bytes &chain_id, const std::set<dht::public_key>& peers);

        // un-follow a chain
        bool unfollowChain(const aux::bytes &chain_id);

        // send new transaction
        bool submitTransaction(const transaction& tx);

        // check if tx is in pool
        bool is_transaction_in_fee_pool(const aux::bytes &chain_id, const sha256_hash& txid);

        // get account by public key
        account getAccountInfo(const aux::bytes &chain_id, dht::public_key publicKey);

        // get main chain block by number
        block getBlock(const aux::bytes &chain_id, std::int64_t block_number);

        // get main chain block by hash
        block getBlock(const aux::bytes &chain_id, sha256_hash block_hash);

        // get top tip blocks
        std::vector<block> getTopTipBlocks(const aux::bytes &chain_id, int topNum);

        // get median tx fee
        std::int64_t getMedianTxFee(const aux::bytes &chain_id);

        // return mining time: -1: cannot mine block
        std::int64_t getMiningTime(const aux::bytes &chain_id);

        // return access list
        std::set<dht::public_key> get_access_list(const aux::bytes &chain_id);

        // return ban list
        std::set<dht::public_key> get_ban_list(const aux::bytes &chain_id);

        // return access list
        std::set<dht::public_key> get_gossip_peers(const aux::bytes &chain_id);

        // set blockchain main loop time interval (ms)
//        void set_blockchain_loop_interval(int milliseconds);

//        void set_priority_chain(const aux::bytes &chain_id);

//        void unset_priority_chain();

        // mutable data is pushed here
        void on_dht_relay(dht::public_key const& peer, entry const& payload);

        void request_state(const aux::bytes &chain_id);

        // reset when account changed
        void account_changed();


    private:
        // initialize member variables
        bool init();

        // get current time(ms)
        static std::int64_t get_total_milliseconds();

        // get current time(us)
        static std::int64_t get_total_microseconds();

        // create and follow tau chain
        bool create_TAU_chain();

        // clear all cache
        void clear_all_cache();

        // clear chain cache
        void clear_chain_cache(const aux::bytes &chain_id);

        void try_to_clear_outdated_data_in_db(const aux::bytes &chain_id);

        std::shared_ptr<blockchain> self()
        { return shared_from_this(); }

        //#ifndef TORRENT_DISABLE_LOGGING
        bool should_log(aux::LOG_LEVEL log_level) const override;
        void log(aux::LOG_LEVEL log_level, char const* fmt, ...) const noexcept override TORRENT_FORMAT(3,4);
        //#endif

        void refresh_timeout(error_code const& e);

        void refresh_chain_status(error_code const &e, const aux::bytes &chain_id);

//        void refresh_votes(error_code const &e, const aux::bytes &chain_id);

        void refresh_mining_timeout(error_code const&, const aux::bytes &chain_id);

//        void refresh_vote_timeout(error_code const& e);

//        void refresh_tx_timeout(error_code const& e);

//        void add_entry_task_to_queue(const aux::bytes &chain_id, const common::blockchain_entry_task &task);


        // load chain all info
        bool load_chain(const aux::bytes &chain_id);

        // start chain
        bool start_chain(const aux::bytes &chain_id);

        // reset chain status
        void reset_chain_status(const aux::bytes &chain_id);

        void manage_peers_in_acl_ban_list(const aux::bytes &chain_id);

        void add_and_access_peers_in_acl(const aux::bytes &chain_id);

        // refresh unchoked peers if timeout
//        void try_to_refresh_unchoked_peers(const aux::bytes &chain_id);

        // select a chain randomly
        aux::bytes select_chain_randomly();

        // select a peer randomly
        dht::public_key select_peer_randomly(const aux::bytes &chain_id);

        // select an un-choked peer randomly
//        dht::public_key select_unchoked_peer_randomly(const aux::bytes &chain_id);

        // select a peer randomly
        std::set<dht::public_key> select_unchoked_peers(const aux::bytes &chain_id);

        // try to mine block
        block try_to_mine_block(const aux::bytes &chain_id);

        // try to update consensus point block if best voting block changed
//        void try_to_update_consensus_point_block(const aux::bytes &chain_id);

        // try to update voting point block if chain changed
        void try_to_update_voting_point_block(const aux::bytes &chain_id);

        // verify block
        RESULT verify_block(const aux::bytes &chain_id, const block &b, const block &previous_block, repository *repo);

        // process block
        RESULT process_block(const aux::bytes &chain_id, const block &blk);

        void block_reception_event(const aux::bytes &chain_id, const block &blk);

        // check if a chain is empty, true if has no info, false otherwise
        bool is_empty_chain(const aux::bytes &chain_id);

        // check if a block immutable certainly
        bool is_block_immutable_certainly(const aux::bytes &chain_id, const block &blk);

        // check if consensus point block immutable, true if it is same to voting block, false otherwise
//        bool is_voting_point_immutable(const aux::bytes &chain_id);

        // check if current chain sync completed
        bool is_sync_completed(const aux::bytes &chain_id);

        // check if current chain sync completed
        bool clear_chain_all_state_in_cache_and_db(const aux::bytes &chain_id);

        // check if a block in cache or db
        bool is_block_in_cache_or_db(const aux::bytes &chain_id, const sha256_hash &hash);

        bool is_peer_in_acl(const aux::bytes &chain_id, const dht::public_key& peer);

        bool is_peer_banned(const aux::bytes &chain_id, const dht::public_key& peer);

        void try_to_kick_out_of_ban_list(const aux::bytes &chain_id, const dht::public_key& peer);

//        void ban_peer(const aux::bytes &chain_id, const dht::public_key& peer);

//        void ban_peer_max_time(const aux::bytes &chain_id, const dht::public_key& peer);

//        void add_if_peer_not_in_acl(const aux::bytes &chain_id, const dht::public_key& peer);

//        void increase_peer_score(const aux::bytes &chain_id, const dht::public_key& peer, int score);

//        void decrease_peer_score(const aux::bytes &chain_id, const dht::public_key& peer, int score);

        // get block from block cache or db
        block get_block_from_cache_or_db(const aux::bytes &chain_id, const sha256_hash &hash);

        // remove all relevant blocks those on the same chain from cache
        void remove_all_same_chain_blocks_from_cache(const block &blk);

        // remove all relevant blocks those on the same chain from cache
        void remove_all_ancestor_blocks_from_cache(const block &blk);

        void try_to_rebranch_to_best_vote(const aux::bytes &chain_id);

        void try_to_rebranch_to_most_difficult_chain(const aux::bytes &chain_id);

        // try to rebranch the most difficult chain, or a voting chain
        RESULT try_to_rebranch(const aux::bytes &chain_id, const block &target, bool absolute, dht::public_key peer = dht::public_key());

        void try_to_sync_block(const aux::bytes &chain_id);

        // count votes
        void count_votes(const aux::bytes &chain_id);

        // 使用LevenshteinDistance算法寻找最佳匹配，并提取相应解需要的中间信息(missing tx)
        void find_best_solution(std::vector<transaction>& txs, const aux::bytes& hash_prefix_array,
                                std::set<transaction> &missing_txs);

        // make a salt on mutable channel
        static std::string make_salt(dht::public_key peer, const aux::bytes &chain_id, std::int64_t data_type_id);

        // make a salt on mutable channel
//        static std::string make_salt(dht::public_key peer, std::int64_t data_type_id);

        // send data to peer
        void send_to(const dht::public_key &peer, entry const& data);

        void request_block(const aux::bytes &chain_id, const sha256_hash& hash);

        void request_block(const aux::bytes &chain_id, const dht::public_key &peer, const sha256_hash& hash);

        void transfer_to_acl_peers(const aux::bytes &chain_id, entry const& data,
                                   const dht::public_key &incoming_peer = dht::public_key());

        void transfer_head_block(const aux::bytes &chain_id, const block& blk);

        void transfer_transaction(const aux::bytes &chain_id, const transaction& tx);

        void introduce_gossip_peers(const aux::bytes &chain_id, const dht::public_key &peer);

        void introduce_peers(const aux::bytes &chain_id, const dht::public_key &peer, const std::set<dht::public_key>& peers);

        void put_gossip_peers_to_cache(const aux::bytes &chain_id);

        void add_gossip_peers(const aux::bytes &chain_id, const std::set<dht::public_key>& peers);

        // request signal from a given peer
        void get_gossip_peers(const aux::bytes &chain_id, const dht::public_key& peer);

        // request signal from a given peer
        void get_voting_block(const aux::bytes &chain_id, const dht::public_key& peer);

        void put_voting_block(const aux::bytes &chain_id, const block &blk);

        // publish online/new message signal to a given peer
//        void publish_signal(const aux::bytes &chain_id, const dht::public_key& peer,
//                            const blockchain_signal &peer_signal = blockchain_signal());

        // process signal from dht
//        void process_signal(const blockchain_signal & signal, const aux::bytes &chain_id, const dht::public_key &peer);

        // immutable data callback
//        void get_immutable_block_callback(aux::bytes const& chain_id, sha256_hash target, dht::item const& i);

//        // get immutable item from dht
//        void dht_get_immutable_block_item(aux::bytes const& chain_id, sha256_hash const& target, std::vector<dht::node_entry> const& eps);
//
//        // immutable data callback
//        void get_immutable_tx_callback(aux::bytes const& chain_id, sha256_hash target, dht::item const& i);

        // get immutable item from dht
//        void dht_get_immutable_tx_item(aux::bytes const& chain_id, sha256_hash const& target, std::vector<dht::node_entry> const& eps);

        // mutable data callback
        void get_mutable_callback(aux::bytes const& chain_id, dht::item const& i, bool);

        // get mutable item from dht
        void dht_get_mutable_item(aux::bytes const& chain_id, std::array<char, 32> key, std::string salt);

        void on_dht_put_mutable_item(dht::item const& i, std::vector<std::pair<dht::node_entry, bool>> const& nodes, dht::public_key const& peer);

        void on_dht_relay_mutable_item(entry const& payload, std::vector<std::pair<dht::node_entry, bool>> const& nodes, dht::public_key const& peer);

        // put immutable item to dht
//        void dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target);

        // put mutable item to dht
        void dht_put_mutable_item(std::array<char, 32> key
                                  , std::function<void(entry&, std::array<char,64>&
                                          , std::int64_t&, std::string const&)> cb,
                                          std::int8_t alpha, std::int8_t beta, std::int8_t invoke_limit
                                          , std::string salt, const dht::public_key &peer, bool cache);

        void print_acl_ban_list_info(aux::bytes const& chain_id);

        void data_received_from_peer(aux::bytes const& chain_id, const dht::public_key& peer, int score);

        void data_received_from_peer(aux::bytes const& chain_id, const dht::public_key& peer, int score,
                                     const std::unique_ptr<common::blockchain_entry_base>& ptr);

        void head_block_received_from_peer(aux::bytes const& chain_id, const dht::public_key& peer, const block &blk);

        void transaction_received_from_peer(aux::bytes const& chain_id, const dht::public_key& peer, const transaction &tx);

        // @return true: response, false: not response
        bool request_received_from_peer(aux::bytes const& chain_id, const dht::public_key& peer,
                                        std::unique_ptr<common::blockchain_entry_base>& ptr);

        // io context
        io_context& m_ioc;

        // session interface
        aux::session_interface& m_ses;

        counters& m_counters;

        // refresh time interval
        int m_refresh_time = blockchain_default_refresh_time;

        // deadline timer
        aux::deadline_timer m_refresh_timer;

        // chain timers
        std::map<aux::bytes, aux::deadline_timer> m_chain_timers;

        // vote timer
//        aux::deadline_timer m_vote_timer;

        // chain status timers
        std::map<aux::bytes, aux::deadline_timer> m_chain_status_timers;

        // tx timer
//        aux::deadline_timer m_exchange_tx_timer;

        // blockchain db
        std::shared_ptr<repository> m_repository;

        // tx pool
        std::map<aux::bytes, tx_pool> m_tx_pools;

        // chain status
        bool m_stop = false;

        // all chains
        std::vector<aux::bytes> m_chains;

//        // all chain peers
//        std::map<aux::bytes, std::set<dht::public_key>> m_chain_peers;
//
//        // all chain gossip peers
//        std::map<aux::bytes, std::set<dht::public_key>> m_chain_gossip_peers;

//        // un-choked peers
//        std::map<aux::bytes, std::set<dht::public_key>> m_unchoked_peers;
//
//        // un-choked peers signal
//        std::map<aux::bytes, std::map<dht::public_key, blockchain_signal>> m_unchoked_peer_signal;
//
//        // update un-choked peers time(s)
//        std::map<aux::bytes, std::int64_t> m_update_peer_time;

        // the time that last cache gossip peers(ms)
        std::map<aux::bytes, std::int64_t> m_last_cache_gossip_peers_time;

        std::map<aux::bytes, CHAIN_STATUS> m_chain_status;

//        std::map<aux::bytes, std::int64_t> m_last_voting_time;

        std::map<aux::bytes, std::int64_t> m_count_votes_time;

        std::map<aux::bytes, std::int64_t> m_collect_gossip_peers_time;

//        std::map<aux::bytes, std::set<dht::public_key>> m_vote_request_peers;

        // all tasks
//        std::queue<common::blockchain_entry_task> m_tasks;
//        std::set<common::blockchain_entry_task> m_tasks_set;

        std::map<aux::bytes, std::set<dht::public_key>> m_gossip_peers;

//        std::map<aux::bytes, std::map<dht::public_key, std::int64_t>> m_last_visiting_time;

        std::map<aux::bytes, std::int64_t> m_last_balance_alert_time;

        std::map<aux::bytes, std::map<dht::public_key, peer_info>> m_access_list;

        std::map<aux::bytes, std::map<dht::public_key, ban_info>> m_ban_list;

        // block cache todo:100000?
//        std::map<aux::bytes, std::map<sha256_hash, block>> m_blocks;

        // head blocks
        std::map<aux::bytes, block> m_head_blocks;

        // tail blocks
        std::map<aux::bytes, block> m_tail_blocks;

        // consensus point blocks
        std::map<aux::bytes, block> m_consensus_point_blocks;

        // voting point blocks
        std::map<aux::bytes, block> m_voting_point_blocks;

        // current best votes
        std::map<aux::bytes, vote> m_best_votes;

        // votes
        std::map<aux::bytes, std::map<dht::public_key, vote>> m_votes;

        // priority chain(time:ms)
//        std::pair<aux::bytes , std::int64_t> m_priority_chain = std::make_pair(aux::bytes(), 0);

        // blockchain signal time(map:key1->chain id, key2->peer, value->signal time(ms))(1min)
//        std::map<aux::bytes, std::map<dht::public_key, std::int64_t>> m_latest_signal_time;

        // the latest item timestamp of peer
//        std::map<aux::bytes, std::map<dht::public_key, dht::timestamp>> m_latest_item_timestamp;

    };
}
}


#endif //LIBTAU_BLOCKCHAIN_HPP
