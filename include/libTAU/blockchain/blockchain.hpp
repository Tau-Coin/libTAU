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
#include "libTAU/blockchain/constants.hpp"
#include "libTAU/blockchain/pool_hash_set.hpp"
#include "libTAU/blockchain/state_hash_array.hpp"
#include "libTAU/blockchain/peer_info.hpp"
#include "libTAU/blockchain/repository.hpp"
#include "libTAU/blockchain/repository_impl.hpp"
#include "libTAU/blockchain/repository_track.hpp"
#include "libTAU/blockchain/state_array.hpp"
#include "libTAU/blockchain/tx_pool.hpp"
#include "libTAU/common/entry_type.hpp"

namespace libTAU {
namespace blockchain {

    using system_clock = std::chrono::system_clock;

    // default refresh time of main task(2000)(ms)
    constexpr int blockchain_default_refresh_time = 2000;

    // max tx list size
    constexpr int blockchain_max_tx_list_size = 10;

    // chain status reset interval(s)
    constexpr int blockchain_status_reset_interval = 60 * 60;

    // min response interval to the same request(2s)
//    constexpr int blockchain_same_response_interval = 2 * 1000;

    // blockchain request timeout(2500ms)
    constexpr std::int64_t blockchain_request_timeout = 2 * 1000 + 500;

    // blockchain min peers in acl
    constexpr std::int64_t blockchain_acl_min_peers = 2;

    // blockchain max peers in acl
    constexpr std::int64_t blockchain_acl_max_peers = 16;

    // blockchain min ban time(5min)
    constexpr std::int64_t blockchain_min_ban_time = 5 * 60 * 1000;

    // blockchain max ban time(30min)
    constexpr std::int64_t blockchain_max_ban_time = 30 * 60 * 1000;

    // pool key suffix
    const std::string key_suffix_pool_root = "pool_root";
    // time pool key suffix
//    const std::string key_suffix_time_pool_root = "time_pool_root";
    // head block key suffix
    const std::string key_suffix_head_block_hash = "head_block_hash";
    // state root key suffix
    const std::string key_suffix_state_root = "state_root";

    enum GET_ITEM_TYPE {
        HEAD_BLOCK_HASH,
        HEAD_BLOCK,
        BLOCK,
        TX,
        POOL_HASH_SET,
        STATE_HASH_ARRAY,
        STATE_ARRAY,
    };

    enum RESULT {
        SUCCESS,
        FAIL,
        MISSING,
        NO_FORK_POINT,
    };

    enum CHAIN_STATUS {
        GET_GOSSIP_PEERS,
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
        bool createNewCommunity(const aux::bytes &chain_id, const std::set<account>& accounts);

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
        bool is_transaction_in_fee_pool(const aux::bytes &chain_id, const sha1_hash &txid);

        // get account by public key
        account getAccountInfo(const aux::bytes &chain_id, dht::public_key publicKey);

        // get main chain block by number
        block getBlock(const aux::bytes &chain_id, std::int64_t block_number);

        // get main chain block by hash
        block getBlock(const aux::bytes &chain_id, sha1_hash block_hash);

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
//        std::set<dht::public_key> get_gossip_peers(const aux::bytes &chain_id);

        // set blockchain main loop time interval (ms)
//        void set_blockchain_loop_interval(int milliseconds);

        // mutable data is pushed here
        void on_dht_relay(dht::public_key const& peer, entry const& payload);

//        void request_state(const aux::bytes &chain_id);

        // reset when account changed
        void account_changed();

        void on_pause();

        void on_resume();


    private:
        // initialize member variables
        bool init();

        // get current time(ms)
        static std::int64_t get_total_milliseconds();

        // get current time(us)
        static std::int64_t get_total_microseconds();

        // create and follow tau chain
//        bool create_TAU_chain();

        // clear all cache
        void clear_all_cache();

        // clear chain cache
        void clear_chain_cache(const aux::bytes &chain_id);

//        void try_to_clear_outdated_data_in_db(const aux::bytes &chain_id);

        std::shared_ptr<blockchain> self()
        { return shared_from_this(); }

        //#ifndef TORRENT_DISABLE_LOGGING
        bool should_log(aux::LOG_LEVEL log_level) const override;
        void log(aux::LOG_LEVEL log_level, char const* fmt, ...) const noexcept override TORRENT_FORMAT(3,4);
        //#endif

        void refresh_timeout(error_code const& e);

//        void refresh_chain_status(error_code const &e, const aux::bytes &chain_id);

        void refresh_mining_timeout(error_code const&, const aux::bytes &chain_id);

        void peer_preparation(const aux::bytes &chain_id);

        // load chain all info
//        bool load_chain(const aux::bytes &chain_id);

        // start chain
        bool start_chain(const aux::bytes &chain_id);

        // reset chain status
        void reset_chain_status(const aux::bytes &chain_id);

        void manage_peers_in_acl_ban_list(const aux::bytes &chain_id);

        void add_and_access_peers_in_acl(const aux::bytes &chain_id);

        // select a peer randomly
        dht::public_key select_peer_randomly(const aux::bytes &chain_id);

        // try to mine block
//        block try_to_mine_block(const aux::bytes &chain_id);

        // verify block
        RESULT verify_block(const aux::bytes &chain_id, const block &b, const block &previous_block, repository *repo);

        // process block
        RESULT process_genesis_block(const aux::bytes &chain_id, const block &blk);

        // process block
        RESULT process_block(const aux::bytes &chain_id, const block &blk);

        void block_reception_event(const aux::bytes &chain_id, const block &blk);

        // check if a chain is empty, true if has no info, false otherwise
        bool is_empty_chain(const aux::bytes &chain_id);

        // check if tx is in pool
        bool is_transaction_in_pool(const aux::bytes &chain_id, const sha1_hash &txid);

        // check if a block immutable certainly
//        bool is_block_immutable_certainly(const aux::bytes &chain_id, const block &blk);

        bool clear_all_chain_data_in_db(const aux::bytes &chain_id);

        // check if current chain sync completed
        bool clear_chain_all_state_in_cache_and_db(const aux::bytes &chain_id);

        // check if a block in cache or db
//        bool is_block_in_cache_or_db(const aux::bytes &chain_id, const sha256_hash &hash);

        void try_to_kick_out_of_ban_list(const aux::bytes &chain_id, const dht::public_key& peer);

//        void ban_peer(const aux::bytes &chain_id, const dht::public_key& peer);

//        void ban_peer_max_time(const aux::bytes &chain_id, const dht::public_key& peer);

//        void add_if_peer_not_in_acl(const aux::bytes &chain_id, const dht::public_key& peer);

//        void increase_peer_score(const aux::bytes &chain_id, const dht::public_key& peer, int score);

//        void decrease_peer_score(const aux::bytes &chain_id, const dht::public_key& peer, int score);

        // get block from block cache or db
        block get_block_from_cache_or_db(const aux::bytes &chain_id, const sha1_hash &hash);

        // remove all relevant blocks those on the same chain from cache
        void remove_all_same_chain_blocks_from_cache(const block &blk);

        // remove all relevant blocks those on the same chain from cache
        void remove_all_ancestor_blocks_from_cache(const block &blk);

//        void try_to_rebranch_to_best_vote(const aux::bytes &chain_id);

        void try_to_rebranch_to_most_difficult_chain(const aux::bytes &chain_id);

        // try to rebranch the most difficult chain, or a voting chain
        RESULT try_to_rebranch(const aux::bytes &chain_id, const block &target, bool absolute, dht::public_key peer = dht::public_key());

        // count votes
//        void count_votes(const aux::bytes &chain_id);

        // 使用LevenshteinDistance算法寻找最佳匹配，并提取相应解需要的中间信息(missing tx)
        void find_best_solution(std::vector<transaction>& txs, const aux::bytes& hash_prefix_array,
                                std::set<transaction> &missing_txs);

        void trim_state(const aux::bytes &chain_id);

        sha1_hash calculate_state_root(const aux::bytes &chain_id);

        // make a salt on mutable channel
//        static std::string make_salt(const aux::bytes &chain_id, std::int64_t data_type_id);

        // make a salt on mutable channel
        static std::string make_salt(const sha1_hash &hash);

        void publish(const std::string& salt, const entry& data);

        // key length < 20 bytes
        void subscribe(aux::bytes const& chain_id, const dht::public_key &peer, const std::string& salt, GET_ITEM_TYPE type);

        // make a salt on mutable channel
//        static std::string make_salt(dht::public_key peer, std::int64_t data_type_id);

        // send data to peer
        void send_to(const dht::public_key &peer, entry const& data);

        void transfer_to_acl_peers(const aux::bytes &chain_id, entry const& data,
                                   const dht::public_key &incoming_peer = dht::public_key());

        void transfer_head_block(const aux::bytes &chain_id, const block& blk);

        void transfer_transaction(const aux::bytes &chain_id, const transaction& tx);

//        void introduce_gossip_peers(const aux::bytes &chain_id, const dht::public_key &peer);

//        void introduce_peers(const aux::bytes &chain_id, const dht::public_key &peer, const std::set<dht::public_key>& peers);

//        void put_gossip_peers_to_cache(const aux::bytes &chain_id);

//        void add_gossip_peers(const aux::bytes &chain_id, const std::set<dht::public_key>& peers);

        // request signal from a given peer
//        void get_gossip_peers(const aux::bytes &chain_id, const dht::public_key& peer);

        // request signal from a given peer
//        void get_voting_block(const aux::bytes &chain_id, const dht::public_key& peer);

//        void put_voting_block(const aux::bytes &chain_id, const block &blk);

        void send_online_signal(const aux::bytes &chain_id);

        void send_new_head_block_signal(const aux::bytes &chain_id);

        void send_new_tx_signal(const aux::bytes &chain_id);

        void get_head_block_from_peer(const aux::bytes &chain_id, const dht::public_key& peer);

        void put_head_block(const aux::bytes &chain_id, const block &blk);

        void get_pool_from_peer(const aux::bytes &chain_id, const dht::public_key& peer);

        void put_new_transaction(const aux::bytes &chain_id, const transaction &tx);

        void get_all_state_from_peer(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash);

        void put_all_state(const aux::bytes &chain_id);

        void get_head_block_hash(const aux::bytes &chain_id, const dht::public_key& peer);

        void put_head_block_hash(const aux::bytes &chain_id, const sha1_hash &hash);

//        void get_pool_root(const aux::bytes &chain_id, const dht::public_key& peer);

//        void put_pool_root(const aux::bytes &chain_id, const sha1_hash &hash);

//        void get_time_pool_root(const aux::bytes &chain_id, const dht::public_key& peer);
//
//        void put_time_pool_root(const aux::bytes &chain_id, const sha1_hash &hash);

        void get_block(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash);

        void put_block(const aux::bytes &chain_id, const block &blk);

        void get_transaction(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash);

        void put_transaction(const aux::bytes &chain_id, const transaction &tx);

        void get_state_array(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash);

        void put_state_array(const aux::bytes &chain_id, const state_array &stateArray);

        void get_pool_hash_set(const aux::bytes &chain_id, const dht::public_key& peer);

        void put_pool_hash_set(const aux::bytes &chain_id);

        void get_state_hash_array(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash);

        void put_state_hash_array(const aux::bytes &chain_id, const state_hash_array &hashArray);

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
        void get_mutable_callback(aux::bytes const& chain_id, dht::item const& i, bool, GET_ITEM_TYPE type);

        // get mutable item from dht
//        void dht_get_mutable_item(aux::bytes const& chain_id, std::array<char, 32> key, std::string salt);

        void on_dht_put_mutable_item(const dht::item &i, int n);

        void on_dht_relay_mutable_item(entry const& payload, std::vector<std::pair<dht::node_entry, bool>> const& nodes, dht::public_key const& peer);

        // put immutable item to dht
//        void dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target);

        // put mutable item to dht
//        void dht_put_mutable_item(std::array<char, 32> key
//                                  , std::function<void(entry&, std::array<char,64>&
//                                          , std::int64_t&, std::string const&)> cb,
//                                          std::int8_t alpha, std::int8_t beta, std::int8_t invoke_limit
//                                          , std::string salt, const dht::public_key &peer, bool cache);

        void print_acl_ban_list_info(aux::bytes const& chain_id);

        void data_received_from_peer(aux::bytes const& chain_id, const dht::public_key& peer, std::int64_t timestamp);

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

        bool m_pause = false;

        // chain timers
        std::map<aux::bytes, aux::deadline_timer> m_chain_timers;

        // chain status timers
//        std::map<aux::bytes, aux::deadline_timer> m_chain_status_timers;

        // blockchain db
        std::shared_ptr<repository> m_repository;

        // tx pool
        std::map<aux::bytes, tx_pool> m_tx_pools;

        // chain status
        bool m_stop = false;

        // all chains
        std::vector<aux::bytes> m_chains;

        // short chain id table<short chain id, chain id>
        std::map<aux::bytes, aux::bytes> m_short_chain_id_table;

        std::map<aux::bytes, CHAIN_STATUS> m_chain_status;

        // Forwarding list
        std::map<aux::bytes, std::map<dht::public_key, peer_info>> m_access_list;

        std::map<aux::bytes, std::map<dht::public_key, ban_info>> m_ban_list;

        // last get time(chain id <--> (peer <--> (salt <-->last get time)))
        std::map<aux::bytes, std::map<dht::public_key, std::map<std::string, std::int64_t>>> m_last_get_time;

        // head blocks
        std::map<aux::bytes, block> m_head_blocks;
    };
}
}


#endif //LIBTAU_BLOCKCHAIN_HPP
