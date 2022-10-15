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
#include <utility>
#include <vector>
#include <queue>
#include <ostream>

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
#include "libTAU/blockchain/state_array.hpp"
#include "libTAU/blockchain/tx_pool.hpp"
#include "libTAU/blockchain/transaction_wrapper.hpp"
#include "libTAU/common/entry_type.hpp"

namespace libTAU {
namespace blockchain {

    using system_clock = std::chrono::system_clock;

    // default refresh time of main task(ms)
    constexpr int blockchain_min_refresh_time = 10;
    constexpr int blockchain_max_refresh_time = 3000;

    // max tx list size
    constexpr int blockchain_max_tx_list_size = 10;

    // chain status reset interval(s)
//    constexpr int blockchain_status_reset_interval = 60 * 60;

    // min response interval to the same request(2s)
//    constexpr int blockchain_same_response_interval = 2 * 1000;

    // blockchain min peers in acl
//    constexpr std::int64_t blockchain_acl_min_peers = 2;

    // blockchain max peers in acl
    constexpr std::size_t blockchain_acl_max_peers = 12;

    // blockchain max getting times
    constexpr std::int64_t blockchain_max_getting_times = 10;

    // blockchain last put time(5min)
    constexpr std::int64_t blockchain_min_put_interval = 5 * 60 * 1000;

    // blockchain min ban time(5min)
//    constexpr std::int64_t blockchain_min_ban_time = 5 * 60 * 1000;

    // blockchain max ban time(30min)
//    constexpr std::int64_t blockchain_max_ban_time = 30 * 60 * 1000;

    // note pool root key suffix
    const std::string key_suffix_note_pool_root = "note_pool_root";
    // transfer tx key suffix
    const std::string key_suffix_transfer_tx = "transfer_tx";
    // head block key suffix
    const std::string key_suffix_head_block_hash = "head_block_hash";
    // state root key suffix
    const std::string key_suffix_state_root = "state_root";

    enum GET_ITEM_TYPE {
        HEAD_BLOCK_HASH,
        HEAD_BLOCK,
        BLOCK,
//        TX_WRAPPER,
        NOTE_POOL_ROOT,
        NOTE_POOL_HASH_SET,
        NOTE_TX,
        TRANSFER_TX,
        STATE_HASH_ARRAY,
        STATE_ARRAY,
        UNKNOWN_GET_ITEM_TYPE,
    };

    enum RESULT {
        SUCCESS,
        FAIL,
        MISSING,
        NO_FORK_POINT,
    };

    enum dht_item_type {
        DHT_SEND,
        DHT_PUT,
        DHT_PUT_TX,
        DHT_GET,
        DHT_UNKNOWN,
    };

    struct dht_item {
        // send
        dht_item(const dht::public_key &mPeer, entry mData) : m_peer(mPeer), m_data(std::move(mData)) {
            m_type = dht_item_type::DHT_SEND;
        }

        // put
        dht_item(std::string mSalt, entry mData) : m_salt(std::move(mSalt)), m_data(std::move(mData)) {
            m_type = dht_item_type::DHT_PUT;
        }

        // put tx
        dht_item(aux::bytes mChainId, const sha1_hash &mHash, std::string mSalt, entry mData)
                : m_chain_id(std::move(mChainId)), m_hash(mHash), m_salt(std::move(mSalt)), m_data(std::move(mData)) {
            m_type = dht_item_type::DHT_PUT_TX;
        }

        // get
        dht_item(aux::bytes mChainId, const dht::public_key &mPeer, std::string mSalt,
                 GET_ITEM_TYPE mGetItemType, int64_t mTimestamp, int mTimes) : m_chain_id(std::move(mChainId)), m_peer(mPeer),
                                                                               m_salt(std::move(mSalt)),
                                                                               m_get_item_type(mGetItemType),
                                                                               m_timestamp(mTimestamp),
                                                                               m_times(mTimes) {
            m_type = dht_item_type::DHT_GET;
        }

        bool operator<(const dht_item &rhs) const {
            if (m_type < rhs.m_type)
                return true;
            if (rhs.m_type < m_type)
                return false;
            if (m_chain_id < rhs.m_chain_id)
                return true;
            if (rhs.m_chain_id < m_chain_id)
                return false;
            if (m_peer < rhs.m_peer)
                return true;
            if (rhs.m_peer < m_peer)
                return false;
            if (m_hash < rhs.m_hash)
                return true;
            if (rhs.m_hash < m_hash)
                return false;
            if (m_salt < rhs.m_salt)
                return true;
            if (rhs.m_salt < m_salt)
                return false;
            std::string encode;
            bencode(std::back_inserter(encode), m_data);
            std::string rhs_encode;
            bencode(std::back_inserter(rhs_encode), rhs.m_data);
            if (encode < rhs_encode)
                return true;
            if (encode > rhs_encode)
                return false;
//                if (m_data < rhs.m_data)
//                    return true;
//                if (rhs.m_data < m_data)
//                    return false;
            if (m_get_item_type < rhs.m_get_item_type)
                return true;
            if (rhs.m_get_item_type < m_get_item_type)
                return false;
            if (m_timestamp < rhs.m_timestamp)
                return true;
            if (rhs.m_timestamp < m_timestamp)
                return false;
            return m_times < rhs.m_times;
        }

        bool operator>(const dht_item &rhs) const {
            return rhs < *this;
        }

        bool operator<=(const dht_item &rhs) const {
            return !(rhs < *this);
        }

        bool operator>=(const dht_item &rhs) const {
            return !(*this < rhs);
        }

        std::string to_string() const {
            std::ostringstream os;
            os << *this;
            return os.str();
        }

        friend std::ostream &operator<<(std::ostream &os, const dht_item &item) {
            switch (item.m_type) {
                case dht_item_type::DHT_GET: {
                    os << "dht get: " << " m_chain_id: " << aux::toHex(item.m_chain_id)
                       << " m_peer: " << aux::toHex(item.m_peer.bytes) << " m_salt: " << aux::toHex(item.m_salt)
                       << " m_get_item_type: " << item.m_get_item_type << " m_timestamp: " << item.m_timestamp
                       << " m_times: " << item.m_times;

                    break;
                }
                case dht_item_type::DHT_PUT: {
                    os << "dht put: " << " m_salt: " << aux::toHex(item.m_salt)
                       << " m_data: " << item.m_data.to_string(true);

                    break;
                }
                case dht_item_type::DHT_PUT_TX: {
                    os << "dht put tx: " << " m_chain_id: " << aux::toHex(item.m_chain_id)
                       << " m_hash: " << aux::toHex(item.m_hash.to_string())
                       << " m_salt: " << aux::toHex(item.m_salt)
                       << " m_data: " << item.m_data.to_string(true);

                    break;
                }
                case dht_item_type::DHT_SEND: {
                    os << "dht send: " << " m_peer: " << aux::toHex(item.m_peer.bytes)
                       << " m_data: " << item.m_data.to_string(true);

                    break;
                }
                default: {
                    os << "unknown type: " << item.m_type;
                }
            }

            return os;
        }

        dht_item_type m_type = DHT_UNKNOWN;
        aux::bytes m_chain_id;
        dht::public_key m_peer;
        sha1_hash m_hash;
        std::string m_salt;
        entry m_data;
        GET_ITEM_TYPE m_get_item_type = UNKNOWN_GET_ITEM_TYPE;
        std::int64_t m_timestamp{};
        int m_times{};
    };

    struct GET_ITEM {
        GET_ITEM(aux::bytes mChainId, const dht::public_key &mPeer, std::string mSalt, GET_ITEM_TYPE mType) :
                m_chain_id(std::move(mChainId)), m_peer(mPeer), m_salt(std::move(mSalt)), m_type(mType) {}

        bool operator<(const GET_ITEM &rhs) const {
            if (m_chain_id < rhs.m_chain_id)
                return true;
            if (rhs.m_chain_id < m_chain_id)
                return false;
            if (m_peer < rhs.m_peer)
                return true;
            if (rhs.m_peer < m_peer)
                return false;
            if (m_salt < rhs.m_salt)
                return true;
            if (rhs.m_salt < m_salt)
                return false;
            return m_type < rhs.m_type;
        }

        bool operator>(const GET_ITEM &rhs) const {
            return rhs < *this;
        }

        bool operator<=(const GET_ITEM &rhs) const {
            return !(rhs < *this);
        }

        bool operator>=(const GET_ITEM &rhs) const {
            return !(*this < rhs);
        }

        aux::bytes m_chain_id;
        dht::public_key m_peer;
        std::string m_salt;
        GET_ITEM_TYPE m_type;
    };

    struct GET_INFO {
        GET_INFO() = default;

        void increase_get_times() { m_times++; }

        int m_times = 1;
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
        m_ioc(mIoc), m_ses(mSes), m_counters(mCounters), m_refresh_timer(mIoc), m_dht_tasks_timer(mIoc) {
            m_repository = std::make_shared<repository_impl>(m_ses.sqldb());
        }

        // start blockchain
        bool start();

        // stop
        bool stop();

        // create chain id
        aux::bytes create_chain_id(aux::bytes type, std::string community_name);

        // create new community with tx
        bool createNewCommunity(const aux::bytes &chain_id, const std::set<account>& accounts);

        std::set<aux::bytes> get_all_chains();

        // follow a chain by chain id and peers
        bool followChain(const aux::bytes &chain_id, const std::set<dht::public_key>& peers);

        // connect chain
        bool connect_chain(const aux::bytes &chain_id);

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

        void request_chain_all_data(const aux::bytes &chain_id, const dht::public_key& peer);

        void put_chain_all_data(const aux::bytes &chain_id);

        void put_chain_all_state(const aux::bytes &chain_id);

        void put_chain_all_blocks(const aux::bytes &chain_id);

        void request_all_state(const aux::bytes &chain_id, const dht::public_key& peer);

        void request_all_blocks(const aux::bytes &chain_id, const dht::public_key& peer);

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

        // init chain
        bool init_chain(const aux::bytes &chain_id);

        bool create_chain_db(const aux::bytes &chain_id);

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

        void refresh_dht_task_timer(error_code const& e);

//        void refresh_chain_status(error_code const &e, const aux::bytes &chain_id);

        void refresh_mining_timeout(error_code const&, const aux::bytes &chain_id);

        void peer_preparation(const aux::bytes &chain_id);

        // load chain all info
//        bool load_chain(const aux::bytes &chain_id);

        // reset chain status
//        void reset_chain_status(const aux::bytes &chain_id);

//        void try_to_get_again();

//        void manage_peers_in_acl_ban_list(const aux::bytes &chain_id);

//        void add_and_access_peers_in_acl(const aux::bytes &chain_id);

        // verify block
        RESULT verify_block(const aux::bytes &chain_id, const block &b, const block &previous_block);

        // process block
        RESULT process_genesis_block(const aux::bytes &chain_id, const block &blk, const std::vector<state_array> &arrays);

        // process block
        RESULT process_block(const aux::bytes &chain_id, const block &blk);

        void block_reception_event(const aux::bytes &chain_id, const dht::public_key& peer, const block &blk);

        void state_reception_event(const aux::bytes &chain_id, const dht::public_key& peer);

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

//        void try_to_kick_out_of_ban_list(const aux::bytes &chain_id, const dht::public_key& peer);

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

        void try_to_rebranch_to_most_difficult_chain(const aux::bytes &chain_id, const dht::public_key& peer);

        // try to rebranch the most difficult chain, or a voting chain
        RESULT try_to_rebranch(const aux::bytes &chain_id, const block &target, bool absolute, dht::public_key peer = dht::public_key());

        // count votes
//        void count_votes(const aux::bytes &chain_id);

        // 使用LevenshteinDistance算法寻找最佳匹配，并提取相应解需要的中间信息(missing tx)
        void find_best_solution(std::vector<transaction>& txs, const aux::bytes& hash_prefix_array,
                                std::set<transaction> &missing_txs);

        void get_genesis_state(const aux::bytes &chain_id, sha1_hash &stateRoot, std::vector<state_array> &arrays);

        // make a salt on mutable channel
//        static std::string make_salt(const aux::bytes &chain_id, std::int64_t data_type_id);

        // make a salt on mutable channel
        static std::string make_salt(const sha1_hash &hash);

        void publish(const std::string& salt, const entry& data);

        void publish_transaction(const aux::bytes &chain_id, const sha1_hash &hash, const std::string& salt, const entry& data);

        // key length < 20 bytes
        void subscribe(aux::bytes const& chain_id, const dht::public_key &peer, const std::string& salt,
                       GET_ITEM_TYPE type, std::int64_t timestamp = 0, int times = 1);

        // make a salt on mutable channel
//        static std::string make_salt(dht::public_key peer, std::int64_t data_type_id);

        // send data to peer
        void send_to(const dht::public_key &peer, entry const& data);

        void add_into_dht_task_queue(const dht_item &dhtItem);

//        void transfer_to_acl_peers(const aux::bytes &chain_id, entry const& data,
//                                   const dht::public_key &incoming_peer = dht::public_key());

//        void transfer_head_block(const aux::bytes &chain_id, const block& blk);

//        void transfer_transaction(const aux::bytes &chain_id, const transaction& tx);

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

        void send_new_head_block_signal(const aux::bytes &chain_id, const sha1_hash &hash);

        void send_new_transfer_tx_signal(const aux::bytes &chain_id, const dht::public_key& tx_receiver);

        void send_new_note_tx_signal(const aux::bytes &chain_id, const sha1_hash &hash);

        void get_head_block_from_peer(const aux::bytes &chain_id, const dht::public_key& peer, std::int64_t timestamp = 0);

        void put_head_block(const aux::bytes &chain_id, const block &blk);

        void put_genesis_head_block(const aux::bytes &chain_id, const block &blk, const std::vector<state_array> &arrays);

        void get_pool_from_peer(const aux::bytes &chain_id, const dht::public_key& peer, std::int64_t timestamp = 0);

        void get_transfer_transaction(const aux::bytes &chain_id, const dht::public_key& peer, std::int64_t timestamp = 0);

        void put_transfer_transaction(const aux::bytes &chain_id, const transaction &tx);

        void put_note_transaction(const aux::bytes &chain_id, const transaction &tx);

        void get_all_state_from_peer(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash);

//        void put_all_state(const aux::bytes &chain_id);

        void get_head_block_hash(const aux::bytes &chain_id, const dht::public_key& peer, std::int64_t timestamp);

        void put_head_block_hash(const aux::bytes &chain_id, const sha1_hash &hash);

        void get_note_pool_root(const aux::bytes &chain_id, const dht::public_key& peer, std::int64_t timestamp);

        void put_note_pool_root(const aux::bytes &chain_id, const sha1_hash &hash);

//        void get_pool_root(const aux::bytes &chain_id, const dht::public_key& peer);

//        void put_pool_root(const aux::bytes &chain_id, const sha1_hash &hash);

//        void get_time_pool_root(const aux::bytes &chain_id, const dht::public_key& peer);
//
//        void put_time_pool_root(const aux::bytes &chain_id, const sha1_hash &hash);

        void get_block(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash);

        void get_head_block(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash, int times = 1);

        void put_block(const aux::bytes &chain_id, const block &blk);

        void put_block_with_all_state(const aux::bytes &chain_id, const block &blk, const std::vector<state_array> &arrays);

//        void get_transaction_wrapper(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash, int times = 1);

//        void put_transaction_wrapper(const aux::bytes &chain_id, const transaction_wrapper &txWrapper);

        void get_transaction(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash, int times = 1);

        void put_transaction(const aux::bytes &chain_id, const transaction &tx);

        void get_state_array(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash);

        void put_state_array(const aux::bytes &chain_id, const state_array &stateArray);

        void get_note_pool_hash_set(const aux::bytes &chain_id, const dht::public_key& peer, const sha1_hash &hash, int times = 1);

        void put_note_pool_hash_set(const aux::bytes &chain_id);

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
        void get_mutable_callback(aux::bytes chain_id, dht::item const& i, bool, GET_ITEM_TYPE type, std::int64_t timestamp, int times = 1);

        // get mutable item from dht
//        void dht_get_mutable_item(aux::bytes const& chain_id, std::array<char, 32> key, std::string salt);

        void on_dht_put_mutable_item(const dht::item &i, int n);

        void on_dht_put_transaction(aux::bytes chain_id, sha1_hash hash, const dht::item &i, int n);

        void on_dht_relay_mutable_item(entry const& payload, std::vector<std::pair<dht::node_entry, bool>> const& nodes, dht::public_key peer);

        // put immutable item to dht
//        void dht_put_immutable_item(entry const& data, std::vector<dht::node_entry> const& eps, sha256_hash target);

        // put mutable item to dht
//        void dht_put_mutable_item(std::array<char, 32> key
//                                  , std::function<void(entry&, std::array<char,64>&
//                                          , std::int64_t&, std::string const&)> cb,
//                                          std::int8_t alpha, std::int8_t beta, std::int8_t invoke_limit
//                                          , std::string salt, const dht::public_key &peer, bool cache);

        void print_acl_info(aux::bytes const& chain_id);

        void add_peer_into_acl(aux::bytes const& chain_id, const dht::public_key& peer, std::int64_t timestamp);

        dht::public_key select_peer_randomly_from_acl(aux::bytes const& chain_id);

//        void data_received_from_peer(aux::bytes const& chain_id, const dht::public_key& peer, int score,
//                                     const std::unique_ptr<common::blockchain_entry_base>& ptr);

//        void head_block_received_from_peer(aux::bytes const& chain_id, const dht::public_key& peer, const block &blk);
//
//        void transaction_received_from_peer(aux::bytes const& chain_id, const dht::public_key& peer, const transaction &tx);

        // @return true: response, false: not response
//        bool request_received_from_peer(aux::bytes const& chain_id, const dht::public_key& peer,
//                                        std::unique_ptr<common::blockchain_entry_base>& ptr);

        // io context
        io_context& m_ioc;

        // session interface
        aux::session_interface& m_ses;

        counters& m_counters;

        // refresh time interval
//        int m_refresh_time = blockchain_default_refresh_time;

        // deadline timer
        aux::deadline_timer m_refresh_timer;

        // dht task deadline timer
        aux::deadline_timer m_dht_tasks_timer;

        bool m_pause = false;

        // chain timers
        std::map<aux::bytes, aux::deadline_timer> m_chain_timers;

//        std::map<GET_ITEM, GET_INFO> m_get_item_info;

        // chain status timers
//        std::map<aux::bytes, aux::deadline_timer> m_chain_status_timers;

        // blockchain db
        std::shared_ptr<repository> m_repository;

        // tx pool
        std::map<aux::bytes, tx_pool> m_tx_pools;

        // note tx wrapper
//        std::map<aux::bytes, transaction_wrapper> m_current_tx_wrapper;

        // chain status
        bool m_stop = false;

        // all chains
        std::set<aux::bytes> m_chains;

        // short chain id table<short chain id, chain id>
        std::map<aux::bytes, aux::bytes> m_short_chain_id_table;

        // chain connected flag
        std::map<aux::bytes, bool> m_chain_connected;

        std::map<aux::bytes, int> m_chain_getting_times;

        // all tasks
        std::queue<dht_item> m_tasks;
//        std::set<dht_item> m_tasks_set;
        std::int64_t m_last_dht_time{};

//        std::map<aux::bytes, CHAIN_STATUS> m_chain_status;

        // Forwarding list
        std::map<aux::bytes, std::map<dht::public_key, peer_info>> m_access_list;

        // last get time(chain id <--> (peer <--> (salt <-->last get time)))
        std::map<aux::bytes, std::map<dht::public_key, std::map<std::string, std::int64_t>>> m_last_get_time;

        // head blocks
        std::map<aux::bytes, block> m_head_blocks;

        std::map<aux::bytes, std::int64_t> m_all_data_last_put_time;

        std::map<aux::bytes, std::int64_t> m_all_blocks_last_put_time;

        std::map<aux::bytes, std::int64_t> m_all_state_last_put_time;
    };
}
}


#endif //LIBTAU_BLOCKCHAIN_HPP
