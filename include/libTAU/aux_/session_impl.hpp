/*

Copyright (c) 2006-2020, Arvid Norberg
Copyright (c) 2014-2019, Steven Siloti
Copyright (c) 2015, Thomas
Copyright (c) 2015-2021, Alden Torres
Copyright (c) 2016-2017, Pavel Pimenov
Copyright (c) 2020, Paul-Louis Ageneau
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_SESSION_IMPL_HPP_INCLUDED
#define TORRENT_SESSION_IMPL_HPP_INCLUDED

#include "libTAU/config.hpp"
#include "libTAU/aux_/session_settings.hpp"
#include "libTAU/aux_/session_interface.hpp"
#include "libTAU/aux_/session_udp_sockets.hpp"
#include "libTAU/aux_/socket_type.hpp"
#include "libTAU/performance_counters.hpp" // for counters
#include "libTAU/aux_/allocating_handler.hpp"
#include "libTAU/aux_/time.hpp"
#include "libTAU/aux_/common.h"
#include "libTAU/session_params.hpp" // for disk_io_constructor_type
#include "libTAU/account_manager.hpp"

#include "libTAU/session.hpp" // for user_load_function_t
#include "libTAU/aux_/ip_voter.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/socket.hpp"
#include "libTAU/peer_id.hpp"
#include "libTAU/aux_/debug.hpp"
#include "libTAU/aux_/tracker_manager.hpp"
#include "libTAU/ip_filter.hpp"
#include "libTAU/aux_/ip_notifier.hpp"
#include "libTAU/session_status.hpp"
#include "libTAU/sha1_hash.hpp"
#include "libTAU/version.hpp"
#include "libTAU/socket.hpp" // for tcp::endpoint
#include "libTAU/bitfield.hpp"
#include "libTAU/error_code.hpp"
#include "libTAU/units.hpp"
#include "libTAU/info_hash.hpp"
#include "libTAU/client_data.hpp"
#include "libTAU/aux_/noexcept_movable.hpp"
#include "libTAU/fwd.hpp"
#include "libTAU/aux_/stat.hpp"
#include "libTAU/aux_/bandwidth_manager.hpp"
#include "libTAU/aux_/udp_socket.hpp"
#include "libTAU/assert.hpp"
#include "libTAU/aux_/alert_manager.hpp" // for alert_manager
#include "libTAU/aux_/deadline_timer.hpp"
#include "libTAU/aux_/socket_io.hpp" // for print_address
#include "libTAU/address.hpp"
#include "libTAU/aux_/bloom_filter.hpp"
#include "libTAU/peer_class.hpp"
#include "libTAU/kademlia/types.hpp"
#include "libTAU/kademlia/dht_observer.hpp"
#include "libTAU/kademlia/dht_state.hpp"
#include "libTAU/kademlia/announce_flags.hpp"
#include "libTAU/kademlia/items_db_sqlite.hpp"
#include "libTAU/kademlia/bs_nodes_storage.hpp"
#include "libTAU/kademlia/types.hpp"
#include "libTAU/kademlia/node_entry.hpp"

#include "libTAU/communication/message.hpp"
#include "libTAU/communication/communication.hpp"

#include "libTAU/blockchain/account.hpp"
#include "libTAU/blockchain/blockchain.hpp"
#include "libTAU/blockchain/block.hpp"
#include "libTAU/blockchain/transaction.hpp"

#include "libTAU/aux_/resolver.hpp"
#include "libTAU/aux_/invariant_check.hpp"
#include "libTAU/extensions.hpp"
#include "libTAU/aux_/portmap.hpp"
#include "libTAU/io_context.hpp"
#include "libTAU/flags.hpp"
#include "libTAU/span.hpp"

#include <leveldb/db.h>
#include <sqlite3.h>
#include <algorithm>
#include <vector>
#include <set>
#include <list>
#include <deque>
#include <condition_variable>
#include <mutex>
#include <cstdarg> // for va_start, va_end
#include <unordered_map>
#include <tuple>

namespace libTAU {

	struct plugin;
	struct upnp;
	struct natpmp;
	struct alert;

namespace dht {

	struct dht_tracker;
	class item;

}

namespace aux {

	struct session_impl;
	struct session_settings;
	struct torrent;

#ifndef TORRENT_DISABLE_LOGGING
	struct tracker_logger;
#endif

	struct unique_ptr_less
	{
		using is_transparent = std::true_type;
		template <typename T>
		bool operator()(std::unique_ptr<T> const& lhs, std::unique_ptr<T> const& rhs) const
		{ return lhs < rhs; }
		template <typename T>
		bool operator()(std::unique_ptr<T> const& lhs, T* rhs) const
		{ return lhs.get() < rhs; }
		template <typename T>
		bool operator()(T* lhs, std::unique_ptr<T> const& rhs) const
		{ return lhs < rhs.get(); }
	};

	using listen_socket_flags_t = flags::bitfield_flag<std::uint8_t, struct listen_socket_flags_tag>;

	struct listen_port_mapping
	{
		port_mapping_t mapping = port_mapping_t{-1};
		int port = 0;
	};

	struct TORRENT_EXTRA_EXPORT listen_socket_t : utp_socket_interface
	{
		// we accept incoming connections on this interface
		static inline constexpr listen_socket_flags_t accept_incoming = 0_bit;

		// this interface was specified to be just the local network. If this flag
		// is not set, this interface is assumed to have a path to the internet
		// (i.e. have a gateway configured)
		static inline constexpr listen_socket_flags_t local_network = 1_bit;

		// this interface was expanded from the user requesting to
		// listen on an unspecified address (either IPv4 or IPv6)
		static inline constexpr listen_socket_flags_t was_expanded = 2_bit;

		// there's a proxy configured, and this is the only one interface
		// representing that one proxy
		static inline constexpr listen_socket_flags_t proxy = 3_bit;

		listen_socket_t() = default;

		// listen_socket_t should not be copied or moved because
		// references to it are held by the DHT and tracker announce
		// code. That code expects a listen_socket_t to always refer
		// to the same socket. It would be easy to accidentally
		// invalidate that assumption if copying or moving were allowed.
		listen_socket_t(listen_socket_t const&) = delete;
		listen_socket_t(listen_socket_t&&) = delete;
		listen_socket_t& operator=(listen_socket_t const&) = delete;
		listen_socket_t& operator=(listen_socket_t&&) = delete;

		udp::endpoint get_local_endpoint() override
		{
			error_code ec;
			if (udp_sock) return udp_sock->sock.local_endpoint(ec);
			return {local_endpoint.address(), local_endpoint.port()};
		}

		// returns true if this listen socket/interface can reach and be reached
		// by the given address. This is useful to know whether it should be
		// annoucned to a tracker (given the tracker's IP) or whether it should
		// have a SOCKS5 UDP tunnel set up (given the IP of the socks proxy)
		bool can_route(address const&) const;

		// this may be empty but can be set
		// to the WAN IP address of a NAT router
		ip_voter external_address;

		// this is a cached local endpoint for the listen TCP socket
		tcp::endpoint local_endpoint;

		address netmask;

		// the name of the device the socket is bound to, may be empty
		// if the socket is not bound to a device
		std::string device;

		// this is the port that was originally specified to listen on it may be
		// different from local_endpoint.port() if we had to retry binding with a
		// higher port
		int original_port = 0;

		// tcp_external_port and udp_external_port return the port which
		// should be published to peers/trackers for this socket
		// If there are active NAT mappings the return value will be
		// the external port returned by the NAT router, otherwise the
		// local listen port is returned
		int udp_external_port()
		{
			for (auto const& m : udp_port_mapping)
			{
				if (m.port != 0) return m.port;
			}
			if (udp_sock) return udp_sock->sock.local_port();
			return 0;
		}

		// 0 is natpmp 1 is upnp
		// the order of these arrays determines the priorty in
		// which their ports will be announced to peers
		aux::array<listen_port_mapping, 2, portmap_transport> udp_port_mapping;

		aux::array<address, 2, portmap_transport> udp_address_mapping;

		// indicates whether this is an SSL listen socket or not
		transport ssl = transport::plaintext;

		listen_socket_flags_t flags = accept_incoming;

		// the actual sockets (TCP listen socket and UDP socket)
		// An entry does not necessarily have a UDP or TCP socket. One of these
		// pointers may be nullptr!
		// These must be shared_ptr to avoid a dangling reference if an
		// incoming packet is in the event queue when the socket is erased
		// TODO: make these direct members and generate shared_ptrs to them
		// which alias the listen_socket_t shared_ptr
		std::shared_ptr<aux::session_udp_socket> udp_sock;

		// since udp packets are expected to be dispatched frequently, this saves
		// time on handler allocation every time we read again.
		aux::handler_storage<aux::udp_handler_max_size, aux::udp_handler> udp_handler_storage;

		std::shared_ptr<natpmp> natpmp_mapper;
		std::shared_ptr<upnp> upnp_mapper;

		// set to true when we receive an incoming connection from this listen
		// socket
		bool incoming_connection = false;
	};

		struct TORRENT_EXTRA_EXPORT listen_endpoint_t
		{
			listen_endpoint_t(address const& adr, int p, std::string dev, transport s
				, listen_socket_flags_t f, address const& nmask = address{})
				: addr(adr), netmask(nmask), port(p), device(std::move(dev)), ssl(s), flags(f) {}

			bool operator==(listen_endpoint_t const& o) const
			{
				return addr == o.addr
					&& port == o.port
					&& device == o.device
					&& ssl == o.ssl
					&& flags == o.flags;
			}

			address addr;
			// if this listen endpoint/interface doesn't have a gateway, we cannot
			// route outside of our network, this netmask defines the range of our
			// local network
			address netmask;
			int port;
			std::string device;
			transport ssl;
			listen_socket_flags_t flags;
		};

		// partitions sockets based on whether they match one of the given endpoints
		// all matched sockets are ordered before unmatched sockets
		// matched endpoints are removed from the vector
		// returns an iterator to the first unmatched socket
		TORRENT_EXTRA_EXPORT std::vector<std::shared_ptr<aux::listen_socket_t>>::iterator
		partition_listen_sockets(
			std::vector<listen_endpoint_t>& eps
			, std::vector<std::shared_ptr<aux::listen_socket_t>>& sockets);

		TORRENT_EXTRA_EXPORT void interface_to_endpoints(
			listen_interface_t const& iface
			, listen_socket_flags_t flags
			, span<ip_interface const> ifs
			, std::vector<listen_endpoint_t>& eps);

		TORRENT_EXTRA_EXPORT void interface_to_endpoints(
			listen_socket_flags_t flags
			, span<ip_interface const> ifs
			, std::vector<listen_endpoint_t>& eps
            , int port);

		// expand [::] to all IPv6 interfaces for BEP 45 compliance
		TORRENT_EXTRA_EXPORT void expand_unspecified_address(
			span<ip_interface const> ifs
			, span<ip_route const> routes
			, std::vector<listen_endpoint_t>& eps);

		void apply_deprecated_dht_settings(settings_pack& sett, bdecode_node const& s);

		TORRENT_EXTRA_EXPORT void expand_devices(span<ip_interface const>
			, std::vector<listen_endpoint_t>& eps);

#ifdef TORRENT_ENABLE_CRASH_ANA
        TORRENT_EXTRA_EXPORT bool crash_dump_call_before(void* context);
#endif

		// this is the switch that sets 'non-referrable' into 'false'
		// if NAT-PMP/UPNP is connected.
		struct TORRENT_EXTRA_EXPORT refer_switch
		{

			refer_switch(bool enabled) { m_enabled = enabled; }

			void set_enabled(bool enabled) { m_enabled = enabled; }
			bool is_enabled() const { return m_enabled; }

			bool is_done() const { return m_done; }
			void set_done() { m_done = true; }

			void on_ip_vote() { ++m_ip_vote; }
			int vote_count() { return m_ip_vote; }

			void reset()
			{
				m_ip_vote = 0;
				m_done = false;
			}

		private:

			bool m_enabled;

			int m_ip_vote = 0;
			bool m_done = false;
		};

		// this is the link between the main thread and the
		// thread started to run the main downloader loop
		struct TORRENT_EXTRA_EXPORT session_impl final
			: session_interface
			, dht::dht_observer
			, aux::portmap_callback
			, single_threaded
			, aux::error_handler_interface
			, std::enable_shared_from_this<session_impl>
		{
			// plugin feature-index key map
			enum
			{
				plugins_all_idx = 0, // to store all plugins
				plugins_optimistic_unchoke_idx = 1, // optimistic_unchoke_feature
				plugins_tick_idx = 2, // tick_feature
				plugins_dht_request_idx = 3 // dht_request_feature
			};

			template <typename Fun, typename... Args>
			void wrap(Fun f, Args&&... a);

#if TORRENT_USE_INVARIANT_CHECKS
			friend struct libTAU::invariant_access;
#endif
			using connection_map = std::set<std::shared_ptr<peer_connection>>;

			session_impl(io_context&, settings_pack const&, session_flags_t);
			~session_impl() override;

			session_impl(session_impl const&) = delete;
			session_impl& operator=(session_impl const&) = delete;

			void start_session();

			void init_peer_class_filter(bool unlimited_local);

			void call_abort()
			{
				auto ptr = shared_from_this();
				dispatch(m_io_context, make_handler([ptr] { ptr->abort(); }
					, m_abort_handler_storage, *this));
			}

#if TORRENT_USE_ASSERTS
			bool is_single_thread() const override { return single_threaded::is_single_thread(); }
#endif

			void on_exception(std::exception const& e) override;
			void on_error(error_code const& ec) override;

			void on_ip_change(error_code const& ec);
			void disconnect();
			void reconnect();
			void reopen_listen_sockets(bool map_ports = true);
			void reopen_outgoing_sockets();
			void reopen_network_sockets(reopen_network_flags_t options);

			io_context& get_context() override { return m_io_context; }
			resolver_interface& get_resolver() override { return m_host_resolver; }

			void incoming_connection(socket_type);

			void apply_settings_pack(std::shared_ptr<settings_pack> pack) override;
			void apply_settings_pack_impl(settings_pack const& pack);
			session_settings const& settings() const override { return m_settings; }
			settings_pack get_settings() const;

			leveldb::DB* kvdb() override {return m_kvdb;}
			sqlite3* sqldb() override {return m_sqldb;}

			std::int64_t timer_coe() override {return m_timer_coe;}

			dht::public_key* pubkey() override {return &(std::get<dht::public_key>(m_keypair));}
			dht::secret_key* serkey() override {return &(std::get<dht::secret_key>(m_keypair));}
			std::tuple<dht::public_key*, dht::secret_key*> pskeys() {
				return std::make_tuple(&(std::get<dht::public_key>(m_keypair)),
									   &(std::get<dht::secret_key>(m_keypair)));
			}

			dht::dht_tracker* dht() override { return m_dht.get(); }
			bool announce_dht() const override { return !m_listening_sockets.empty(); }

			void add_dht_router(std::tuple<std::string, int, std::string> const& node);

            //io_context
            void stop_service();

            void pause_service();

            void resume_service();

            void restart_service();

			//communicaiton
			void start_communication();
			void stop_communication();

			//blockchain
			void start_blockchain();
			void stop_blockchain();

			// you must give up ownership of the dht state
			void set_dht_state(dht::dht_state&& state);
			void set_dht_storage(dht::dht_storage_constructor_type sc);
			void start_dht();
			void stop_dht();
			bool has_dht() const override;

			void get_immutable_callback(sha256_hash target
				, dht::item const& i);
			void get_mutable_callback(dht::item const& i, bool);

			void dht_get_immutable_item(sha256_hash const& target);

			void dht_get_mutable_item(std::array<char, 32> key
				, std::string salt = std::string());

			void dht_put_immutable_item(entry const& data, sha256_hash target);

			void dht_put_mutable_item(std::array<char, 32> key
				, std::function<void(entry&, std::array<char,64>&
					, std::int64_t&, std::string const&)> cb
				, std::string salt = std::string());

			void tau_get_mutable_callback(dht::item const& i, bool);

			void tau_put_mutable_callback(dht::item const& i
				, int num, std::int8_t alpha, std::int8_t invoke_window
				, std::int8_t invoke_limit, std::string salt);

            void send(dht::public_key const& to , entry const& payload
                , std::int8_t alpha , std::int8_t beta
                , std::int8_t invoke_limit, std::int8_t hit_limit);

			void dht_live_nodes(sha256_hash const& nid);

			void on_dht_router_name_lookup(error_code const& e
				, std::vector<address> const& addresses
				, int port
				, std::string pubkey);

			// called when a port mapping is successful, or a router returns
			// a failure to map a port
			void on_port_mapping(port_mapping_t mapping, address const& ip, int port
				, portmap_protocol proto, error_code const& ec
				, portmap_transport transport, listen_socket_handle const&) override;

			bool is_aborted() const override { return m_abort; }

			int get_log_level() const override { return m_logged; }

			void set_ip_filter(std::shared_ptr<ip_filter> f);
			ip_filter const& get_ip_filter();

			void set_port_filter(port_filter const& f);
			port_filter const& get_port_filter() const override;
			void ban_ip(address addr) override;

			// ==== peer class operations ====

			// implements session_interface
			peer_class_pool const& peer_classes() const override { return m_classes; }
			peer_class_pool& peer_classes() override { return m_classes; }

			peer_class_t create_peer_class(char const* name);
			void delete_peer_class(peer_class_t cid);
			void set_peer_class_filter(ip_filter const& f);
			ip_filter const& get_peer_class_filter() const;

			peer_class_info get_peer_class(peer_class_t cid) const;
			void set_peer_class(peer_class_t cid, peer_class_info const& pci);

			bool is_listening() const;

			void post_session_stats();
			void post_dht_stats();

			void pop_alerts(std::vector<alert*>* alerts);
			alert* wait_for_alert(time_duration max_wait);

			std::size_t set_alert_queue_size_limit(std::size_t queue_size_limit_);

			// deprecated, use stats counters ``num_peers_connected`` +
			// ``num_peers_half_open`` instead.
			int num_connections() const override { return int(m_connections.size()); }

			void trigger_unchoke() noexcept override
			{
				TORRENT_ASSERT(is_single_thread());
				m_unchoke_time_scaler = 0;
			}
			void trigger_optimistic_unchoke() noexcept override
			{
				TORRENT_ASSERT(is_single_thread());
				m_optimistic_unchoke_time_scaler = 0;
			}

			// used by the DHT tracker, returns a UDP listen port
			int get_listen_port(transport ssl, aux::listen_socket_handle const& s) override;

			void for_each_listen_socket(std::function<void(aux::listen_socket_handle const&)> f) override
			{
				for (auto& s : m_listening_sockets)
				{
					f(listen_socket_handle(s));
				}
			}

			alert_manager& alerts() override { return m_alerts; }

			void abort() noexcept;
			void abort_stage2() noexcept;

			session_params session_state(save_state_flags_t flags) const;
			proxy_settings proxy() const override;

			bool is_dht_running() const { return (m_dht.get() != nullptr); }
			int external_udp_port(address const& local_address) const override;

			udp::endpoint external_udp_endpoint() const override;

			void start_ip_notifier();
			void start_natpmp();
			void start_upnp();

			void stop_ip_notifier();
			void stop_natpmp();
			void stop_upnp();

			std::vector<port_mapping_t> add_port_mapping(portmap_protocol t, int external_port
				, int local_port);
			void delete_port_mapping(port_mapping_t handle);

			int next_port() const;

			// implements dht_observer
			void set_external_address(aux::listen_socket_handle const& iface
				, address const& ip, address const& source) override;
			void get_peers(sha256_hash const& ih) override;
			void announce(sha256_hash const& ih, address const& addr, int port) override;
			void outgoing_get_peers(sha256_hash const& target
				, sha256_hash const& sent_target, udp::endpoint const& ep) override;

#ifndef TORRENT_DISABLE_LOGGING
			bool should_log(module_t m) const override;
			bool should_log(module_t m, aux::LOG_LEVEL log_level) const override;
			void log(module_t m, char const* fmt, ...)
				override TORRENT_FORMAT(3,4);
			void log_packet(message_direction_t dir, span<char const> pkt
				, udp::endpoint const& node) override;

			bool should_log_portmap(portmap_transport transport) const override;
			void log_portmap(portmap_transport transport, char const* msg
				, listen_socket_handle const&) const override;
#endif

			bool on_dht_request(string_view query
				, dht::msg const& request, entry& response) override;

			void on_dht_item(dht::item& i) override;

			std::int64_t get_time() override;

			void on_dht_relay(dht::public_key const& from, entry const& payload) override;

			sqlite3* get_items_database() override;

			void set_external_address(tcp::endpoint const& local_endpoint
				, address const& ip
				, ip_source_t source_type, address const& source) override;
			aux::external_ip external_address() const override;

			// used when posting synchronous function
			// calls to session_impl and torrent objects
			mutable std::mutex mut;
			mutable std::condition_variable cond;

			// implements session_interface
			bool verify_incoming_interface(address const& addr);
			bool verify_bound_address(address const& addr, bool utp
				, error_code& ec) override;

			void inc_boost_connections() override
			{
				++m_boost_connections;
			}

			// the settings for the client
			aux::session_settings m_settings;

			void update_dht_upload_rate_limit();
			void update_proxy();
			void update_peer_tos();
			void update_user_agent();
			void update_connection_speed();
			void update_alert_queue_size();
			void update_disk_threads();
			void update_outgoing_interfaces();
			void update_listen_interfaces();
			void update_privileged_ports();
			void update_resolver_cache_timeout();

			void update_ip_notifier();
			void update_log_level();
			void set_log_level(int logged);
			void update_upnp();
			void update_natpmp();
			void update_dht();
			void update_device_id();
			void update_db_dir();
			void update_account_seed();
			std::uint16_t get_port_from_pubkey(const dht::public_key &pubkey);
			std::uint16_t get_port_from_local();
			void new_account_seed(std::string& account_seed);
			void update_dht_bootstrap_nodes();

			void update_socket_buffer_size();
			void update_connections_limit();
			void update_alert_mask();
			void update_auto_relay();

            //DEPRECATED
            //1. communication
			void set_loop_time_interval(int milliseconds);
            void get_friend_info(const dht::public_key& pubkey, std::vector<char>* info);
            void request_friend_info(const dht::public_key& pubkey);
            bool update_friend_info(const dht::public_key& pubkey, aux::bytes friend_info);
            void unset_chatting_friend();
			void set_chatting_friend(const dht::public_key& chatting_friend);
            void set_active_friends(std::vector<dht::public_key> active_friends);
            //2. blockchain
        	bool get_gossip_list(const aux::bytes &chain_id, std::set<dht::public_key>* keys);
        	void set_priority_chain(const aux::bytes &chain_id);
        	void unset_priority_chain();
        	void request_chain_state(const aux::bytes &chain_id);

            //Valid
            //1. communication
			bool add_new_friend(const dht::public_key& pubkey);
			bool delete_friend(const dht::public_key& pubkey);
            bool add_new_message(const communication::message& msg);
		    bool publish_data(const aux::bytes& key, const aux::bytes& value);
		    bool subscribe_from_peer(const dht::public_key& pubkey, const aux::bytes& data);
		    bool send_to_peer(const dht::public_key& pubkey, const aux::bytes& data);
		    bool pay_attention_to_peer(const dht::public_key& pubkey);

            //2. blockchain
        	void create_chain_id(const aux::bytes& type, std::string community_name, std::vector<char>* id);
            bool create_new_community(const aux::bytes &chain_id, const std::set<blockchain::account>& accounts);
        	bool follow_chain(const aux::bytes &chain_id, const std::set<dht::public_key>& peers);
        	bool add_new_bootstrap_peers(const aux::bytes &chain_id, const std::set<dht::public_key>& peers);
        	bool unfollow_chain(const aux::bytes &chain_id);
        	bool start_chain(const aux::bytes &chain_id);
        	bool submit_transaction(const blockchain::transaction & tx);
        	bool get_account_info(const aux::bytes &chain_id, dht::public_key publicKey, blockchain::account* act);
        	bool get_top_tip_block(const aux::bytes &chain_id, int topNum, std::vector<blockchain::block>* blks);
        	bool get_access_list(const aux::bytes &chain_id, std::set<dht::public_key>* keys);
        	bool get_ban_list(const aux::bytes &chain_id, std::set<dht::public_key>* keys);
        	std::int64_t get_median_tx_free(const aux::bytes &chain_id);
        	std::int64_t get_mining_time(const aux::bytes &chain_id);
        	blockchain::block get_block_by_number(const aux::bytes &chain_id, std::int64_t block_number);
        	blockchain::block get_block_by_hash(const aux::bytes &chain_id, const sha1_hash& block_hash);
        	bool is_transaction_in_fee_pool(const aux::bytes &chain_id, const sha1_hash& txid);
        	void request_chain_data(const aux::bytes &chain_id, const dht::public_key &peer);
        	void put_all_chain_data(const aux::bytes &chain_id);
        	bool send_online_signal(const aux::bytes &chain_id);
        	bool connect_chain(const aux::bytes &chain_id);
            void get_all_chains(std::set<std::vector<char>>* cids);

			std::int64_t session_current_time_ms() const
			{
				return m_session_time;
			}

            void crash_test();

            void sql_test();

		private:

			// return the settings value for int setting "n", if the value is
			// negative, return INT_MAX
			int get_int_setting(int n) const;

			peer_class_pool m_classes;

			void init();

			void start_natpmp(std::shared_ptr<aux::listen_socket_t> const&  s);
			void start_upnp(std::shared_ptr<aux::listen_socket_t> const& s);

			void set_external_address(std::shared_ptr<listen_socket_t> const& sock, address const& ip
				, ip_source_t source_type, address const& source);

			counters m_stats_counters;

			io_context& m_io_context;

			// handles delayed alerts
			mutable alert_manager m_alerts;

			// the peer class that all peers belong to by default
			peer_class_t m_global_class{0};

			// peer class for local peers
			peer_class_t m_local_peer_class{0};

			resolver m_host_resolver;

			// all torrents that are downloading or queued,
			// ordered by their queue position
			aux::vector<torrent*, queue_position_t> m_download_queue;

			// peer connections are put here when disconnected to avoid
			// race conditions with the disk thread. It's important that
			// peer connections are destructed from the network thread,
			// once a peer is disconnected, it's put in this list and
			// every second their refcount is checked, and if it's 1,
			// they are deleted (from the network thread)
			std::vector<std::shared_ptr<peer_connection>> m_undead_peers;

			executor_work_guard<io_context::executor_type> m_work;

			// this maps sockets to their peer_connection
			// object. It is the complete list of all connected
			// peers.
			connection_map m_connections;

			// maps IP ranges to bitfields representing peer class IDs
			// to assign peers matching a specific IP range based on its
			// remote endpoint
			ip_filter m_peer_class_filter;

			// filters incoming connections
			std::shared_ptr<ip_filter> m_ip_filter;

			// filters outgoing connections
			port_filter m_port_filter;

			// posts a notification when the set of local IPs changes
			std::unique_ptr<ip_change_notifier> m_ip_notifier;

			// the addresses or device names of the interfaces we are supposed to
			// listen on. if empty, it means that we should let the os decide
			// which interface to listen on
			std::vector<listen_interface_t> m_listen_interfaces;

			// the network interfaces outgoing connections are opened through. If
			// there is more then one, they are used in a round-robin fashion
			// each element is a device name or IP address (in string form) and
			// a port number. The port determines which port to bind the listen
			// socket to, and the device or IP determines which network adapter
			// to be used. If no adapter with the specified name exists, the listen
			// socket fails.
			std::vector<std::string> m_outgoing_interfaces;

			// since we might be listening on multiple interfaces
			// we might need more than one listen socket
			std::vector<std::shared_ptr<listen_socket_t>> m_listening_sockets;
			std::vector<std::shared_ptr<listen_socket_t>> m_listened_sockets;

			// round-robin index into m_outgoing_interfaces
			mutable std::uint8_t m_interface_index = 0;

			std::shared_ptr<listen_socket_t> setup_listener(
				listen_endpoint_t const& lep, error_code& ec);

			dht::dht_state m_dht_state;

            leveldb::DB* m_kvdb;
            sqlite3* m_sqldb;

            std::int64_t m_timer_coe = 1;
			
	 		std::tuple<dht::public_key, dht::secret_key> m_keypair;

			// this is initialized to the unchoke_interval
			// session_setting and decreased every second.
			// when it reaches zero, it is reset to the
			// unchoke_interval and the unchoke set is
			// recomputed.
			// TODO: replace this by a proper asio timer
			int m_unchoke_time_scaler = 0;

			// this is used to decide when to recalculate which
			// torrents to keep queued and which to activate
			// TODO: replace this by a proper asio timer
			int m_auto_manage_time_scaler = 0;

			// works like unchoke_time_scaler but it
			// is only decreased when the unchoke set
			// is recomputed, and when it reaches zero,
			// the optimistic unchoke is moved to another peer.
			// TODO: replace this by a proper asio timer
			int m_optimistic_unchoke_time_scaler = 0;

			// works like unchoke_time_scaler. Each time
			// it reaches 0, and all the connections are
			// used, the worst connection will be disconnected
			// from the torrent with the most peers
			int m_disconnect_time_scaler = 90;

			// when this scaler reaches zero, it will
			// scrape one of the auto managed, paused,
			// torrents.
			int m_auto_scrape_time_scaler = 180;

			// statistics gathered from all torrents.
			stat m_stat;

			// implements session_interface
			void sent_bytes(int bytes_payload, int bytes_protocol) override;
			void received_bytes(int bytes_payload, int bytes_protocol) override;
			void trancieve_ip_packet(int bytes, bool ipv6) override;
			void sent_syn(bool ipv6) override;
			void received_synack(bool ipv6) override;

			time_point m_created;
			std::uint16_t session_time() const override
			{
				// +1 is here to make it possible to distinguish uninitialized (to
				// 0) timestamps and timestamps of things that happened during the
				// first second after the session was constructed
				std::int64_t const ret = total_seconds(aux::time_now()
					- m_created) + 1;
				TORRENT_ASSERT(ret >= 0);
				if (ret > (std::numeric_limits<std::uint16_t>::max)())
					return (std::numeric_limits<std::uint16_t>::max)();
				return static_cast<std::uint16_t>(ret);
			}
			time_point session_start_time() const override
			{
				return m_created;
			}

			std::int64_t m_last_tick;
			std::int64_t m_session_time;
			std::int64_t m_last_reopen = 0;
			std::int64_t m_dht_nodes_non_zero = 0; //nodes number == 0

			void on_tick(error_code const& e);
			void session_time_modification(std::int64_t time = 0);

#ifdef TORRENT_ENABLE_CRASH_ANA
			void crash_dump_initial();
#endif
			// when outgoing_ports is configured, this is the
			// port we'll bind the next outgoing socket to
			mutable int m_next_port = 0;

			std::shared_ptr<account_manager> m_account_manager;

			std::string m_raw_send_udp_packet;
			std::string m_encrypted_udp_packet;

			std::string m_raw_recv_udp_packet;
			std::string m_decrypted_udp_packet;
			std::string m_decrypted_ucd_udp_packet;

			std::unique_ptr<dht::dht_storage_interface> m_dht_storage;
			std::shared_ptr<dht::items_db_sqlite> m_items_db;
			std::unique_ptr<dht::bs_nodes_storage_interface> m_bs_nodes_storage;
			std::string m_bs_nodes_dir;
			std::shared_ptr<dht::dht_tracker> m_dht;
			dht::dht_storage_constructor_type m_dht_storage_constructor
				= dht::dht_default_storage_constructor;

			// communication
			std::shared_ptr<communication::communication> m_communication;
			aux::bytes m_device_id;

			// blockchain
			std::shared_ptr<blockchain::blockchain> m_blockchain;

			// these are used when starting the DHT
			// (and bootstrapping it), and then erased
			std::vector<dht::node_entry> m_dht_router_nodes;

			// if a DHT node is added when there's no DHT instance, they're stored
			// here until we start the DHT
			std::vector<dht::node_entry> m_dht_nodes;

			// the number of DHT router lookups there are currently outstanding. As
			// long as this is > 0, we'll postpone starting the DHT
			int m_outstanding_router_lookups = 0;

			void send_udp_packet_hostname(std::weak_ptr<utp_socket_interface> sock
				, char const* hostname
				, int port
				, span<char const> p
				, error_code& ec
				, udp_send_flags_t flags);

			void send_udp_packet_hostname_listen(aux::listen_socket_handle const& sock
				, char const* hostname
				, int port
				, span<char const> p
				, error_code& ec
				, udp_send_flags_t const flags)
			{
				listen_socket_t* s = sock.get();
				if (!s)
				{
					ec = boost::asio::error::bad_descriptor;
					return;
				}
				send_udp_packet_hostname(sock.get_ptr(), hostname, port, p, ec, flags);
			}

			void send_udp_packet(std::weak_ptr<utp_socket_interface> sock
				, udp::endpoint const& ep
				, span<char const> p
				, error_code& ec
				, udp_send_flags_t flags);

			void send_udp_packet_listen(aux::listen_socket_handle const& sock
				, udp::endpoint const& ep
				, span<char const> p
				, error_code& ec
				, udp_send_flags_t const flags)
			{
				listen_socket_t* s = sock.get();
				if (!s)
				{
					ec = boost::asio::error::bad_descriptor;
					return;
				}
				send_udp_packet(sock.get_ptr(), ep, p, ec, flags);
			}

			void send_udp_packet_listen_encryption(aux::listen_socket_handle const& sock
				, udp::endpoint const& ep
				, sha256_hash const& pk
				, span<char const> p
				, error_code& ec
				, udp_send_flags_t const flags);

#ifdef TORRENT_ENABLE_UDP_COMPRESS
			bool compress_udp_packet(span<char const> p, std::string& out);

			bool uncompress_udp_packet(const std::string& in, std::string& out);
#endif

			bool encrypt_udp_packet(sha256_hash const& pk
				, const std::string& in
				, std::string& out
				, std::string& err_str);

			bool decrypt_udp_packet(const std::string& in
				, sha256_hash const& pk
				, std::string& out
				, std::string& err_str);

			void on_udp_packet(std::weak_ptr<session_udp_socket> s
				, std::weak_ptr<listen_socket_t> ls
				, transport ssl, error_code const& ec);

			// the number of torrent connection boosts
			// connections that have been made this second
			// this is deducted from the connect speed
			int m_boost_connections = 0;

			// mask is a bitmask of which protocols to remap on:
			enum remap_port_mask_t
			{
				remap_natpmp = 1,
				remap_upnp = 2,
				remap_natpmp_and_upnp = 3
			};
			void remap_ports(remap_port_mask_t mask, listen_socket_t& s);

			//the timer used to fire the tick
			deadline_timer m_timer;

			// abort may not fail and cannot allocate memory
			aux::handler_storage<aux::abort_handler_max_size, aux::abort_handler> m_abort_handler_storage;

			// submit_deferred may not fail
			aux::handler_storage<aux::submit_handler_max_size, aux::submit_handler> m_submit_jobs_handler_storage;

			counters& stats_counters() override { return m_stats_counters; }

			void received_buffer(int size) override;
			void sent_buffer(int size) override;

#ifndef TORRENT_DISABLE_LOGGING
			bool should_log() const override;
			bool should_log(aux::LOG_LEVEL log_level) const override;
			void session_log(char const* fmt, ...) const noexcept override TORRENT_FORMAT(2,3);
#endif

			// set to true when the session object
			// is being destructed and the thread
			// should exit
			bool m_abort = false;

			int m_logged = aux::LOG_LEVEL::LOG_DEBUG;

			// set to true the first time post_session_stats() is
			// called and we post the headers alert
			bool m_posted_stats_header = false;

			void reset_refer_switch();
			void trigger_refer_switch(std::shared_ptr<listen_socket_t> const& sock
				, address const& ip);
			refer_switch m_refer_switch;
		};

#ifndef TORRENT_DISABLE_LOGGING
		struct tracker_logger : request_callback
		{
			explicit tracker_logger(session_interface& ses);
			void tracker_warning(tracker_request const& req
				, std::string const& str) override;
			void tracker_response(tracker_request const&
				, libTAU::address const& tracker_ip
				, std::list<address> const& tracker_ips
				, struct tracker_response const& resp) override;
			void tracker_request_error(tracker_request const& r
				, error_code const& ec, operation_t op, const std::string& str
				, seconds32 retry_interval) override;
			bool should_log() const override;
			void debug_log(const char* fmt, ...) const noexcept override TORRENT_FORMAT(2,3);
			session_interface& m_ses;

		private:
			// explicitly disallow assignment, to silence msvc warning
			tracker_logger& operator=(tracker_logger const&);
		};
#endif

	}
}

#endif
