/*

Copyright (c) 2014-2018, Steven Siloti
Copyright (c) 2015-2020, Arvid Norberg
Copyright (c) 2015-2018, Alden Torres
Copyright (c) 2020, AllSeeingEyeTolledEweSew
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef TORRENT_SESSION_HANDLE_HPP_INCLUDED
#define TORRENT_SESSION_HANDLE_HPP_INCLUDED

#include <memory> // for shared_ptr

#include "libTAU/config.hpp"
#include "libTAU/fwd.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/alert.hpp" // alert_category::error
#include "libTAU/peer_class.hpp"
#include "libTAU/peer_id.hpp"
#include "libTAU/io_context.hpp"
#include "libTAU/session_types.hpp"
#include "libTAU/session_status.hpp"
#include "libTAU/portmap.hpp" // for portmap_protocol

#include "libTAU/aux_/common.h" // for aux::bytes

#include "libTAU/kademlia/dht_storage.hpp"
#include "libTAU/kademlia/announce_flags.hpp"

#include "libTAU/extensions.hpp"
#include "libTAU/session_types.hpp" // for session_flags_t

#include "libTAU/communication/message.hpp" // for adding new message

#include "libTAU/blockchain/account.hpp" 
#include "libTAU/blockchain/block.hpp"
#include "libTAU/blockchain/transaction.hpp"

namespace libTAU {

	// this class provides a non-owning handle to a session and a subset of the
	// interface of the session class. If the underlying session is destructed
	// any handle to it will no longer be valid. is_valid() will return false and
	// any operation on it will throw a system_error exception, with error code
	// invalid_session_handle.
	struct TORRENT_EXPORT session_handle
	{
		friend struct session;
		friend struct aux::session_impl;

		// hidden
		session_handle() = default;
		session_handle(session_handle const& t) = default;
		session_handle(session_handle&& t) noexcept = default;
		session_handle& operator=(session_handle const&) & = default;
		session_handle& operator=(session_handle&&) & noexcept = default;

		// returns true if this handle refers to a valid session object. If the
		// session has been destroyed, all session_handle objects will expire and
		// not be valid.
		bool is_valid() const { return !m_impl.expired(); }

		// saves settings (i.e. the settings_pack)
		static constexpr save_state_flags_t save_settings = 0_bit;

		// saves dht state such as nodes and node-id, possibly accelerating
		// joining the DHT if provided at next session startup.
		static constexpr save_state_flags_t save_dht_state = 2_bit;

		// load or save state from plugins
		static constexpr save_state_flags_t save_extension_state = 11_bit;

		// load or save the IP filter set on the session
		static constexpr save_state_flags_t save_ip_filter = 12_bit;

		// returns the current session state. This can be passed to
		// write_session_params() to save the state to disk and restored using
		// read_session_params() when constructing a new session. The kind of
		// state that's included is all settings, the DHT routing table, possibly
		// plugin-specific state.
		// the flags parameter can be used to only save certain parts of the
		// session state
		session_params session_state(save_state_flags_t flags = save_state_flags_t::all()) const;

		// This function will post a session_stats_alert object, containing a
		// snapshot of the performance counters from the internals of libTAU.
		// To interpret these counters, query the session via
		// session_stats_metrics().
		//
		// For more information, see the session-statistics_ section.
		void post_session_stats();

		// This will cause a dht_stats_alert to be posted.
		void post_dht_stats();

		// internal
		io_context& get_context();

		// set the DHT state for the session. This will be taken into account the
		// next time the DHT is started, as if it had been passed in via the
		// session_params on startup.
		void set_dht_state(dht::dht_state const& st);
		void set_dht_state(dht::dht_state&& st);

		// ``is_dht_running()`` returns true if the DHT support has been started
		// and false otherwise.
		bool is_dht_running() const;

        //get port from port
        std::uint16_t get_port_from_pubkey(const dht::public_key& pubkey);

        //update account seed
        void new_account_seed(std::string& account_seed);

        //update account seed
        void set_log_level(int logged);

		// ``set_dht_storage`` set a dht custom storage constructor function
		// to be used internally when the dht is created.
		//
		// Since the dht storage is a critical component for the dht behavior,
		// this function will only be effective the next time the dht is started.
		// If you never touch this feature, a default map-memory based storage
		// is used.
		//
		// If you want to make sure the dht is initially created with your
		// custom storage, create a session with the setting
		// ``settings_pack::enable_dht`` to false, set your constructor function
		// and call ``apply_settings`` with ``settings_pack::enable_dht`` to true.
		void set_dht_storage(dht::dht_storage_constructor_type sc);

		// query the DHT for an immutable item at the ``target`` hash.
		// the result is posted as a dht_immutable_item_alert.
		void dht_get_item(sha256_hash const& target);

		// query the DHT for a mutable item under the public key ``key``.
		// this is an ed25519 key. ``salt`` is optional and may be left
		// as an empty string if no salt is to be used.
		// if the item is found in the DHT, a dht_mutable_item_alert is
		// posted.
		void dht_get_item(std::array<char, 32> key
			, std::string salt = std::string());

		// store the given bencoded data as an immutable item in the DHT.
		// the returned hash is the key that is to be used to look the item
		// up again. It's just the SHA-1 hash of the bencoded form of the
		// structure.
		sha256_hash dht_put_item(entry data);

		// store a mutable item. The ``key`` is the public key the blob is
		// to be stored under. The optional ``salt`` argument is a string that
		// is to be mixed in with the key when determining where in the DHT
		// the value is to be stored. The callback function is called from within
		// the libTAU network thread once we've found where to store the blob,
		// possibly with the current value stored under the key.
		// The values passed to the callback functions are:
		//
		// entry& value
		// 	the current value stored under the key (may be empty). Also expected
		// 	to be set to the value to be stored by the function.
		//
		// std::array<char,64>& signature
		// 	the signature authenticating the current value. This may be zeros
		// 	if there is currently no value stored. The function is expected to
		// 	fill in this buffer with the signature of the new value to store.
		// 	To generate the signature, you may want to use the
		// 	``sign_mutable_item`` function.
		//
		// std::int64_t& seq
		// 	current sequence number. May be zero if there is no current value.
		// 	The function is expected to set this to the new sequence number of
		// 	the value that is to be stored. Sequence numbers must be monotonically
		// 	increasing. Attempting to overwrite a value with a lower or equal
		// 	sequence number will fail, even if the signature is correct.
		//
		// std::string const& salt
		// 	this is the salt that was used for this put call.
		//
		// Since the callback function ``cb`` is called from within libTAU,
		// it is critical to not perform any blocking operations. Ideally not
		// even locking a mutex. Pass any data required for this function along
		// with the function object's context and make the function entirely
		// self-contained. The only reason data blob's value is computed
		// via a function instead of just passing in the new value is to avoid
		// race conditions. If you want to *update* the value in the DHT, you
		// must first retrieve it, then modify it, then write it back. The way
		// the DHT works, it is natural to always do a lookup before storing and
		// calling the callback in between is convenient.
		void dht_put_item(std::array<char, 32> key
			, std::function<void(entry&, std::array<char, 64>&
				, std::int64_t&, std::string const&)> cb
			, std::string salt = std::string());

        void send(dht::public_key const& to , entry const& payload
            , std::int8_t alpha , std::int8_t beta
            , std::int8_t invoke_limit, std::int8_t hit_limit);

		// Retrieve all the live DHT (identified by ``nid``) nodes. All the
		// nodes id and endpoint will be returned in the list of nodes in the
		// alert ``dht_live_nodes_alert``.
		// Since this alert is a response to an explicit call, it will always be
		// posted, regardless of the alert mask.
		void dht_live_nodes(sha256_hash const& nid);

		// use save_state and load_state instead
		void add_extension(std::shared_ptr<plugin> ext);

		// Sets a filter that will be used to reject and accept incoming as well
		// as outgoing connections based on their originating ip address. The
		// default filter will allow connections to any ip address. To build a
		// set of rules for which addresses are accepted and not, see ip_filter.
		//
		// Each time a peer is blocked because of the IP filter, a
		// peer_blocked_alert is generated. ``get_ip_filter()`` Returns the
		// ip_filter currently in the session. See ip_filter.
		void set_ip_filter(ip_filter f);
		ip_filter get_ip_filter() const;

		// apply port_filter ``f`` to incoming and outgoing peers. a port filter
		// will reject making outgoing peer connections to certain remote ports.
		// The main intention is to be able to avoid triggering certain
		// anti-virus software by connecting to SMTP, FTP ports.
		void set_port_filter(port_filter const& f);

		// built-in peer classes
		static constexpr peer_class_t global_peer_class_id{0};
		static constexpr peer_class_t tcp_peer_class_id{1};
		static constexpr peer_class_t local_peer_class_id{2};

		// ``is_listening()`` will tell you whether or not the session has
		// successfully opened a listening port. If it hasn't, this function will
		// return false, and then you can set a new
		// settings_pack::listen_interfaces to try another interface and port to
		// bind to.
		bool is_listening() const;

		// Sets the peer class filter for this session. All new peer connections
		// will take this into account and be added to the peer classes specified
		// by this filter, based on the peer's IP address.
		//
		// The ip-filter essentially maps an IP -> uint32. Each bit in that 32
		// bit integer represents a peer class. The least significant bit
		// represents class 0, the next bit class 1 and so on.
		//
		// For more info, see ip_filter.
		//
		// For example, to make all peers in the range 200.1.1.0 - 200.1.255.255
		// belong to their own peer class, apply the following filter:
		//
		// .. code:: c++
		//
		// 	ip_filter f = ses.get_peer_class_filter();
		// 	peer_class_t my_class = ses.create_peer_class("200.1.x.x IP range");
		// 	f.add_rule(make_address("200.1.1.0"), make_address("200.1.255.255")
		// 		, 1 << static_cast<std::uint32_t>(my_class));
		// 	ses.set_peer_class_filter(f);
		//
		// This setting only applies to new connections, it won't affect existing
		// peer connections.
		//
		// This function is limited to only peer class 0-31, since there are only
		// 32 bits in the IP range mapping. Only the set bits matter; no peer
		// class will be removed from a peer as a result of this call, peer
		// classes are only added.
		//
		// The ``peer_class`` argument cannot be greater than 31. The bitmasks
		// representing peer classes in the ``peer_class_filter`` are 32 bits.
		//
		// The ``get_peer_class_filter()`` function returns the current filter.
		//
		// For more information, see peer-classes_.
		void set_peer_class_filter(ip_filter const& f);
		ip_filter get_peer_class_filter() const;

		// Creates a new peer class (see peer-classes_) with the given name. The
		// returned integer is the new peer class identifier. Peer classes may
		// have the same name, so each invocation of this function creates a new
		// class and returns a unique identifier.
		//
		// Identifiers are assigned from low numbers to higher. So if you plan on
		// using certain peer classes in a call to set_peer_class_filter(),
		// make sure to create those early on, to get low identifiers.
		//
		// For more information on peer classes, see peer-classes_.
		peer_class_t create_peer_class(char const* name);

        //stop network
		void disconnect();

        //restartNetwork
		void reconnect();

		// set main loop time interval (ms)

		void set_loop_time_interval(int milliseconds);

		bool publish_data(const std::vector<char>& key, const std::vector<char>& value);

		bool subscribe_from_peer(const dht::public_key& pubkey, const std::vector<char>& data);

		bool send_to_peer(const dht::public_key& pubkey, const std::vector<char>& data);

		bool pay_attention_to_peer(const dht::public_key& pubkey);

		// add new friend in memory & db
		bool add_new_friend(const dht::public_key& pubkey);

		// delete friend and all related data in memory & db
		bool delete_friend(const dht::public_key& pubkey);

		// get friend info by public key
		std::vector<char> get_friend_info(const dht::public_key& pubkey);

		// request friend info by public key
		void request_friend_info(const dht::public_key& pubkey);

		// set chatting friends
		void set_chatting_friend(const dht::public_key& pubkey);

		// unset chatting friends
		void unset_chatting_friend();

		// save friend info
		bool update_friend_info(const dht::public_key& pubkey, std::vector<char> friend_info);

		// set active friends
		void set_active_friends(std::vector<dht::public_key> active_friends);

		// add a new message
		bool add_new_message(communication::message msg);

		// create chain id
		std::vector<char> create_chain_id(std::vector<char> type, std::vector<char> community_name);

        // get all followd chains
		std::set<std::vector<char>> get_all_chains();

		// create new community
        bool create_new_community(std::vector<char> chain_id, const std::set<blockchain::account>& accounts);
		// follow chain
        bool follow_chain(std::vector<char> chain_id, const std::set<dht::public_key>& peers);
        //add new bs peers
        bool add_new_bootstrap_peers(std::vector<char> chain_id, const std::set<dht::public_key>& peers);
		// unfollow chain
        bool unfollow_chain(std::vector<char> chain_id);

		// start chain
        bool start_chain(std::vector<char> chain_id);

		// submit transaction
        bool submit_transaction(const blockchain::transaction & tx);
		// get account info
        blockchain::account get_account_info(std::vector<char> chain_id, dht::public_key publicKey);
		// get top and tip blocks
        std::vector<blockchain::block> get_top_tip_block(std::vector<char> chain_id, int num);

        // get access list
        std::set<dht::public_key> get_access_list(std::vector<char> chain_id);

        // get ban list
        std::set<dht::public_key> get_ban_list(std::vector<char> chain_id);

        // get gossip list
        std::set<dht::public_key> get_gossip_list(std::vector<char> chain_id);

		// get median tx fee
        std::int64_t get_median_tx_free(std::vector<char> chain_id);

		// get mining time
        std::int64_t get_mining_time(std::vector<char> chain_id);

		// focus on chain
        void set_priority_chain(std::vector<char> chain_id);

		// send online signal
        bool send_online_signal(std::vector<char> chain_id);

		// connect chain
        bool connect_chain(std::vector<char> chain_id);

		// un-focus on chain
        void unset_priority_chain();

		// get block by number
        blockchain::block get_block_by_number(std::vector<char> chain_id, std::int64_t block_number);

		// get block by hash
        blockchain::block get_block_by_hash(std::vector<char> chain_id, const sha1_hash& block_hash);

		// whether txid in pool or not
        bool is_transaction_in_fee_pool(std::vector<char> chain_id, const sha1_hash& txid);

		// get chain state 
        void request_chain_state(std::vector<char> chain_id);

		// get chain data 
        void request_chain_data(std::vector<char> chain_id, dht::public_key publicKey);

		// put chain data 
        void put_all_chain_data(std::vector<char> chain_id);

		// get current session system time
        std::int64_t get_session_time();

        void stop_service();

        void restart_service();

        void pause_service();

        void resume_service();

        void crash_test();

        void sql_test();

		// This call dereferences the reference count of the specified peer
		// class. When creating a peer class it's automatically referenced by 1.
		// If you want to recycle a peer class, you may call this function. You
		// may only call this function **once** per peer class you create.
		// Calling it more than once for the same class will lead to memory
		// corruption.
		//
		// Since peer classes are reference counted, this function will not
		// remove the peer class if it's still assigned to torrents or peers. It
		// will however remove it once the last peer and torrent drops their
		// references to it.
		//
		// There is no need to call this function for custom peer classes. All
		// peer classes will be properly destructed when the session object
		// destructs.
		//
		// For more information on peer classes, see peer-classes_.
		void delete_peer_class(peer_class_t cid);

		// These functions queries information from a peer class and updates the
		// configuration of a peer class, respectively.
		//
		// ``cid`` must refer to an existing peer class. If it does not, the
		// return value of ``get_peer_class()`` is undefined.
		//
		// ``set_peer_class()`` sets all the information in the
		// peer_class_info object in the specified peer class. There is no
		// option to only update a single property.
		//
		// A peer or torrent belonging to more than one class, the highest
		// priority among any of its classes is the one that is taken into
		// account.
		//
		// For more information, see peer-classes_.
		peer_class_info get_peer_class(peer_class_t cid) const;
		void set_peer_class(peer_class_t cid, peer_class_info const& pci);

		// delete the files belonging to the torrent from disk.
		// including the part-file, if there is one
		static constexpr remove_flags_t delete_files = 0_bit;

		// delete just the part-file associated with this torrent
		static constexpr remove_flags_t delete_partfile = 1_bit;

		// when set, the session will start paused. Call
		// session_handle::resume() to start
		static constexpr session_flags_t paused = 2_bit;

		// Applies the settings specified by the settings_pack ``s``. This is an
		// asynchronous operation that will return immediately and actually apply
		// the settings to the main thread of libTAU some time later.
		void apply_settings(settings_pack const&);
		void apply_settings(settings_pack&&);
		settings_pack get_settings() const;

		// Alerts is the main mechanism for libTAU to report errors and
		// events. ``pop_alerts`` fills in the vector passed to it with pointers
		// to new alerts. The session still owns these alerts and they will stay
		// valid until the next time ``pop_alerts`` is called. You may not delete
		// the alert objects.
		//
		// It is safe to call ``pop_alerts`` from multiple different threads, as
		// long as the alerts themselves are not accessed once another thread
		// calls ``pop_alerts``. Doing this requires manual synchronization
		// between the popping threads.
		//
		// ``wait_for_alert`` will block the current thread for ``max_wait`` time
		// duration, or until another alert is posted. If an alert is available
		// at the time of the call, it returns immediately. The returned alert
		// pointer is the head of the alert queue. ``wait_for_alert`` does not
		// pop alerts from the queue, it merely peeks at it. The returned alert
		// will stay valid until ``pop_alerts`` is called twice. The first time
		// will pop it and the second will free it.
		//
		// If there is no alert in the queue and no alert arrives within the
		// specified timeout, ``wait_for_alert`` returns nullptr.
		//
		// In the python binding, ``wait_for_alert`` takes the number of
		// milliseconds to wait as an integer.
		//
		// The alert queue in the session will not grow indefinitely. Make sure
		// to pop periodically to not miss notifications. To control the max
		// number of alerts that's queued by the session, see
		// ``settings_pack::alert_queue_size``.
		//
		// Some alerts are considered so important that they are posted even when
		// the alert queue is full. Some alerts are considered mandatory and cannot
		// be disabled by the ``alert_mask``. For instance,
		// save_resume_data_alert and save_resume_data_failed_alert are always
		// posted, regardless of the alert mask.
		//
		// To control which alerts are posted, set the alert_mask
		// (settings_pack::alert_mask).
		//
		// If the alert queue fills up to the point where alerts are dropped, this
		// will be indicated by a alerts_dropped_alert, which contains a bitmask
		// of which types of alerts were dropped. Generally it is a good idea to
		// make sure the alert queue is large enough, the alert_mask doesn't have
		// unnecessary categories enabled and to call pop_alert() frequently, to
		// avoid alerts being dropped.
		//
		// the ``set_alert_notify`` function lets the client set a function object
		// to be invoked every time the alert queue goes from having 0 alerts to
		// 1 alert. This function is called from within libTAU, it may be the
		// main thread, or it may be from within a user call. The intention of
		// of the function is that the client wakes up its main thread, to poll
		// for more alerts using ``pop_alerts()``. If the notify function fails
		// to do so, it won't be called again, until ``pop_alerts`` is called for
		// some other reason. For instance, it could signal an eventfd, post a
		// message to an HWND or some other main message pump. The actual
		// retrieval of alerts should not be done in the callback. In fact, the
		// callback should not block. It should not perform any expensive work.
		// It really should just notify the main application thread.
		//
		// The type of an alert is returned by the polymorphic function
		// ``alert::type()`` but can also be queries from a concrete type via
		// ``T::alert_type``, as a static constant.
		void pop_alerts(std::vector<alert*>* alerts);
		alert* wait_for_alert(time_duration max_wait);
		void set_alert_notify(std::function<void()> const& fun);

		// use the setting instead
		size_t set_alert_queue_size_limit(size_t queue_size_limit_);

		// Changes the mask of which alerts to receive. By default only errors
		// are reported. ``m`` is a bitmask where each bit represents a category
		// of alerts.
		//
		// ``get_alert_mask()`` returns the current mask;
		//
		// See category_t enum for options.
		void set_alert_mask(std::uint32_t m);
		std::uint32_t get_alert_mask() const;

		// Starts and stops the UPnP service. When started, the listen port and
		// the DHT port are attempted to be forwarded on local UPnP router
		// devices.
		//
		// The upnp object returned by ``start_upnp()`` can be used to add and
		// remove arbitrary port mappings. Mapping status is returned through the
		// portmap_alert and the portmap_error_alert. The object will be valid
		// until ``stop_upnp()`` is called. See upnp-and-nat-pmp_.
		//
		// deprecated. use settings_pack::enable_upnp instead
		void start_upnp();
		void stop_upnp();

		// Starts and stops the NAT-PMP service. When started, the listen port
		// and the DHT port are attempted to be forwarded on the router through
		// NAT-PMP.
		//
		// The natpmp object returned by ``start_natpmp()`` can be used to add
		// and remove arbitrary port mappings. Mapping status is returned through
		// the portmap_alert and the portmap_error_alert. The object will be
		// valid until ``stop_natpmp()`` is called. See upnp-and-nat-pmp_.
		//
		// deprecated. use settings_pack::enable_natpmp instead
		void start_natpmp();
		void stop_natpmp();

		// protocols used by add_port_mapping()
		static constexpr portmap_protocol udp = portmap_protocol::udp;
		static constexpr portmap_protocol tcp = portmap_protocol::tcp;

		// add_port_mapping adds one or more port forwards on UPnP and/or NAT-PMP,
		// whichever is enabled. A mapping is created for each listen socket
		// in the session. The return values are all handles referring to the
		// port mappings that were just created. Pass them to delete_port_mapping()
		// to remove them.
		std::vector<port_mapping_t> add_port_mapping(portmap_protocol t, int external_port, int local_port);
		void delete_port_mapping(port_mapping_t handle);

		// This option indicates if the ports are mapped using natpmp
		// and upnp. If mapping was already made, they are deleted and added
		// again. This only works if natpmp and/or upnp are configured to be
		// enable.
		static constexpr reopen_network_flags_t reopen_map_ports = 0_bit;

		// Instructs the session to reopen all listen and outgoing sockets.
		//
		// It's useful in the case your platform doesn't support the built in
		// IP notifier mechanism, or if you have a better more reliable way to
		// detect changes in the IP routing table.
		void reopen_network_sockets(reopen_network_flags_t options = reopen_map_ports);

		// This function is intended only for use by plugins. This type does
		// not have a stable API and should be relied on as little as possible.
		std::shared_ptr<aux::session_impl> native_handle() const
		{ return m_impl.lock(); }

	private:

		template <typename Fun, typename... Args>
		void async_call(Fun f, Args&&... a) const;

		template <typename Fun, typename... Args>
		void sync_call(Fun f, Args&&... a) const;

		template <typename Ret, typename Fun, typename... Args>
		Ret sync_call_ret(Fun f, Args&&... a) const;

		explicit session_handle(std::weak_ptr<aux::session_impl> impl)
			: m_impl(std::move(impl))
		{}

		std::weak_ptr<aux::session_impl> m_impl;
	};

} // namespace libTAU

#endif // TORRENT_SESSION_HANDLE_HPP_INCLUDED
