/*

Copyright (c) 2014-2018, Steven Siloti
Copyright (c) 2015-2020, Arvid Norberg
Copyright (c) 2015-2018, Alden Torres
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

#include "libTAU/session_handle.hpp"
#include "libTAU/aux_/session_impl.hpp"
#include "libTAU/aux_/session_call.hpp"
#include "libTAU/aux_/throw.hpp"
#include "libTAU/aux_/path.hpp"
#include "libTAU/hasher.hpp"
#include "libTAU/peer_class.hpp"
#include "libTAU/aux_/scope_end.hpp"

using libTAU::aux::session_impl;

namespace libTAU {

	constexpr peer_class_t session_handle::global_peer_class_id;
	constexpr peer_class_t session_handle::tcp_peer_class_id;
	constexpr peer_class_t session_handle::local_peer_class_id;

	constexpr save_state_flags_t session_handle::save_settings;
	constexpr save_state_flags_t session_handle::save_dht_state;
	constexpr save_state_flags_t session_handle::save_extension_state;
	constexpr save_state_flags_t session_handle::save_ip_filter;

	constexpr session_flags_t session_handle::paused;

	constexpr reopen_network_flags_t session_handle::reopen_map_ports;

	template <typename Fun, typename... Args>
	void session_handle::async_call(Fun f, Args&&... a) const
	{
		std::shared_ptr<session_impl> s = m_impl.lock();
		if (!s) aux::throw_ex<system_error>(errors::invalid_session_handle);
		dispatch(s->get_context(), [=]() mutable
		{
#ifndef BOOST_NO_EXCEPTIONS
			try {
#endif
				(s.get()->*f)(std::forward<Args>(a)...);
#ifndef BOOST_NO_EXCEPTIONS
			} catch (system_error const& e) {
				s->alerts().emplace_alert<session_error_alert>(e.code(), e.what());
			} catch (std::exception const& e) {
				s->alerts().emplace_alert<session_error_alert>(error_code(), e.what());
			} catch (...) {
				s->alerts().emplace_alert<session_error_alert>(error_code(), "unknown error");
			}
#endif
		});
	}

	template<typename Fun, typename... Args>
	void session_handle::sync_call(Fun f, Args&&... a) const
	{
		std::shared_ptr<session_impl> s = m_impl.lock();
		if (!s) aux::throw_ex<system_error>(errors::invalid_session_handle);

		// this is the flag to indicate the call has completed
		// capture them by pointer to allow everything to be captured by value
		// and simplify the capture expression
		bool done = false;

		std::exception_ptr ex;
		dispatch(s->get_context(), [=, &done, &ex]() mutable
		{
#ifndef BOOST_NO_EXCEPTIONS
			try {
#endif
				(s.get()->*f)(std::forward<Args>(a)...);
#ifndef BOOST_NO_EXCEPTIONS
			} catch (...) {
				ex = std::current_exception();
			}
#endif
			std::unique_lock<std::mutex> l(s->mut);
			done = true;
			s->cond.notify_all();
		});

		aux::torrent_wait(done, *s);
		if (ex) std::rethrow_exception(ex);
	}

	template<typename Ret, typename Fun, typename... Args>
	Ret session_handle::sync_call_ret(Fun f, Args&&... a) const
	{
		std::shared_ptr<session_impl> s = m_impl.lock();
		if (!s) aux::throw_ex<system_error>(errors::invalid_session_handle);

		// this is the flag to indicate the call has completed
		// capture them by pointer to allow everything to be captured by value
		// and simplify the capture expression
		bool done = false;
		Ret r;
		std::exception_ptr ex;
		dispatch(s->get_context(), [=, &r, &done, &ex]() mutable
		{
#ifndef BOOST_NO_EXCEPTIONS
			try {
#endif
				r = (s.get()->*f)(std::forward<Args>(a)...);
#ifndef BOOST_NO_EXCEPTIONS
			} catch (...) {
				ex = std::current_exception();
			}
#endif
			std::unique_lock<std::mutex> l(s->mut);
			done = true;
			s->cond.notify_all();
		});

		aux::torrent_wait(done, *s);
		if (ex) std::rethrow_exception(ex);
		return r;
	}

	session_params session_handle::session_state(save_state_flags_t const flags) const
	{
		return sync_call_ret<session_params>(&session_impl::session_state, flags);
	}

	void session_handle::post_session_stats()
	{
		async_call(&session_impl::post_session_stats);
	}

	void session_handle::post_dht_stats()
	{
		async_call(&session_impl::post_dht_stats);
	}

	io_context& session_handle::get_context()
	{
		std::shared_ptr<session_impl> s = m_impl.lock();
		if (!s) aux::throw_ex<system_error>(errors::invalid_session_handle);
		return s->get_context();
	}

	void session_handle::set_dht_state(dht::dht_state const& st)
	{
		async_call(&session_impl::set_dht_state, dht::dht_state(st));
	}

	void session_handle::set_dht_state(dht::dht_state&& st)
	{
		async_call(&session_impl::set_dht_state, std::move(st));
	}

	bool session_handle::is_dht_running() const
	{
		return sync_call_ret<bool>(&session_impl::is_dht_running);
	}

	void session_handle::set_dht_storage(dht::dht_storage_constructor_type sc)
	{
		async_call(&session_impl::set_dht_storage, sc);
	}

	void session_handle::dht_get_item(sha256_hash const& target)
	{
		async_call(&session_impl::dht_get_immutable_item, target);
	}

	void session_handle::dht_get_item(std::array<char, 32> key
		, std::string salt)
	{
		async_call(&session_impl::dht_get_mutable_item, key, salt);
	}

	// TODO: 3 expose the timestamp, public_key, secret_key and signature
	// types to the client
	sha256_hash session_handle::dht_put_item(entry data)
	{
		std::vector<char> buf;
		bencode(std::back_inserter(buf), data);
		sha256_hash const ret = hasher256(buf).final();
		async_call(&session_impl::dht_put_immutable_item, data, ret);
		return ret;
	}

	void session_handle::dht_put_item(std::array<char, 32> key
		, std::function<void(entry&, std::array<char,64>&
			, std::int64_t&, std::string const&)> cb
		, std::string salt)
	{
		async_call(&session_impl::dht_put_mutable_item, key, cb, salt);
	}

	void session_handle::send(dht::public_key const& to , entry const& payload
		, std::int8_t alpha , std::int8_t beta , std::int8_t invoke_limit
		, std::int8_t hit_limit)
	{
		async_call(&session_impl::send, to, payload, alpha, beta
			, invoke_limit, hit_limit);
	}

	void session_handle::dht_live_nodes(sha256_hash const& nid)
	{
		async_call(&session_impl::dht_live_nodes, nid);
	}

	std::uint16_t session_handle::get_port_from_pubkey(const dht::public_key& pubkey) {
		return sync_call_ret<std::uint16_t>(&session_impl::get_port_from_pubkey, pubkey);
    }

	void session_handle::new_account_seed(std::string& account_seed)
	{
		sync_call(&session_impl::new_account_seed, account_seed);
	}

    //disconnect network
	void session_handle::disconnect()
	{
		sync_call(&session_impl::disconnect);
	}

    //reconnect network
	void session_handle::reconnect()
	{
		sync_call(&session_impl::reconnect);
	}

	void session_handle::set_log_level(int logged)
	{
		sync_call(&session_impl::set_log_level, logged);
	}

	void session_handle::set_loop_time_interval(int milliseconds)
	{
		async_call(&session_impl::set_loop_time_interval, milliseconds);
	}

	bool session_handle::publish_data(const std::vector<char>& key, const std::vector<char>& value)
	{
		return sync_call_ret<bool>(&session_impl::publish_data, key, value);
	}

	bool session_handle::subscribe_from_peer(const dht::public_key& pubkey, const std::vector<char>& data)
	{
		return sync_call_ret<bool>(&session_impl::subscribe_from_peer, pubkey, data);
	}

	bool session_handle::send_to_peer(const dht::public_key& pubkey, const std::vector<char>& data)
	{
		return sync_call_ret<bool>(&session_impl::send_to_peer, pubkey, data);
	}

	bool session_handle::pay_attention_to_peer(const dht::public_key& pubkey)
	{
		return sync_call_ret<bool>(&session_impl::pay_attention_to_peer, pubkey);
	}

	bool session_handle::add_new_friend(const dht::public_key& pubkey)
	{
		return sync_call_ret<bool>(&session_impl::add_new_friend, pubkey);
	}

	bool session_handle::delete_friend(const dht::public_key& pubkey)
	{
		return sync_call_ret<bool>(&session_impl::delete_friend, pubkey);
	}

	void session_handle::set_chatting_friend(const dht::public_key& pubkey)
	{
		sync_call(&session_impl::set_chatting_friend, pubkey);
	}

	std::vector<char> session_handle::get_friend_info(const dht::public_key& pubkey)
	{
		std::vector<char> info;
		sync_call(&session_impl::get_friend_info, pubkey, &info);
		return info;
	}

	void session_handle::request_friend_info(const dht::public_key& pubkey)
	{
		sync_call(&session_impl::request_friend_info, pubkey);
	}

	void session_handle::unset_chatting_friend()
	{
		sync_call(&session_impl::unset_chatting_friend);
	}

	bool session_handle::update_friend_info(const dht::public_key& pubkey, std::vector<char> friend_info)
	{
		return sync_call_ret<bool>(&session_impl::update_friend_info, pubkey, friend_info);
	}

	void session_handle::set_active_friends(std::vector<dht::public_key> active_friends)
	{
		sync_call(&session_impl::set_active_friends, active_friends);	
	}

	bool session_handle::add_new_message(communication::message msg)
	{
		return sync_call_ret<bool>(&session_impl::add_new_message, msg);
	}

	std::vector<char> session_handle::create_chain_id(std::vector<char> type, std::vector<char> community_name)
	{
		std::string name;
		name.insert(name.begin(), community_name.begin(), community_name.end());
		std::vector<char> id;
		sync_call(&session_impl::create_chain_id, type, name, &id); 
		return id;
	}

	std::set<std::vector<char>> session_handle::get_all_chains()
	{
		std::set<std::vector<char>> cids;
		sync_call(&session_impl::get_all_chains, &cids); 
		return cids;
	}

	// create new community
    bool session_handle::create_new_community(std::vector<char> chain_id, const std::set<blockchain::account>& accounts)
	{
		return sync_call_ret<bool>(&session_impl::create_new_community, chain_id, accounts);
	}

	// follow chain
    bool session_handle::follow_chain(std::vector<char> chain_id, const std::set<dht::public_key>& peers)
	{
		return sync_call_ret<bool>(&session_impl::follow_chain, chain_id, peers);
	}

	// add new bs peers
    bool session_handle::add_new_bootstrap_peers(std::vector<char> chain_id, const std::set<dht::public_key>& peers)
	{
		return sync_call_ret<bool>(&session_impl::add_new_bootstrap_peers, chain_id, peers);
	}

	// unfollow chain
    bool session_handle::unfollow_chain(std::vector<char> chain_id)
	{
		return sync_call_ret<bool>(&session_impl::unfollow_chain, chain_id);
	}

	// start chain
    bool session_handle::start_chain(std::vector<char> chain_id)
	{
		return sync_call_ret<bool>(&session_impl::start_chain, chain_id);
	}

	// submit transaction
    bool session_handle::submit_transaction(const blockchain::transaction & tx)
	{
		return sync_call_ret<bool>(&session_impl::submit_transaction, tx);
	}

	// get account info
    blockchain::account session_handle::get_account_info(std::vector<char> chain_id, dht::public_key pub_key)
	{
		blockchain::account act;
		sync_call(&session_impl::get_account_info, chain_id, pub_key, &act);
		return act;
	}

	// get top and tip blocks
    std::vector<blockchain::block> session_handle::get_top_tip_block(std::vector<char> chain_id, int num)
	{
		std::vector<blockchain::block> blks;
		sync_call(&session_impl::get_top_tip_block, chain_id, num, &blks);
		return blks;
	}

	// get access list
    std::set<dht::public_key> session_handle::get_access_list(std::vector<char> chain_id)
	{
		std::set<dht::public_key> keys;
		sync_call(&session_impl::get_access_list, chain_id, &keys);
		return keys;
	}

	// get ban list
    std::set<dht::public_key> session_handle::get_ban_list(std::vector<char> chain_id)
	{
		std::set<dht::public_key> keys;
		sync_call(&session_impl::get_ban_list, chain_id, &keys);
		return keys;
	}

	// get gossip list
    std::set<dht::public_key> session_handle::get_gossip_list(std::vector<char> chain_id)
	{
		std::set<dht::public_key> keys;
		sync_call(&session_impl::get_gossip_list, chain_id, &keys);
		return keys;
	}

	// get median tx fee
    std::int64_t session_handle::get_median_tx_free(std::vector<char> chain_id)
	{
		return sync_call_ret<std::int64_t>(&session_impl::get_median_tx_free, chain_id);
	}

	std::int64_t session_handle::get_mining_time(std::vector<char> chain_id) {
		return sync_call_ret<std::int64_t>(&session_impl::get_mining_time, chain_id);
	}

	void session_handle::set_priority_chain(std::vector<char> chain_id) {
		return sync_call(&session_impl::set_priority_chain, chain_id);
	}

	void session_handle::unset_priority_chain() {
		return sync_call(&session_impl::unset_priority_chain);
	}

	// get block by number
    blockchain::block session_handle::get_block_by_number(std::vector<char> chain_id, std::int64_t block_number)
	{
		return sync_call_ret<blockchain::block>(&session_impl::get_block_by_number, chain_id, block_number);
	}

	// get block by hash
    blockchain::block session_handle::get_block_by_hash(std::vector<char> chain_id, const sha1_hash& block_hash)
	{
		return sync_call_ret<blockchain::block>(&session_impl::get_block_by_hash, chain_id, block_hash);
	}

	// txid in pool or not
    bool session_handle::is_transaction_in_fee_pool(std::vector<char> chain_id, const sha1_hash& txid)
	{
		return sync_call_ret<bool>(&session_impl::is_transaction_in_fee_pool, chain_id, txid);
	}

	// get chain state
    void session_handle::request_chain_state(std::vector<char> chain_id)
	{
		return sync_call(&session_impl::request_chain_state, chain_id);
	}

	// get chain data
    void session_handle::request_chain_data(std::vector<char> chain_id, dht::public_key pub_key)
	{
		return sync_call(&session_impl::request_chain_data, chain_id, pub_key);
	}

	// put chain data
    void session_handle::put_all_chain_data(std::vector<char> chain_id)
	{
		return sync_call(&session_impl::put_all_chain_data, chain_id);
	}

	// send online signal
    bool session_handle::send_online_signal(std::vector<char> chain_id)
	{
		return sync_call_ret<bool>(&session_impl::send_online_signal, chain_id);
	}

	// connect chain
    bool session_handle::connect_chain(std::vector<char> chain_id)
	{
		return sync_call_ret<bool>(&session_impl::connect_chain, chain_id);
	}

	// get current time
	std::int64_t session_handle::get_session_time()
	{
		return sync_call_ret<std::int64_t>(&session_impl::session_current_time_ms);
	}

	// stop service
	void session_handle::stop_service()
	{
		return sync_call(&session_impl::stop_service);
	}

	// restart service
	void session_handle::restart_service()
	{
		return sync_call(&session_impl::restart_service);
	}

	// pause service
	void session_handle::pause_service()
	{
		return sync_call(&session_impl::pause_service);
	}

	// resume service
	void session_handle::resume_service()
	{
		return sync_call(&session_impl::resume_service);
	}

    void session_handle::crash_test()
    {
		return sync_call(&session_impl::crash_test);
    }

    void session_handle::sql_test()
    {
		return sync_call(&session_impl::sql_test);
    }

	void session_handle::set_ip_filter(ip_filter f)
	{
		std::shared_ptr<ip_filter> copy = std::make_shared<ip_filter>(std::move(f));
		async_call(&session_impl::set_ip_filter, std::move(copy));
	}

	ip_filter session_handle::get_ip_filter() const
	{
		return sync_call_ret<ip_filter>(&session_impl::get_ip_filter);
	}

	void session_handle::set_port_filter(port_filter const& f)
	{
		async_call(&session_impl::set_port_filter, f);
	}

	bool session_handle::is_listening() const
	{
		return sync_call_ret<bool>(&session_impl::is_listening);
	}

	void session_handle::set_peer_class_filter(ip_filter const& f)
	{
		async_call(&session_impl::set_peer_class_filter, f);
	}

	ip_filter session_handle::get_peer_class_filter() const
	{
		return sync_call_ret<ip_filter>(&session_impl::get_peer_class_filter);
	}

	peer_class_t session_handle::create_peer_class(char const* name)
	{
		return sync_call_ret<peer_class_t>(&session_impl::create_peer_class, name);
	}

	void session_handle::delete_peer_class(peer_class_t cid)
	{
		async_call(&session_impl::delete_peer_class, cid);
	}

	peer_class_info session_handle::get_peer_class(peer_class_t cid) const
	{
		return sync_call_ret<peer_class_info>(&session_impl::get_peer_class, cid);
	}

	void session_handle::set_peer_class(peer_class_t cid, peer_class_info const& pci)
	{
		async_call(&session_impl::set_peer_class, cid, pci);
	}

	void session_handle::apply_settings(settings_pack const& s)
	{
		TORRENT_ASSERT_PRECOND(!s.has_val(settings_pack::out_enc_policy)
			|| s.get_int(settings_pack::out_enc_policy)
				<= settings_pack::pe_disabled);
		TORRENT_ASSERT_PRECOND(!s.has_val(settings_pack::in_enc_policy)
			|| s.get_int(settings_pack::in_enc_policy)
				<= settings_pack::pe_disabled);
		TORRENT_ASSERT_PRECOND(!s.has_val(settings_pack::allowed_enc_level)
			|| s.get_int(settings_pack::allowed_enc_level)
				<= settings_pack::pe_both);

		auto copy = std::make_shared<settings_pack>(s);
		async_call(&session_impl::apply_settings_pack, copy);
	}

	void session_handle::apply_settings(settings_pack&& s)
	{
		TORRENT_ASSERT_PRECOND(!s.has_val(settings_pack::out_enc_policy)
			|| s.get_int(settings_pack::out_enc_policy)
				<= settings_pack::pe_disabled);
		TORRENT_ASSERT_PRECOND(!s.has_val(settings_pack::in_enc_policy)
			|| s.get_int(settings_pack::in_enc_policy)
				<= settings_pack::pe_disabled);
		TORRENT_ASSERT_PRECOND(!s.has_val(settings_pack::allowed_enc_level)
			|| s.get_int(settings_pack::allowed_enc_level)
				<= settings_pack::pe_both);

		auto copy = std::make_shared<settings_pack>(std::move(s));
		async_call(&session_impl::apply_settings_pack, copy);
	}

	settings_pack session_handle::get_settings() const
	{
		return sync_call_ret<settings_pack>(&session_impl::get_settings);
	}

	// the alerts are const, they may not be deleted by the client
	void session_handle::pop_alerts(std::vector<alert*>* alerts)
	{
		std::shared_ptr<session_impl> s = m_impl.lock();
		if (!s) aux::throw_ex<system_error>(errors::invalid_session_handle);
		s->pop_alerts(alerts);
	}

	alert* session_handle::wait_for_alert(time_duration max_wait)
	{
		std::shared_ptr<session_impl> s = m_impl.lock();
		if (!s) aux::throw_ex<system_error>(errors::invalid_session_handle);
		return s->wait_for_alert(max_wait);
	}

	void session_handle::set_alert_notify(std::function<void()> const& fun)
	{
		std::shared_ptr<session_impl> s = m_impl.lock();
		if (!s) aux::throw_ex<system_error>(errors::invalid_session_handle);
		s->alerts().set_notify_function(fun);
	}

	size_t session_handle::set_alert_queue_size_limit(size_t queue_size_limit_)
	{
		return sync_call_ret<size_t>(&session_impl::set_alert_queue_size_limit, queue_size_limit_);
	}

	void session_handle::set_alert_mask(std::uint32_t m)
	{
		settings_pack p;
		p.set_int(settings_pack::alert_mask, int(m));
		apply_settings(std::move(p));
	}

	std::uint32_t session_handle::get_alert_mask() const
	{
		return std::uint32_t(get_settings().get_int(settings_pack::alert_mask));
	}

	void session_handle::start_upnp()
	{
		settings_pack p;
		p.set_bool(settings_pack::enable_upnp, true);
		apply_settings(std::move(p));
	}

	void session_handle::stop_upnp()
	{
		settings_pack p;
		p.set_bool(settings_pack::enable_upnp, false);
		apply_settings(std::move(p));
	}

	void session_handle::start_natpmp()
	{
		settings_pack p;
		p.set_bool(settings_pack::enable_natpmp, true);
		apply_settings(std::move(p));
	}

	void session_handle::stop_natpmp()
	{
		settings_pack p;
		p.set_bool(settings_pack::enable_natpmp, false);
		apply_settings(std::move(p));
	}

	std::vector<port_mapping_t> session_handle::add_port_mapping(portmap_protocol const t
		, int external_port, int local_port)
	{
		return sync_call_ret<std::vector<port_mapping_t>>(&session_impl::add_port_mapping, t, external_port, local_port);
	}

	void session_handle::delete_port_mapping(port_mapping_t handle)
	{
		async_call(&session_impl::delete_port_mapping, handle);
	}

	void session_handle::reopen_network_sockets(reopen_network_flags_t const options)
	{
		async_call(&session_impl::reopen_network_sockets, options);
	}

} // namespace libTAU
