/*

Copyright (c) 2003, Magnus Jonsson
Copyright (c) 2006-2021, Arvid Norberg
Copyright (c) 2009, Andrew Resch
Copyright (c) 2014-2020, Steven Siloti
Copyright (c) 2015-2021, Alden Torres
Copyright (c) 2015, Thomas
Copyright (c) 2015, Mikhail Titov
Copyright (c) 2016, Falcosc
Copyright (c) 2016-2017, Pavel Pimenov
Copyright (c) 2016-2017, Andrei Kurushin
Copyright (c) 2017, sledgehammer_999
Copyright (c) 2018, Xiyue Deng
Copyright (c) 2020, Fonic
Copyright (c) 2020, Rosen Penev
Copyright (c) 2020, Paul-Louis Ageneau
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/config.hpp"

#include <ctime>
#include <algorithm>
#include <cctype>
#include <cstdio> // for snprintf
#include <cinttypes> // for PRId64 et.al.
#include <functional>
#include <type_traits>
#include <numeric> // for accumulate

#include "libTAU/aux_/disable_warnings_push.hpp"
#include <filesystem>
#include <boost/filesystem.hpp>
#include <boost/asio/ts/internet.hpp>
#include <boost/asio/ts/executor.hpp>
#include "libTAU/aux_/disable_warnings_pop.hpp"

#include "libTAU/aux_/ssl.hpp"
#include "libTAU/peer_id.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/hasher.hpp"
#include "libTAU/hex.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/session.hpp"
#include "libTAU/fingerprint.hpp"
#include "libTAU/alert_types.hpp"
#include "libTAU/aux_/invariant_check.hpp"
#include "libTAU/peer_connection_handle.hpp"
#include "libTAU/ip_filter.hpp"
#include "libTAU/socket.hpp"
#include "libTAU/aux_/session_impl.hpp"

#include "libTAU/aux_/common.h"

#include "libTAU/kademlia/ed25519.hpp"
#include "libTAU/kademlia/dht_tracker.hpp"
#include "libTAU/kademlia/types.hpp"
#include "libTAU/kademlia/node_entry.hpp"

#include "libTAU/communication/communication.hpp"

#include "libTAU/aux_/enum_net.hpp"
#include "libTAU/upnp.hpp"
#include "libTAU/natpmp.hpp"
#include "libTAU/aux_/instantiate_connection.hpp"
#include "libTAU/aux_/random.hpp"
#include "libTAU/magnet_uri.hpp"
#include "libTAU/aux_/session_settings.hpp"
#include "libTAU/error.hpp"
#include "libTAU/aux_/platform_util.hpp"
#include "libTAU/aux_/bind_to_device.hpp"
#include "libTAU/hex.hpp" // to_hex, from_hex
#include "libTAU/aux_/scope_end.hpp"
#include "libTAU/aux_/set_socket_buffer.hpp"
#include "libTAU/aux_/generate_peer_id.hpp"
#include "libTAU/aux_/ffs.hpp"
#include "libTAU/aux_/array.hpp"

#ifndef TORRENT_DISABLE_LOGGING

#include "libTAU/aux_/socket_io.hpp"

// for logging stat layout
#include "libTAU/aux_/stat.hpp"

#include <cstdarg> // for va_list

#include <leveldb/db.h>
#include <sqlite3.h>

// for logging the size of DHT structures
#include <libTAU/kademlia/find_data.hpp>
#include <libTAU/kademlia/refresh.hpp>
#include <libTAU/kademlia/node.hpp>
#include <libTAU/kademlia/observer.hpp>
#include <libTAU/kademlia/item.hpp>

#include "libTAU/aux_/http_tracker_connection.hpp"
#include "libTAU/aux_/udp_tracker_connection.hpp"

#endif // TORRENT_DISABLE_LOGGING

#ifdef TORRENT_USE_LIBGCRYPT

#if GCRYPT_VERSION_NUMBER < 0x010600
extern "C" {
GCRY_THREAD_OPTION_PTHREAD_IMPL;
}
#endif

namespace {

	// libgcrypt requires this to initialize the library
	struct gcrypt_setup
	{
		gcrypt_setup()
		{
			gcry_check_version(nullptr);
#if GCRYPT_VERSION_NUMBER < 0x010600
			gcry_error_t e = gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
			if (e != 0) std::fprintf(stderr, "libcrypt ERROR: %s\n", gcry_strerror(e));
			e = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
			if (e != 0) std::fprintf(stderr, "initialization finished error: %s\n", gcry_strerror(e));
#endif
		}
	} gcrypt_global_constructor;
}

#endif // TORRENT_USE_LIBGCRYPT

#ifdef TORRENT_USE_OPENSSL
#ifdef TORRENT_WINDOWS
#include <wincrypt.h>
#endif
#endif // TORRENT_USE_OPENSSL

#ifdef TORRENT_WINDOWS
// for ERROR_SEM_TIMEOUT
#include <winerror.h>
#endif

using namespace std::placeholders;

#ifdef BOOST_NO_EXCEPTIONS
namespace boost {

	void throw_exception(std::exception const& e) { std::abort(); }
}
#endif

namespace libTAU::aux {

#if defined TORRENT_ASIO_DEBUGGING
	std::map<std::string, async_t> _async_ops;
	std::deque<wakeup_t> _wakeups;
	int _async_ops_nthreads = 0;
	std::mutex _async_ops_mutex;

	std::map<int, handler_alloc_t> _handler_storage;
	std::mutex _handler_storage_mutex;
	bool _handler_logger_registered = false;
#endif

void apply_deprecated_dht_settings(settings_pack& sett, bdecode_node const& s)
{
	bdecode_node val;
	val = s.dict_find_int("max_peers_reply");
	if (val) sett.set_int(settings_pack::dht_max_peers_reply, int(val.int_value()));
	val = s.dict_find_int("search_branching");
	if (val) sett.set_int(settings_pack::dht_search_branching, int(val.int_value()));
	val = s.dict_find_int("max_fail_count");
	if (val) sett.set_int(settings_pack::dht_max_fail_count, int(val.int_value()));
	val = s.dict_find_int("max_dht_items");
	if (val) sett.set_int(settings_pack::dht_max_dht_items, int(val.int_value()));
	val = s.dict_find_int("max_peers");
	if (val) sett.set_int(settings_pack::dht_max_peers, int(val.int_value()));
	val = s.dict_find_int("restrict_routing_ips");
	if (val) sett.set_bool(settings_pack::dht_restrict_routing_ips, (val.int_value() != 0));
	val = s.dict_find_int("restrict_search_ips");
	if (val) sett.set_bool(settings_pack::dht_restrict_search_ips, (val.int_value() != 0));
	val = s.dict_find_int("extended_routing_table");
	if (val) sett.set_bool(settings_pack::dht_extended_routing_table, (val.int_value() != 0));
	val = s.dict_find_int("aggressive_lookups");
	if (val) sett.set_bool(settings_pack::dht_aggressive_lookups, (val.int_value() != 0));
	val = s.dict_find_int("privacy_lookups");
	if (val) sett.set_bool(settings_pack::dht_privacy_lookups, (val.int_value() != 0));
	val = s.dict_find_int("enforce_node_id");
	if (val) sett.set_bool(settings_pack::dht_enforce_node_id, (val.int_value() != 0));
	val = s.dict_find_int("ignore_dark_internet");
	if (val) sett.set_bool(settings_pack::dht_ignore_dark_internet, (val.int_value() != 0));
	val = s.dict_find_int("block_timeout");
	if (val) sett.set_int(settings_pack::dht_block_timeout, int(val.int_value()));
	val = s.dict_find_int("block_ratelimit");
	if (val) sett.set_int(settings_pack::dht_block_ratelimit, int(val.int_value()));
	val = s.dict_find_int("read_only");
	if (val) sett.set_bool(settings_pack::dht_read_only, (val.int_value() != 0));
	val = s.dict_find_int("item_lifetime");
	if (val) sett.set_int(settings_pack::dht_item_lifetime, int(val.int_value()));
}

	std::vector<std::shared_ptr<listen_socket_t>>::iterator partition_listen_sockets(
		std::vector<listen_endpoint_t>& eps
		, std::vector<std::shared_ptr<listen_socket_t>>& sockets)
	{
		return std::partition(sockets.begin(), sockets.end()
			, [&eps](std::shared_ptr<listen_socket_t> const& sock)
		{
			auto match = std::find_if(eps.begin(), eps.end()
				, [&sock](listen_endpoint_t const& ep)
			{
				return ep.ssl == sock->ssl
					&& ep.port == sock->original_port
					&& ep.device == sock->device
					&& ep.flags == sock->flags
					&& ep.addr == sock->local_endpoint.address();
			});

			if (match != eps.end())
			{
				// remove the matched endpoint so that another socket can't match it
				// this also signals to the caller that it doesn't need to create a
				// socket for the endpoint
				eps.erase(match);
				return true;
			}
			else
			{
				return false;
			}
		});
	}

	// To comply with BEP 45 multi homed clients must run separate DHT nodes
	// on each interface they use to talk to the DHT. This is enforced
	// by prohibiting creating a listen socket on [::] and 0.0.0.0. Instead the list of
	// interfaces is enumerated and sockets are created for each of them.
	void expand_unspecified_address(span<ip_interface const> const ifs
		, span<ip_route const> const routes
		, std::vector<listen_endpoint_t>& eps)
	{
		auto unspecified_begin = std::partition(eps.begin(), eps.end()
			, [](listen_endpoint_t const& ep) { return !ep.addr.is_unspecified(); });
		std::vector<listen_endpoint_t> unspecified_eps(unspecified_begin, eps.end());
		eps.erase(unspecified_begin, eps.end());
		for (auto const& uep : unspecified_eps)
		{
			bool const v4 = uep.addr.is_v4();
			for (auto const& ipface : ifs)
			{
				if (!ipface.preferred)
					continue;
				if (ipface.interface_address.is_v4() != v4)
					continue;
				if (!uep.device.empty() && uep.device != ipface.name)
					continue;
				if (std::any_of(eps.begin(), eps.end(), [&](listen_endpoint_t const& e)
				{
					// ignore device name because we don't want to create
					// duplicates if the user explicitly configured an address
					// without a device name
					return e.addr == ipface.interface_address
						&& e.port == uep.port
						&& e.ssl == uep.ssl;
				}))
				{
					continue;
				}

				// ignore interfaces that are down
				if (ipface.state != if_state::up && ipface.state != if_state::unknown)
					continue;
				if (!(ipface.flags & if_flags::up))
					continue;

				// we assume this listen_socket_t is local-network under some
				// conditions, meaning we won't announce it to internet trackers
				bool const local
					= ipface.interface_address.is_loopback()
					|| is_link_local(ipface.interface_address)
					|| (ipface.flags & if_flags::loopback)
					|| (!is_global(ipface.interface_address)
						&& !(ipface.flags & if_flags::pointopoint)
						&& !has_internet_route(ipface.name, family(ipface.interface_address), routes));

				eps.emplace_back(ipface.interface_address, uep.port, uep.device
					, uep.ssl, uep.flags | listen_socket_t::was_expanded
					| (local ? listen_socket_t::local_network : listen_socket_flags_t{}));
			}
		}
	}

	void expand_devices(span<ip_interface const> const ifs
		, std::vector<listen_endpoint_t>& eps)
	{
		for (auto& ep : eps)
		{
			auto const iface = ep.device.empty()
				? std::find_if(ifs.begin(), ifs.end(), [&](ip_interface const& ipface)
					{
						return match_addr_mask(ipface.interface_address, ep.addr, ipface.netmask);
					})
				: std::find_if(ifs.begin(), ifs.end(), [&](ip_interface const& ipface)
					{
						return ipface.name == ep.device
							&& match_addr_mask(ipface.interface_address, ep.addr, ipface.netmask);
					});

			if (iface == ifs.end())
			{
				// we can't find which device this is for, just assume we can't
				// reach anything on it
				ep.netmask = build_netmask(0, ep.addr.is_v4() ? AF_INET : AF_INET6);
				continue;
			}

			ep.netmask = iface->netmask;
			ep.device = iface->name;
		}
	}

	bool listen_socket_t::can_route(address const& addr) const
	{
		// if this is a proxy, we assume it can reach everything
		if (flags & proxy) return true;

		if (is_v4(local_endpoint) != addr.is_v4()) return false;

		if (local_endpoint.address().is_v6()
			&& local_endpoint.address().to_v6().scope_id() != addr.to_v6().scope_id())
			return false;

		if (local_endpoint.address() == addr) return true;
		if (local_endpoint.address().is_unspecified()) return true;
		if (match_addr_mask(addr, local_endpoint.address(), netmask)) return true;
		return !(flags & local_network);
	}

	void session_impl::init_peer_class_filter(bool unlimited_local)
	{
		// set the default peer_class_filter to use the local peer class
		// for peers on local networks
		std::uint32_t lfilter = 1 << static_cast<std::uint32_t>(m_local_peer_class);
		std::uint32_t gfilter = 1 << static_cast<std::uint32_t>(m_global_class);

		struct class_mapping
		{
			char const* first;
			char const* last;
			std::uint32_t filter;
		};

		static const class_mapping v4_classes[] =
		{
			// everything
			{"0.0.0.0", "255.255.255.255", gfilter},
			// local networks
			{"10.0.0.0", "10.255.255.255", lfilter},
			{"172.16.0.0", "172.31.255.255", lfilter},
			{"192.168.0.0", "192.168.255.255", lfilter},
			// link-local
			{"169.254.0.0", "169.254.255.255", lfilter},
			// loop-back
			{"127.0.0.0", "127.255.255.255", lfilter},
		};

		static const class_mapping v6_classes[] =
		{
			// everything
			{"::0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", gfilter},
			// local networks
			{"fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", lfilter},
			// link-local
			{"fe80::", "febf::ffff:ffff:ffff:ffff:ffff:ffff:ffff", lfilter},
			// loop-back
			{"::1", "::1", lfilter},
		};

		class_mapping const* p = v4_classes;
		int len = sizeof(v4_classes) / sizeof(v4_classes[0]);
		if (!unlimited_local) len = 1;
		for (int i = 0; i < len; ++i)
		{
			error_code ec;
			address_v4 begin = make_address_v4(p[i].first, ec);
			address_v4 end = make_address_v4(p[i].last, ec);
			if (ec) continue;
			m_peer_class_filter.add_rule(begin, end, p[i].filter);
		}
		p = v6_classes;
		len = sizeof(v6_classes) / sizeof(v6_classes[0]);
		if (!unlimited_local) len = 1;
		for (int i = 0; i < len; ++i)
		{
			error_code ec;
			address_v6 begin = make_address_v6(p[i].first, ec);
			address_v6 end = make_address_v6(p[i].last, ec);
			if (ec) continue;
			m_peer_class_filter.add_rule(begin, end, p[i].filter);
		}
	}

	session_impl::session_impl(io_context& ioc, settings_pack const& pack
		, disk_io_constructor_type disk_io_constructor
		, session_flags_t const flags)
		: m_settings(pack)
		, m_io_context(ioc)
#if TORRENT_USE_SSL
		, m_ssl_ctx(ssl::context::tls_client)
#ifdef TORRENT_SSL_PEERS
		, m_peer_ssl_ctx(ssl::context::tls)
#endif
#endif // TORRENT_USE_SSL
		, m_alerts(m_settings.get_int(settings_pack::alert_queue_size)
			, alert_category_t{static_cast<unsigned int>(m_settings.get_int(settings_pack::alert_mask))})
		, m_disk_thread((disk_io_constructor ? disk_io_constructor : default_disk_io_constructor)
			(m_io_context, m_settings, m_stats_counters))
		, m_host_resolver(m_io_context)
		, m_work(make_work_guard(m_io_context))
		, m_created(clock_type::now())
		, m_last_tick(m_created)
		, m_last_second_tick(m_created - milliseconds(900))
		, m_utp_socket_manager(
			std::bind(&session_impl::send_udp_packet, this, _1, _2, _3, _4, _5)
			, [this](socket_type s) { this->incoming_connection(std::move(s)); }
			, m_io_context
			, m_settings, m_stats_counters, nullptr)
#ifdef TORRENT_SSL_PEERS
		, m_ssl_utp_socket_manager(
			std::bind(&session_impl::send_udp_packet, this, _1, _2, _3, _4, _5)
			, std::bind(&session_impl::on_incoming_utp_ssl, this, _1)
			, m_io_context
			, m_settings, m_stats_counters
			, &m_peer_ssl_ctx)
#endif
		, m_timer(m_io_context)
		, m_paused(flags & session::paused)
	{
	}

	template <typename Fun, typename... Args>
	void session_impl::wrap(Fun f, Args&&... a)
#ifndef BOOST_NO_EXCEPTIONS
	try
#endif
	{
		(this->*f)(std::forward<Args>(a)...);
	}
#ifndef BOOST_NO_EXCEPTIONS
	catch (system_error const& e) {
		alerts().emplace_alert<session_error_alert>(e.code(), e.what());
		pause();
	} catch (std::exception const& e) {
		alerts().emplace_alert<session_error_alert>(error_code(), e.what());
		pause();
	} catch (...) {
		alerts().emplace_alert<session_error_alert>(error_code(), "unknown error");
		pause();
	}
#endif

	// This function is called by the creating thread, not in the message loop's
	// io_context thread.
	// TODO: 2 is there a reason not to move all of this into init()? and just
	// post it to the io_context?
	void session_impl::start_session()
	{
#ifndef TORRENT_DISABLE_LOGGING
		session_log("start session");
#endif

		m_global_class = m_classes.new_peer_class("global");
		m_tcp_peer_class = m_classes.new_peer_class("tcp");
		m_local_peer_class = m_classes.new_peer_class("local");
		// local peers are always unchoked
		m_classes.at(m_local_peer_class)->ignore_unchoke_slots = true;
		// local peers are allowed to exceed the normal connection
		// limit by 50%
		m_classes.at(m_local_peer_class)->connection_limit_factor = 150;

		TORRENT_ASSERT(m_global_class == session::global_peer_class_id);
		TORRENT_ASSERT(m_tcp_peer_class == session::tcp_peer_class_id);
		TORRENT_ASSERT(m_local_peer_class == session::local_peer_class_id);

		init_peer_class_filter(true);

		// TCP, SSL/TCP and I2P connections should be assigned the TCP peer class
		m_peer_class_type_filter.add(peer_class_type_filter::tcp_socket, m_tcp_peer_class);
		m_peer_class_type_filter.add(peer_class_type_filter::ssl_tcp_socket, m_tcp_peer_class);

#ifndef TORRENT_DISABLE_LOGGING

		session_log("version: %s revision: %" PRIx64
			, lt::version_str, lt::version_revision);

#endif // TORRENT_DISABLE_LOGGING

		// ---- auto-cap max connections ----
		int const max_files = max_open_files();
		// deduct some margin for epoll/kqueue, log files,
		// futexes, shared objects etc.
		// 80% of the available file descriptors should go to connections
		m_settings.set_int(settings_pack::connections_limit, std::min(
			m_settings.get_int(settings_pack::connections_limit)
			, std::max(5, (max_files - 20) * 8 / 10)));
		// 20% goes towards regular files (see disk_io_thread)
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("max-connections: %d max-files: %d"
				, m_settings.get_int(settings_pack::connections_limit)
				, max_files);
		}
#endif

		post(m_io_context, [this] { wrap(&session_impl::init); });
	}

	void session_impl::init()
	{
		// this is a debug facility
		// see single_threaded in debug.hpp
		thread_started();

		TORRENT_ASSERT(is_single_thread());

#ifndef TORRENT_DISABLE_LOGGING
		session_log(" *** session thread init");
#endif

		// this is where we should set up all async operations. This
		// is called from within the network thread as opposed to the
		// constructor which is called from the main thread

#if defined TORRENT_ASIO_DEBUGGING
		async_inc_threads();
		add_outstanding_async("session_impl::on_tick");
#endif
		post(m_io_context, [this]{ wrap(&session_impl::on_tick, error_code()); });

#ifndef TORRENT_DISABLE_LOGGING
		session_log(" done starting session");
#endif
		// apply all m_settings to this session
		run_all_updates(*this);

		reopen_listen_sockets(false);

		start_communication();
	}

#if TORRENT_ABI_VERSION <= 2
	// TODO: 2 the ip filter should probably be saved here too
	void session_impl::save_state(entry* eptr, save_state_flags_t const flags) const
	{
		TORRENT_ASSERT(is_single_thread());

		entry& e = *eptr;
		// make it a dict
		e.dict();

		if (flags & session::save_settings)
		{
			entry::dictionary_type& sett = e["settings"].dict();
			save_settings_to_dict(non_default_settings(m_settings), sett);
		}

		if (flags & session::save_dht_settings)
		{
			e["dht"] = dht::save_dht_settings(get_dht_settings());
		}

		if (m_dht && (flags & session::save_dht_state))
		{
			e["dht state"] = dht::save_dht_state(m_dht->state());
		}

#ifndef TORRENT_DISABLE_EXTENSIONS
		for (auto const& ext : m_ses_extensions[plugins_all_idx])
		{
			ext->save_state(*eptr);
		}
#endif
	}

	void session_impl::load_state(bdecode_node const* e
		, save_state_flags_t const flags)
	{
		TORRENT_ASSERT(is_single_thread());

		bdecode_node settings;
		if (e->type() != bdecode_node::dict_t) return;

		bool need_update_dht = false;
		if (flags & session_handle::save_dht_state)
		{
			settings = e->dict_find_dict("dht state");
			if (settings)
			{
				m_dht_state = dht::read_dht_state(settings);
				need_update_dht = true;
			}
		}

#if TORRENT_ABI_VERSION == 1
		bool need_update_proxy = false;
		if (flags & session_handle::save_proxy)
		{
			settings = e->dict_find_dict("proxy");
			if (settings)
			{
				m_settings.bulk_set([&settings](session_settings_single_thread& s)
				{
					bdecode_node val;
					val = settings.dict_find_int("port");
					if (val) s.set_int(settings_pack::proxy_port, int(val.int_value()));
					val = settings.dict_find_int("type");
					if (val) s.set_int(settings_pack::proxy_type, int(val.int_value()));
					val = settings.dict_find_int("proxy_hostnames");
					if (val) s.set_bool(settings_pack::proxy_hostnames, val.int_value() != 0);
					val = settings.dict_find_string("hostname");
					if (val) s.set_str(settings_pack::proxy_hostname, std::string(val.string_value()));
					val = settings.dict_find_string("password");
					if (val) s.set_str(settings_pack::proxy_password, std::string(val.string_value()));
					val = settings.dict_find_string("username");
					if (val) s.set_str(settings_pack::proxy_username, std::string(val.string_value()));
				});
				need_update_proxy = true;
			}
		}

		settings = e->dict_find_dict("encryption");
		if (settings)
		{
			m_settings.bulk_set([&settings](session_settings_single_thread& s)
			{
				bdecode_node val;
				val = settings.dict_find_int("prefer_rc4");
				if (val) s.set_bool(settings_pack::prefer_rc4, val.int_value() != 0);
				val = settings.dict_find_int("out_enc_policy");
				if (val) s.set_int(settings_pack::out_enc_policy, int(val.int_value()));
				val = settings.dict_find_int("in_enc_policy");
				if (val) s.set_int(settings_pack::in_enc_policy, int(val.int_value()));
				val = settings.dict_find_int("allowed_enc_level");
				if (val) s.set_int(settings_pack::allowed_enc_level, int(val.int_value()));
			});
		}
#endif

		if ((flags & session_handle::save_settings)
			|| (flags & session_handle::save_dht_settings)
			)
		{
			settings = e->dict_find_dict("settings");
			if (settings)
			{
				// apply_settings_pack will update dht and proxy
				settings_pack pack = load_pack_from_dict(settings);

				// these settings are not loaded from state
				// they are set by the client software, not configured by users
				pack.clear(settings_pack::user_agent);
				pack.clear(settings_pack::peer_fingerprint);

				apply_settings_pack_impl(pack);
				need_update_dht = false;
#if TORRENT_ABI_VERSION == 1
				need_update_proxy = false;
#endif
			}
		}

		if (flags & session_handle::save_dht_settings)
		{
			// This is here for backwards compatibility, to support loading state
			// files in the previous file format, where the DHT settings were in
			// its own dictionary
			settings = e->dict_find_dict("dht");
			if (settings)
			{
				settings_pack sett;
				aux::apply_deprecated_dht_settings(sett, settings);
				apply_settings_pack_impl(sett);
			}
		}

		if (need_update_dht) start_dht();

#if TORRENT_ABI_VERSION == 1
		if (need_update_proxy) update_proxy();
#endif

#ifndef TORRENT_DISABLE_EXTENSIONS
		for (auto& ext : m_ses_extensions[plugins_all_idx])
		{
			ext->load_state(*e);
		}
#endif
	}
#endif

	session_params session_impl::session_state(save_state_flags_t const flags) const
	{
		TORRENT_ASSERT(is_single_thread());

		session_params ret;
		if (flags & session::save_settings)
			ret.settings = non_default_settings(m_settings);

#if TORRENT_ABI_VERSION <= 2
	if (flags & session_handle::save_dht_settings)
	{
		ret.dht_settings = get_dht_settings();
	}
#endif

		if (m_dht && (flags & session::save_dht_state))
			ret.dht_state = m_dht->state();

#ifndef TORRENT_DISABLE_EXTENSIONS
		if (flags & session::save_extension_state)
		{
			for (auto const& ext : m_ses_extensions[plugins_all_idx])
			{
				auto state = ext->save_state();
				for (auto& v : state)
					ret.ext_state[std::move(v.first)] = std::move(v.second);
			}
		}
#endif

		if ((flags & session::save_ip_filter) && m_ip_filter)
		{
			ret.ip_filter = *m_ip_filter;
		}
		return ret;
	}

	proxy_settings session_impl::proxy() const
	{
		return proxy_settings(m_settings);
	}

#ifndef TORRENT_DISABLE_EXTENSIONS

	void session_impl::add_extension(ext_function_t ext)
	{
		TORRENT_ASSERT(is_single_thread());
		TORRENT_ASSERT(ext);

		add_ses_extension(std::make_shared<session_plugin_wrapper>(ext));
	}

	void session_impl::add_ses_extension(std::shared_ptr<plugin> ext)
	{
		// this is called during startup of the session, from the thread creating
		// it, not its own thread
//		TORRENT_ASSERT(is_single_thread());
		TORRENT_ASSERT_VAL(ext, ext);

		feature_flags_t const features = ext->implemented_features();

		m_ses_extensions[plugins_all_idx].push_back(ext);

		if (features & plugin::tick_feature)
			m_ses_extensions[plugins_tick_idx].push_back(ext);
		if (features & plugin::dht_request_feature)
			m_ses_extensions[plugins_dht_request_idx].push_back(ext);
		if (features & plugin::alert_feature)
			m_alerts.add_extension(ext);
		session_handle h(shared_from_this());
		ext->added(h);
	}

#endif // TORRENT_DISABLE_EXTENSIONS

	void session_impl::abort() noexcept
	{
		TORRENT_ASSERT(is_single_thread());

		if (m_abort) return;
#ifndef TORRENT_DISABLE_LOGGING
		session_log(" *** ABORT CALLED ***");
#endif

		// at this point we cannot call the notify function anymore, since the
		// session will become invalid.
		m_alerts.set_notify_function({});

#ifndef TORRENT_DISABLE_EXTENSIONS
		for (auto& ext : m_ses_extensions[plugins_all_idx])
		{
			ext->abort();
		}
#endif

		// this will cancel requests that are not critical for shutting down
		// cleanly. i.e. essentially tracker hostname lookups that we're not
		// about to send event=stopped to
		m_host_resolver.abort();

		// abort the main thread
		m_abort = true;
		error_code ec;

		// we rely on on_tick() during shutdown, but we don't need to wait a
		// whole second for it to fire
		m_timer.cancel();

		stop_ip_notifier();
		stop_upnp();
		stop_natpmp();
		stop_dht();
		stop_communication();

		if(m_kvdb) {
			delete m_kvdb;
		}

		if (m_sqldb) {
			sqlite3_close_v2(m_sqldb);
			m_sqldb = nullptr;
		}

#ifdef TORRENT_SSL_PEERS
		for (auto const& s : m_incoming_sockets)
		{
			s->close(ec);
			TORRENT_ASSERT(!ec);
		}
		m_incoming_sockets.clear();
#endif

#ifndef TORRENT_DISABLE_LOGGING
		session_log(" aborting all tracker requests");
#endif

		// close the listen sockets
		for (auto const& l : m_listen_sockets)
		{
			if (l->sock)
			{
				l->sock->close(ec);
				TORRENT_ASSERT(!ec);
			}

			// TODO: 3 closing the udp sockets here means that
			// the uTP connections cannot be closed gracefully
			if (l->udp_sock)
			{
				l->udp_sock->sock.close();
			}
		}

		// we need to give all the sockets an opportunity to actually have their handlers
		// called and cancelled before we continue the shutdown. This is a bit
		// complicated, if there are no "undead" peers, it's safe to resume the
		// shutdown, but if there are, we have to wait for them to be cleared out
		// first. In session_impl::on_tick() we check them periodically. If we're
		// shutting down and we remove the last one, we'll initiate
		// shutdown_stage2 from there.
		if (m_undead_peers.empty())
		{
			post(m_io_context, make_handler([this] { abort_stage2(); }
				, m_abort_handler_storage, *this));
		}
	}

	void session_impl::abort_stage2() noexcept
	{
		// it's OK to detach the threads here. The disk_io_thread
		// has an internal counter and won't release the network
		// thread until they're all dead (via m_work).
		m_disk_thread->abort(false);

		// now it's OK for the network thread to exit
		m_work.reset();
	}

	void session_impl::set_port_filter(port_filter const& f)
	{
		m_port_filter = f;
		if (m_settings.get_bool(settings_pack::no_connect_privileged_ports))
			m_port_filter.add_rule(0, 1024, port_filter::blocked);
	}

	void session_impl::set_ip_filter(std::shared_ptr<ip_filter> f)
	{
		m_ip_filter = std::move(f);

	}

	void session_impl::ban_ip(address addr)
	{
		TORRENT_ASSERT(is_single_thread());
		if (!m_ip_filter) m_ip_filter = std::make_shared<ip_filter>();
		m_ip_filter->add_rule(addr, addr, ip_filter::blocked);
	}

	ip_filter const& session_impl::get_ip_filter()
	{
		TORRENT_ASSERT(is_single_thread());
		if (!m_ip_filter) m_ip_filter = std::make_shared<ip_filter>();
		return *m_ip_filter;
	}

	port_filter const& session_impl::get_port_filter() const
	{
		TORRENT_ASSERT(is_single_thread());
		return m_port_filter;
	}

	peer_class_t session_impl::create_peer_class(char const* name)
	{
		TORRENT_ASSERT(is_single_thread());
		return m_classes.new_peer_class(name);
	}

	void session_impl::delete_peer_class(peer_class_t const cid)
	{
		TORRENT_ASSERT(is_single_thread());
		// if you hit this assert, you're deleting a non-existent peer class
		TORRENT_ASSERT_PRECOND(m_classes.at(cid));
		if (m_classes.at(cid) == nullptr) return;
		m_classes.decref(cid);
	}

	peer_class_info session_impl::get_peer_class(peer_class_t const cid) const
	{
		peer_class_info ret{};
		peer_class const* pc = m_classes.at(cid);
		// if you hit this assert, you're passing in an invalid cid
		TORRENT_ASSERT_PRECOND(pc);
		if (pc == nullptr)
		{
			return ret;
		}

		pc->get_info(&ret);
		return ret;
	}

	void session_impl::set_peer_class(peer_class_t const cid, peer_class_info const& pci)
	{
		peer_class* pc = m_classes.at(cid);
		// if you hit this assert, you're passing in an invalid cid
		TORRENT_ASSERT_PRECOND(pc);
		if (pc == nullptr) return;

		pc->set_info(&pci);
	}

	void session_impl::set_peer_class_filter(ip_filter const& f)
	{
		m_peer_class_filter = f;
	}

	ip_filter const& session_impl::get_peer_class_filter() const
	{
		return m_peer_class_filter;
	}

	void session_impl::set_peer_class_type_filter(peer_class_type_filter f)
	{
		m_peer_class_type_filter = f;
	}

	peer_class_type_filter session_impl::get_peer_class_type_filter()
	{
		return m_peer_class_type_filter;
	}

	void session_impl::deferred_submit_jobs()
	{
		if (m_deferred_submit_disk_jobs) return;
		m_deferred_submit_disk_jobs = true;
		post(m_io_context, make_handler(
			[this] { wrap(&session_impl::submit_disk_jobs); }
			, m_submit_jobs_handler_storage, *this));
	}

	void session_impl::submit_disk_jobs()
	{
		TORRENT_ASSERT(m_deferred_submit_disk_jobs);
		m_deferred_submit_disk_jobs = false;
		m_disk_thread->submit_jobs();
	}

	// session_impl is responsible for deleting 'pack'
	void session_impl::apply_settings_pack(std::shared_ptr<settings_pack> pack)
	{
		apply_settings_pack_impl(*pack);
	}

	settings_pack session_impl::get_settings() const
	{
		settings_pack ret;
		// TODO: it would be nice to reserve() these vectors up front
		for (int i = settings_pack::string_type_base;
			i < settings_pack::max_string_setting_internal; ++i)
		{
			ret.set_str(i, m_settings.get_str(i));
		}
		for (int i = settings_pack::int_type_base;
			i < settings_pack::max_int_setting_internal; ++i)
		{
			ret.set_int(i, m_settings.get_int(i));
		}
		for (int i = settings_pack::bool_type_base;
			i < settings_pack::max_bool_setting_internal; ++i)
		{
			ret.set_bool(i, m_settings.get_bool(i));
		}
		return ret;
	}

namespace {
	template <typename Pack>
	int get_setting_impl(Pack const& p, int name, int*)
	{ return p.get_int(name); }

	template <typename Pack>
	bool get_setting_impl(Pack const& p, int name, bool*)
	{ return p.get_bool(name); }

	template <typename Pack>
	std::string get_setting_impl(Pack const& p, int name, std::string*)
	{ return p.get_str(name); }

	template <typename Type, typename Pack>
	Type get_setting(Pack const& p, int name)
	{
		return get_setting_impl(p, name, static_cast<Type*>(nullptr));
	}

	template <typename Type>
	bool setting_changed(settings_pack const& pack, aux::session_settings const& sett, int name)
	{
		return pack.has_val(name)
			&& get_setting<Type>(pack, name) != get_setting<Type>(sett, name);
	}
}

	void session_impl::apply_settings_pack_impl(settings_pack const& pack)
	{
		bool const reopen_listen_port
			= setting_changed<std::string>(pack, m_settings, settings_pack::listen_interfaces)
			|| setting_changed<int>(pack, m_settings, settings_pack::proxy_type)
#if TORRENT_ABI_VERSION == 1
			|| setting_changed<int>(pack, m_settings, settings_pack::ssl_listen)
#endif
			;

#ifndef TORRENT_DISABLE_LOGGING
		session_log("applying settings pack, reopen_listen_port=%s"
			, reopen_listen_port ? "true" : "false");
#endif

		apply_pack(&pack, m_settings, this);
		m_disk_thread->settings_updated();

		if (!reopen_listen_port)
		{
			// no need to call this if reopen_listen_port is true
			// since the apply_pack will do it
			update_listen_interfaces();
		}
		else
		{
			reopen_listen_sockets();
		}

	}

	std::shared_ptr<listen_socket_t> session_impl::setup_listener(
		listen_endpoint_t const& lep, error_code& ec)
	{
		int retries = m_settings.get_int(settings_pack::max_retry_port_bind);
		tcp::endpoint bind_ep(lep.addr, std::uint16_t(lep.port));

#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("attempting to open listen socket to: %s on device: %s %s%s%s%s%s"
				, print_endpoint(bind_ep).c_str(), lep.device.c_str()
				, (lep.ssl == transport::ssl) ? "ssl " : ""
				, (lep.flags & listen_socket_t::local_network) ? "local-network " : ""
				, (lep.flags & listen_socket_t::accept_incoming) ? "accept-incoming " : "no-incoming "
				, (lep.flags & listen_socket_t::was_expanded) ? "expanded-ip " : ""
				, (lep.flags & listen_socket_t::proxy) ? "proxy " : "");
		}
#endif

		auto ret = std::make_shared<listen_socket_t>();
		ret->ssl = lep.ssl;
		ret->original_port = bind_ep.port();
		ret->flags = lep.flags;
		ret->netmask = lep.netmask;
		operation_t last_op = operation_t::unknown;
		socket_type_t const sock_type
			= (lep.ssl == transport::ssl)
			? socket_type_t::tcp_ssl
			: socket_type_t::tcp;

		// if we're in force-proxy mode, don't open TCP listen sockets. We cannot
		// accept connections on our local machine in this case.
		// TODO: 3 the logic in this if-block should be factored out into a
		// separate function. At least most of it
		if (ret->flags & listen_socket_t::accept_incoming)
		{
			ret->sock = std::make_shared<tcp::acceptor>(m_io_context);
			ret->sock->open(bind_ep.protocol(), ec);
			last_op = operation_t::sock_open;
			if (ec)
			{
#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("failed to open socket: %s"
						, ec.message().c_str());
				}
#endif

				if (m_alerts.should_post<listen_failed_alert>())
					m_alerts.emplace_alert<listen_failed_alert>(lep.device, bind_ep, last_op
						, ec, sock_type);
				return ret;
			}

#ifdef TORRENT_WINDOWS
			{
				// this is best-effort. ignore errors
				error_code err;
				ret->sock->set_option(exclusive_address_use(true), err);
#ifndef TORRENT_DISABLE_LOGGING
				if (err && should_log())
				{
					session_log("failed enable exclusive address use on listen socket: %s"
						, err.message().c_str());
				}
#endif // TORRENT_DISABLE_LOGGING
			}
#else

			{
				// this is best-effort. ignore errors
				error_code err;
				ret->sock->set_option(tcp::acceptor::reuse_address(true), err);
#ifndef TORRENT_DISABLE_LOGGING
				if (err && should_log())
				{
					session_log("failed enable reuse-address on listen socket: %s"
						, err.message().c_str());
				}
#endif // TORRENT_DISABLE_LOGGING
			}
#endif // TORRENT_WINDOWS

			if (is_v6(bind_ep))
			{
				error_code err; // ignore errors here
				ret->sock->set_option(boost::asio::ip::v6_only(true), err);
#ifndef TORRENT_DISABLE_LOGGING
				if (err && should_log())
				{
					session_log("failed enable v6 only on listen socket: %s"
						, err.message().c_str());
				}
#endif // LOGGING

#ifdef TORRENT_WINDOWS
				// enable Teredo on windows
				ret->sock->set_option(v6_protection_level(PROTECTION_LEVEL_UNRESTRICTED), err);
#ifndef TORRENT_DISABLE_LOGGING
				if (err && should_log())
				{
					session_log("failed enable IPv6 unrestricted protection level on "
						"listen socket: %s", err.message().c_str());
				}
#endif // TORRENT_DISABLE_LOGGING
#endif // TORRENT_WINDOWS
			}

			if (!lep.device.empty())
			{
				// we have an actual device we're interested in listening on, if we
				// have SO_BINDTODEVICE functionality, use it now.
#if TORRENT_HAS_BINDTODEVICE
				bind_device(*ret->sock, lep.device.c_str(), ec);
#ifndef TORRENT_DISABLE_LOGGING
				if (ec && should_log())
				{
					session_log("bind to device failed (device: %s): %s"
						, lep.device.c_str(), ec.message().c_str());
				}
#endif // TORRENT_DISABLE_LOGGING
				ec.clear();
#endif // TORRENT_HAS_BINDTODEVICE
			}

			ret->sock->bind(bind_ep, ec);
			last_op = operation_t::sock_bind;

			while (ec == error_code(error::address_in_use) && retries > 0)
			{
				TORRENT_ASSERT_VAL(ec, ec);
#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("failed to bind listen socket to: %s on device: %s :"
						" [%s] (%d) %s (retries: %d)"
						, print_endpoint(bind_ep).c_str()
						, lep.device.c_str()
						, ec.category().name(), ec.value(), ec.message().c_str()
						, retries);
				}
#endif
				ec.clear();
				--retries;
				bind_ep.port(bind_ep.port() + 1);
				ret->sock->bind(bind_ep, ec);
			}

			if (ec == error_code(error::address_in_use)
				&& m_settings.get_bool(settings_pack::listen_system_port_fallback)
				&& bind_ep.port() != 0)
			{
				// instead of giving up, try let the OS pick a port
				bind_ep.port(0);
				ec.clear();
				ret->sock->bind(bind_ep, ec);
				last_op = operation_t::sock_bind;
			}

			if (ec)
			{
				// not even that worked, give up

#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("failed to bind listen socket to: %s on device: %s :"
						" [%s] (%d) %s (giving up)"
						, print_endpoint(bind_ep).c_str()
						, lep.device.c_str()
						, ec.category().name(), ec.value(), ec.message().c_str());
				}
#endif
				if (m_alerts.should_post<listen_failed_alert>())
				{
					m_alerts.emplace_alert<listen_failed_alert>(lep.device, bind_ep
						, last_op, ec, sock_type);
				}
				ret->sock.reset();
				return ret;
			}
			ret->local_endpoint = ret->sock->local_endpoint(ec);
			last_op = operation_t::getname;
			if (ec)
			{
#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("get_sockname failed on listen socket: %s"
						, ec.message().c_str());
				}
#endif
				if (m_alerts.should_post<listen_failed_alert>())
				{
					m_alerts.emplace_alert<listen_failed_alert>(lep.device, bind_ep
						, last_op, ec, sock_type);
				}
				return ret;
			}

			TORRENT_ASSERT(ret->local_endpoint.port() == bind_ep.port()
				|| bind_ep.port() == 0);

			if (bind_ep.port() == 0) bind_ep = ret->local_endpoint;

			ret->sock->listen(m_settings.get_int(settings_pack::listen_queue_size), ec);
			last_op = operation_t::sock_listen;

			if (ec)
			{
#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("cannot listen on interface \"%s\": %s"
						, lep.device.c_str(), ec.message().c_str());
				}
#endif
				if (m_alerts.should_post<listen_failed_alert>())
				{
					m_alerts.emplace_alert<listen_failed_alert>(lep.device, bind_ep
						, last_op, ec, sock_type);
				}
				return ret;
			}
		} // accept incoming

		socket_type_t const udp_sock_type
			= (lep.ssl == transport::ssl)
			? socket_type_t::utp_ssl
			: socket_type_t::utp;
		udp::endpoint udp_bind_ep(bind_ep.address(), bind_ep.port());

		ret->udp_sock = std::make_shared<session_udp_socket>(m_io_context, ret);
		ret->udp_sock->sock.open(udp_bind_ep.protocol(), ec);
		if (ec)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("failed to open UDP socket: %s: %s"
					, lep.device.c_str(), ec.message().c_str());
			}
#endif

			last_op = operation_t::sock_open;
			if (m_alerts.should_post<listen_failed_alert>())
				m_alerts.emplace_alert<listen_failed_alert>(lep.device
					, bind_ep, last_op, ec, udp_sock_type);

			return ret;
		}

#if TORRENT_HAS_BINDTODEVICE
		if (!lep.device.empty())
		{
			bind_device(ret->udp_sock->sock, lep.device.c_str(), ec);
#ifndef TORRENT_DISABLE_LOGGING
			if (ec && should_log())
			{
				session_log("bind to device failed (device: %s): %s"
					, lep.device.c_str(), ec.message().c_str());
			}
#endif // TORRENT_DISABLE_LOGGING
			ec.clear();
		}
#endif
		ret->udp_sock->sock.bind(udp_bind_ep, ec);

		while (ec == error_code(error::address_in_use) && retries > 0)
		{
			TORRENT_ASSERT_VAL(ec, ec);
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("failed to bind udp socket to: %s on device: %s :"
					" [%s] (%d) %s (retries: %d)"
					, print_endpoint(bind_ep).c_str()
					, lep.device.c_str()
					, ec.category().name(), ec.value(), ec.message().c_str()
					, retries);
			}
#endif
			ec.clear();
			--retries;
			udp_bind_ep.port(udp_bind_ep.port() + 1);
			ret->udp_sock->sock.bind(udp_bind_ep, ec);
		}

		if (ec == error_code(error::address_in_use)
			&& m_settings.get_bool(settings_pack::listen_system_port_fallback)
			&& udp_bind_ep.port() != 0)
		{
			// instead of giving up, try let the OS pick a port
			udp_bind_ep.port(0);
			ec.clear();
			ret->udp_sock->sock.bind(udp_bind_ep, ec);
		}

		last_op = operation_t::sock_bind;
		if (ec)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("failed to bind UDP socket: %s: %s"
					, lep.device.c_str(), ec.message().c_str());
			}
#endif

			if (m_alerts.should_post<listen_failed_alert>())
				m_alerts.emplace_alert<listen_failed_alert>(lep.device
					, bind_ep, last_op, ec, udp_sock_type);

			return ret;
		}

		// if we did not open a TCP listen socket, ret->local_endpoint was never
		// initialized, so do that now, based on the UDP socket
		if (!(ret->flags & listen_socket_t::accept_incoming))
		{
			auto const udp_ep = ret->udp_sock->local_endpoint();
			ret->local_endpoint = tcp::endpoint(udp_ep.address(), udp_ep.port());
		}

		ret->device = lep.device;

		error_code err;
		set_socket_buffer_size(ret->udp_sock->sock, m_settings, err);
		if (err)
		{
			if (m_alerts.should_post<udp_error_alert>())
				m_alerts.emplace_alert<udp_error_alert>(ret->udp_sock->sock.local_endpoint(ec)
					, operation_t::alloc_recvbuf, err);
		}

		// this call is necessary here because, unless the settings actually
		// change after the session is up and listening, at no other point
		// set_proxy_settings is called with the correct proxy configuration,
		// internally, this method handle the SOCKS5's connection logic
		ret->udp_sock->sock.set_proxy_settings(proxy(), m_alerts);

		ADD_OUTSTANDING_ASYNC("session_impl::on_udp_packet");
		ret->udp_sock->sock.async_read(aux::make_handler([this, ret](error_code const& e)
			{ this->on_udp_packet(ret->udp_sock, ret, ret->ssl, e); }
			, ret->udp_handler_storage, *this));

#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log(" listening on: %s TCP port: %d UDP port: %d"
				, bind_ep.address().to_string().c_str()
				, ret->tcp_external_port(), ret->udp_external_port());
		}
#endif
		return ret;
	}

	void session_impl::on_exception(std::exception const& e)
	{
		TORRENT_UNUSED(e);
#ifndef TORRENT_DISABLE_LOGGING
		session_log("FATAL SESSION ERROR [%s]", e.what());
#endif
		this->abort();
	}

	void session_impl::on_error(error_code const& ec)
	{
		TORRENT_UNUSED(ec);
#ifndef TORRENT_DISABLE_LOGGING
		session_log("FATAL SESSION ERROR (%s : %d) [%s]"
			, ec.category().name(), ec.value(), ec.message().c_str());
#endif
		this->abort();
	}

	void session_impl::on_ip_change(error_code const& ec)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (!ec)
			session_log("received ip change from internal ip_notifier");
		else
			session_log("received error on_ip_change: %d, %s", ec.value(), ec.message().c_str());
#endif
		if (ec || m_abort || !m_ip_notifier) return;
		m_ip_notifier->async_wait([this] (error_code const& e)
			{ wrap(&session_impl::on_ip_change, e); });
		reopen_network_sockets({});
	}

	// TODO: could this function be merged with expand_unspecified_addresses?
	// right now both listen_endpoint_t and listen_interface_t are almost
	// identical, maybe the latter could be removed too
	void interface_to_endpoints(listen_interface_t const& iface
		, listen_socket_flags_t flags
		, span<ip_interface const> const ifs
		, std::vector<listen_endpoint_t>& eps)
	{
		flags |= iface.local ? listen_socket_t::local_network : listen_socket_flags_t{};
		transport const ssl = iface.ssl ? transport::ssl : transport::plaintext;

		// First, check to see if it's an IP address
		error_code err;
		address const adr = make_address(iface.device.c_str(), err);
		if (!err)
		{
			eps.emplace_back(adr, iface.port, std::string{}, ssl, flags);
		}
		else
		{
			flags |= listen_socket_t::was_expanded;

			// this is the case where device names a network device. We need to
			// enumerate all IPs associated with this device
			for (auto const& ipface : ifs)
			{
				// we're looking for a specific interface, and its address
				// (which must be of the same family as the address we're
				// connecting to)
				if (iface.device != ipface.name) continue;

				bool const local = iface.local
					|| ipface.interface_address.is_loopback()
					|| is_link_local(ipface.interface_address);

				eps.emplace_back(ipface.interface_address, iface.port, iface.device
					, ssl, flags | (local ? listen_socket_t::local_network : listen_socket_flags_t{}));
			}
		}
	}

	void session_impl::reopen_listen_sockets(bool const map_ports)
	{
#ifndef TORRENT_DISABLE_LOGGING
		session_log("reopen listen sockets");
#endif

		TORRENT_ASSERT(is_single_thread());

		TORRENT_ASSERT(!m_abort);

		error_code ec;

		if (m_abort) return;

		// first build a list of endpoints we should be listening on
		// we need to remove any unneeded sockets first to avoid the possibility
		// of a new socket failing to bind due to a conflict with a stale socket
		std::vector<listen_endpoint_t> eps;

		// if we don't proxy peer connections, don't apply the special logic for
		// proxies
		if (m_settings.get_int(settings_pack::proxy_type) != settings_pack::none)
		{
			// we will be able to accept incoming connections over UDP. so use
			// one of the ports the user specified to use a consistent port
			// across sessions. If the user did not specify any ports, pick one
			// at random
			int const port = m_listen_interfaces.empty()
				? int(random(63000) + 2000)
				: m_listen_interfaces.front().port;
			listen_endpoint_t ep(address_v4::any(), port, {}
				, transport::plaintext, listen_socket_t::proxy);
			eps.emplace_back(ep);
		}
		else
		{
			std::vector<ip_interface> const ifs = enum_net_interfaces(m_io_context, ec);
			if (ec && m_alerts.should_post<listen_failed_alert>())
			{
				m_alerts.emplace_alert<listen_failed_alert>(""
					, operation_t::enum_if, ec, socket_type_t::tcp);
			}
			auto const routes = enum_routes(m_io_context, ec);
			if (ec && m_alerts.should_post<listen_failed_alert>())
			{
				m_alerts.emplace_alert<listen_failed_alert>(""
					, operation_t::enum_route, ec, socket_type_t::tcp);
			}

			// expand device names and populate eps
			for (auto const& iface : m_listen_interfaces)
			{
#if !TORRENT_USE_SSL
				if (iface.ssl)
				{
#ifndef TORRENT_DISABLE_LOGGING
					session_log("attempted to listen ssl with no library support on device: \"%s\""
						, iface.device.c_str());
#endif
					if (m_alerts.should_post<listen_failed_alert>())
					{
						m_alerts.emplace_alert<listen_failed_alert>(iface.device
							, operation_t::sock_open
							, boost::asio::error::operation_not_supported
							, socket_type_t::tcp_ssl);
					}
					continue;
				}
#endif

				// now we have a device to bind to. This device may actually just be an
				// IP address or a device name. In case it's a device name, we want to
				// (potentially) end up binding a socket for each IP address associated
				// with that device.
				interface_to_endpoints(iface, listen_socket_t::accept_incoming, ifs, eps);
			}

			if (eps.empty())
			{
#ifndef TORRENT_DISABLE_LOGGING
				session_log("no listen sockets");
#endif
			}

			expand_unspecified_address(ifs, routes, eps);
			expand_devices(ifs, eps);
		}

		auto remove_iter = partition_listen_sockets(eps, m_listen_sockets);

		while (remove_iter != m_listen_sockets.end())
		{
			if (m_dht)
				m_dht->delete_socket(*remove_iter);

#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("closing listen socket for %s on device \"%s\""
					, print_endpoint((*remove_iter)->local_endpoint).c_str()
					, (*remove_iter)->device.c_str());
			}
#endif
			if ((*remove_iter)->sock) (*remove_iter)->sock->close(ec);
			if ((*remove_iter)->udp_sock) (*remove_iter)->udp_sock->sock.close();
			if ((*remove_iter)->natpmp_mapper) (*remove_iter)->natpmp_mapper->close();
			if ((*remove_iter)->upnp_mapper) (*remove_iter)->upnp_mapper->close();
			remove_iter = m_listen_sockets.erase(remove_iter);
		}

		// all sockets in there stayed the same. Only sockets after this point are
		// new and should post alerts
		int const existing_sockets = int(m_listen_sockets.size());

		m_stats_counters.set_value(counters::has_incoming_connections
			, std::any_of(m_listen_sockets.begin(), m_listen_sockets.end()
				, [](std::shared_ptr<listen_socket_t> const& l)
				{ return l->incoming_connection; }));

		// open new sockets on any endpoints that didn't match with
		// an existing socket
		for (auto const& ep : eps)
#ifndef BOOST_NO_EXCEPTIONS
			try
#endif
		{
			std::shared_ptr<listen_socket_t> s = setup_listener(ep, ec);

			if (!ec && (s->sock || s->udp_sock))
			{
				m_listen_sockets.emplace_back(s);

				if (m_dht
					&& s->ssl != transport::ssl
					&& !(s->flags & listen_socket_t::local_network))
				{
					m_dht->new_socket(m_listen_sockets.back());
				}

				TORRENT_ASSERT(bool(s->flags & listen_socket_t::accept_incoming) == bool(s->sock));
				if (s->sock) async_accept(s->sock, s->ssl);
			}
		}
#ifndef BOOST_NO_EXCEPTIONS
		catch (std::exception const& e)
		{
			TORRENT_UNUSED(e);
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("setup_listener(%s) device: %s failed: %s"
					, print_endpoint(ep.addr, ep.port).c_str()
					, ep.device.c_str()
					, e.what());
			}
#endif // TORRENT_DISABLE_LOGGING
		}
#endif // BOOST_NO_EXCEPTIONS

		if (m_listen_sockets.empty())
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log("giving up on binding listen sockets");
#endif
			return;
		}

		auto const new_sockets = span<std::shared_ptr<listen_socket_t>>(
			m_listen_sockets).subspan(existing_sockets);

		// now, send out listen_succeeded_alert for the listen sockets we are
		// listening on
		if (m_alerts.should_post<listen_succeeded_alert>())
		{
			for (auto const& l : new_sockets)
			{
				error_code err;
				if (l->sock)
				{
					tcp::endpoint const tcp_ep = l->sock->local_endpoint(err);
					if (!err)
					{
						socket_type_t const socket_type
							= l->ssl == transport::ssl
							? socket_type_t::tcp_ssl
							: socket_type_t::tcp;

						m_alerts.emplace_alert<listen_succeeded_alert>(
							tcp_ep, socket_type);
					}
				}

				if (l->udp_sock)
				{
					udp::endpoint const udp_ep = l->udp_sock->sock.local_endpoint(err);
					if (!err && l->udp_sock->sock.is_open())
					{
						socket_type_t const socket_type
							= l->ssl == transport::ssl
							? socket_type_t::utp_ssl
							: socket_type_t::utp;

						m_alerts.emplace_alert<listen_succeeded_alert>(
							udp_ep, socket_type);
					}
				}
			}
		}

		if (m_settings.get_int(settings_pack::peer_tos) != 0)
		{
			update_peer_tos();
		}

		ec.clear();

		if (m_settings.get_bool(settings_pack::enable_natpmp))
		{
			for (auto const& s : new_sockets)
				start_natpmp(s);
		}

		if (m_settings.get_bool(settings_pack::enable_upnp))
		{
			for (auto const& s : new_sockets)
				start_upnp(s);
		}

		if (map_ports)
		{
			for (auto const& s : m_listen_sockets)
				remap_ports(remap_natpmp_and_upnp, *s);
		}
		else
		{
			// new sockets need to map ports even if the caller did not request
			// re-mapping
			for (auto const& s : new_sockets)
				remap_ports(remap_natpmp_and_upnp, *s);
		}
	}

	void session_impl::reopen_network_sockets(reopen_network_flags_t const options)
	{
		reopen_listen_sockets(bool(options & session_handle::reopen_map_ports));
	}

	namespace {
		template <typename MapProtocol, typename ProtoType, typename EndpointType>
		void map_port(MapProtocol& m, ProtoType protocol, EndpointType const& ep
			, port_mapping_t& map_handle)
		{
			if (map_handle != port_mapping_t{-1}) m.delete_mapping(map_handle);
			map_handle = port_mapping_t{-1};

			address const addr = ep.address();
			// with IPv4 the interface might be behind NAT so we can't skip them
			// based on the scope of the local address
			if (addr.is_v6() && is_local(addr))
				return;

			// only update this mapping if we actually have a socket listening
			if (ep != EndpointType())
				map_handle = m.add_mapping(protocol, ep.port(), ep);
		}
	}

	void session_impl::remap_ports(remap_port_mask_t const mask
		, listen_socket_t& s)
	{
		tcp::endpoint const tcp_ep = s.sock ? s.sock->local_endpoint() : tcp::endpoint();
		udp::endpoint const udp_ep = s.udp_sock ? s.udp_sock->sock.local_endpoint() : udp::endpoint();

		if ((mask & remap_natpmp) && s.natpmp_mapper)
		{
			map_port(*s.natpmp_mapper, portmap_protocol::tcp, tcp_ep
				, s.tcp_port_mapping[portmap_transport::natpmp].mapping);
			map_port(*s.natpmp_mapper, portmap_protocol::udp, make_tcp(udp_ep)
				, s.udp_port_mapping[portmap_transport::natpmp].mapping);
		}
		if ((mask & remap_upnp) && s.upnp_mapper)
		{
			map_port(*s.upnp_mapper, portmap_protocol::tcp, tcp_ep
				, s.tcp_port_mapping[portmap_transport::upnp].mapping);
			map_port(*s.upnp_mapper, portmap_protocol::udp, make_tcp(udp_ep)
				, s.udp_port_mapping[portmap_transport::upnp].mapping);
		}
	}

	int session_impl::external_udp_port(address const& local_address) const
	{
		auto ls = std::find_if(m_listen_sockets.begin(), m_listen_sockets.end()
			, [&](std::shared_ptr<listen_socket_t> const& e)
		{
			return e->local_endpoint.address() == local_address;
		});

		if (ls != m_listen_sockets.end())
			return (*ls)->udp_external_port();
		else
			return -1;
	}

	void session_impl::send_udp_packet_hostname(std::weak_ptr<utp_socket_interface> sock
		, char const* hostname
		, int const port
		, span<char const> p
		, error_code& ec
		, udp_send_flags_t const flags)
	{
		auto si = sock.lock();
		if (!si)
		{
			ec = boost::asio::error::bad_descriptor;
			return;
		}

		auto s = std::static_pointer_cast<aux::listen_socket_t>(si)->udp_sock;

		s->sock.send_hostname(hostname, port, p, ec, flags);

		if ((ec == error::would_block || ec == error::try_again)
			&& !s->write_blocked)
		{
			s->write_blocked = true;
			ADD_OUTSTANDING_ASYNC("session_impl::on_udp_writeable");
			s->sock.async_write(std::bind(&session_impl::on_udp_writeable
				, this, s, _1));
		}
	}

	void session_impl::send_udp_packet(std::weak_ptr<utp_socket_interface> sock
		, udp::endpoint const& ep
		, span<char const> p
		, error_code& ec
		, udp_send_flags_t const flags)
	{
		auto si = sock.lock();
		if (!si)
		{
			ec = boost::asio::error::bad_descriptor;
			return;
		}

		auto s = std::static_pointer_cast<aux::listen_socket_t>(si)->udp_sock;

		TORRENT_ASSERT(s->sock.is_closed() || s->sock.local_endpoint().protocol() == ep.protocol());

		s->sock.send(ep, p, ec, flags);

		if ((ec == error::would_block || ec == error::try_again) && !s->write_blocked)
		{
			s->write_blocked = true;
			ADD_OUTSTANDING_ASYNC("session_impl::on_udp_writeable");
			s->sock.async_write(std::bind(&session_impl::on_udp_writeable
				, this, s, _1));
		}
	}

	void session_impl::on_udp_writeable(std::weak_ptr<session_udp_socket> sock, error_code const& ec)
	{
		COMPLETE_ASYNC("session_impl::on_udp_writeable");
		if (ec) return;

		auto s = sock.lock();
		if (!s) return;

		s->write_blocked = false;

#ifdef TORRENT_SSL_PEERS
		auto i = std::find_if(
			m_listen_sockets.begin(), m_listen_sockets.end()
			, [&s] (std::shared_ptr<listen_socket_t> const& ls) { return ls->udp_sock == s; });
#endif

		// notify the utp socket manager it can start sending on the socket again
		struct utp_socket_manager& mgr =
#ifdef TORRENT_SSL_PEERS
			(i != m_listen_sockets.end() && (*i)->ssl == transport::ssl) ? m_ssl_utp_socket_manager :
#endif
			m_utp_socket_manager;

		mgr.writable();
	}


	void session_impl::on_udp_packet(std::weak_ptr<session_udp_socket> socket
		, std::weak_ptr<listen_socket_t> ls, transport const ssl, error_code const& ec)
	{
		COMPLETE_ASYNC("session_impl::on_udp_packet");
		if (ec)
		{
			std::shared_ptr<session_udp_socket> s = socket.lock();
			udp::endpoint ep;
			if (s) ep = s->local_endpoint();

			// don't bubble up operation aborted errors to the user
			if (ec != boost::asio::error::operation_aborted
				&& ec != boost::asio::error::bad_descriptor
				&& m_alerts.should_post<udp_error_alert>())
			{
				m_alerts.emplace_alert<udp_error_alert>(ep
					, operation_t::sock_read, ec);
			}

#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("UDP error: %s (%d) %s"
					, print_endpoint(ep).c_str(), ec.value(), ec.message().c_str());
			}
#endif
			return;
		}

		m_stats_counters.inc_stats_counter(counters::on_udp_counter);

		std::shared_ptr<session_udp_socket> s = socket.lock();
		if (!s) return;

		struct utp_socket_manager& mgr =
#ifdef TORRENT_SSL_PEERS
			ssl == transport::ssl ? m_ssl_utp_socket_manager :
#endif
			m_utp_socket_manager;

		for (;;)
		{
			aux::array<udp_socket::packet, 50> p;
			error_code err;
			int const num_packets = s->sock.read(p, err);

			for (udp_socket::packet& packet : span<udp_socket::packet>(p).first(num_packets))
			{
				if (packet.error)
				{
					// TODO: 3 it would be neat if the utp socket manager would
					// handle ICMP errors too

					if (m_dht)
						m_dht->incoming_error(packet.error, packet.from);

				}

				span<char const> const buf = packet.data;

				// give the uTP socket manager first dibs on the packet. Presumably
				// the majority of packets are uTP packets.
				if (!mgr.incoming_packet(ls, packet.from, buf))
				{
					// if it wasn't a uTP packet, try the other users of the UDP
					// socket
					auto listen_socket = ls.lock();
					if (m_dht && buf.size() > 20
						&& buf.front() == 'd'
						&& buf.back() == 'e'
						&& listen_socket)
					{
						m_dht->incoming_packet(listen_socket, packet.from, buf);
					}
				}
			}

			if (err == error::would_block || err == error::try_again)
			{
				// there are no more packets on the socket
				break;
			}

			if (err)
			{
				udp::endpoint const ep = s->local_endpoint();

				if (err != boost::asio::error::operation_aborted
					&& m_alerts.should_post<udp_error_alert>())
					m_alerts.emplace_alert<udp_error_alert>(ep
						, operation_t::sock_read, err);

#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("UDP error: %s (%d) %s"
						, print_endpoint(ep).c_str(), ec.value(), ec.message().c_str());
				}
#endif

				// any error other than these ones are considered fatal errors, and
				// we won't read from the socket again
				if (err != boost::asio::error::host_unreachable
					&& err != boost::asio::error::fault
					&& err != boost::asio::error::connection_reset
					&& err != boost::asio::error::connection_refused
					&& err != boost::asio::error::connection_aborted
					&& err != boost::asio::error::operation_aborted
					&& err != boost::asio::error::network_reset
					&& err != boost::asio::error::network_unreachable
#ifdef _WIN32
					// ERROR_MORE_DATA means the same thing as EMSGSIZE
					&& err != error_code(ERROR_MORE_DATA, system_category())
					&& err != error_code(ERROR_HOST_UNREACHABLE, system_category())
					&& err != error_code(ERROR_PORT_UNREACHABLE, system_category())
					&& err != error_code(ERROR_RETRY, system_category())
					&& err != error_code(ERROR_NETWORK_UNREACHABLE, system_category())
					&& err != error_code(ERROR_CONNECTION_REFUSED, system_category())
					&& err != error_code(ERROR_CONNECTION_ABORTED, system_category())
#endif
					&& err != boost::asio::error::message_size)
				{
					// fatal errors. Don't try to read from this socket again
					mgr.socket_drained();
					return;
				}
				// non-fatal UDP errors get here, we should re-issue the read.
				continue;
			}
		}

		mgr.socket_drained();

		ADD_OUTSTANDING_ASYNC("session_impl::on_udp_packet");
		s->sock.async_read(make_handler([this, socket, ls, ssl](error_code const& e)
			{ this->on_udp_packet(std::move(socket), std::move(ls), ssl, e); }
			, s->udp_handler_storage, *this));
	}

	void session_impl::async_accept(std::shared_ptr<tcp::acceptor> const& listener
		, transport const ssl)
#ifndef BOOST_NO_EXCEPTIONS
	try
#endif
	{
		TORRENT_ASSERT(!m_abort);

		std::weak_ptr<tcp::acceptor> ls(listener);
		m_stats_counters.inc_stats_counter(counters::num_outstanding_accept);
		ADD_OUTSTANDING_ASYNC("session_impl::on_accept_connection");
		listener->async_accept([this, ls, ssl] (error_code const& ec, true_tcp_socket s)
			{ return wrap(&session_impl::on_accept_connection, std::move(s), ec, ls, ssl); });
	}
#ifndef BOOST_NO_EXCEPTIONS
	catch (system_error const& e) {
		alerts().emplace_alert<session_error_alert>(e.code(), e.what());
		pause();
	} catch (std::exception const& e) {
		alerts().emplace_alert<session_error_alert>(error_code(), e.what());
		pause();
	} catch (...) {
		alerts().emplace_alert<session_error_alert>(error_code(), "unknown error");
		pause();
	}
#endif

	void session_impl::on_accept_connection(true_tcp_socket s, error_code const& e
		, std::weak_ptr<tcp::acceptor> listen_socket, transport const ssl)
	{
		COMPLETE_ASYNC("session_impl::on_accept_connection");
		m_stats_counters.inc_stats_counter(counters::on_accept_counter);
		m_stats_counters.inc_stats_counter(counters::num_outstanding_accept, -1);

		TORRENT_ASSERT(is_single_thread());
		std::shared_ptr<tcp::acceptor> listener = listen_socket.lock();
		if (!listener) return;

		if (e == boost::asio::error::operation_aborted) return;

		if (m_abort) return;

		error_code ec;
		if (e)
		{
			tcp::endpoint const ep = listener->local_endpoint(ec);
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("error accepting connection on '%s': %s"
					, print_endpoint(ep).c_str(), e.message().c_str());
			}
#endif
#ifdef TORRENT_WINDOWS
			// Windows sometimes generates this error. It seems to be
			// non-fatal and we have to do another async_accept.
			if (e.value() == ERROR_SEM_TIMEOUT)
			{
				async_accept(listener, ssl);
				return;
			}
#endif
#ifdef TORRENT_BSD
			// Leopard sometimes generates an "invalid argument" error. It seems to be
			// non-fatal and we have to do another async_accept.
			if (e.value() == EINVAL)
			{
				async_accept(listener, ssl);
				return;
			}
#endif
			if (m_alerts.should_post<listen_failed_alert>())
			{
				m_alerts.emplace_alert<listen_failed_alert>(ep.address().to_string()
					, ep, operation_t::sock_accept, e
					, ssl == transport::ssl ? socket_type_t::tcp_ssl : socket_type_t::tcp);
			}
			return;
		}
		async_accept(listener, ssl);

		// don't accept any connections from our local sockets if we're using a
		// proxy
		if (m_settings.get_int(settings_pack::proxy_type) != settings_pack::none)
			return;

		auto listen = std::find_if(m_listen_sockets.begin(), m_listen_sockets.end()
			, [&listener](std::shared_ptr<listen_socket_t> const& l)
		{ return l->sock == listener; });
		if (listen != m_listen_sockets.end())
			(*listen)->incoming_connection = true;

		socket_type c = [&]{
#ifdef TORRENT_SSL_PEERS
			if (ssl == transport::ssl)
			{
				// accept connections initializing the SSL connection to use the peer
				// ssl context. Since it has the servername callback set on it, we will
				// switch away from this context into a specific torrent once we start
				// handshaking
				return socket_type(ssl_stream<tcp::socket>(tcp::socket(std::move(s)), m_peer_ssl_ctx));
			}
			else
#endif
			{
				return socket_type(tcp::socket(std::move(s)));
			}
		}();

#ifdef TORRENT_SSL_PEERS
		TORRENT_ASSERT((ssl == transport::ssl) == is_ssl(c));
#endif

#ifdef TORRENT_SSL_PEERS
		if (ssl == transport::ssl)
		{
			TORRENT_ASSERT(is_ssl(c));

			// save the socket so we can cancel the handshake
			// TODO: this size need to be capped
			auto iter = m_incoming_sockets.emplace(std::make_unique<socket_type>(std::move(c))).first;

			auto sock = iter->get();
			// for SSL connections, incoming_connection() is called
			// after the handshake is done
			ADD_OUTSTANDING_ASYNC("session_impl::ssl_handshake");
			std::get<ssl_stream<tcp::socket>>(**iter).async_accept_handshake(
				[this, sock] (error_code const& err) { ssl_handshake(err, sock); });
		}
		else
#endif
		{
			incoming_connection(std::move(c));
		}
	}

#ifdef TORRENT_SSL_PEERS

	void session_impl::on_incoming_utp_ssl(socket_type s)
	{
		TORRENT_ASSERT(is_ssl(s));

		// save the socket so we can cancel the handshake

		// TODO: this size need to be capped
		auto iter = m_incoming_sockets.emplace(std::make_unique<socket_type>(std::move(s))).first;
		auto sock = iter->get();

		// for SSL connections, incoming_connection() is called
		// after the handshake is done
		ADD_OUTSTANDING_ASYNC("session_impl::ssl_handshake");
		std::get<ssl_stream<utp_stream>>(**iter).async_accept_handshake(
			[this, sock] (error_code const& err) { ssl_handshake(err, sock); });
	}

	// to test SSL connections, one can use this openssl command template:
	//
	// openssl s_client -cert <client-cert>.pem -key <client-private-key>.pem
	//   -CAfile <torrent-cert>.pem  -debug -connect 127.0.0.1:4433 -tls1
	//   -servername <hex-encoded-info-hash>

	void session_impl::ssl_handshake(error_code const& ec, socket_type* sock)
	{
		COMPLETE_ASYNC("session_impl::ssl_handshake");

		auto iter = m_incoming_sockets.find(sock);

		// this happens if the SSL connection is aborted because we're shutting
		// down
		if (iter == m_incoming_sockets.end()) return;

		socket_type s(std::move(**iter));
		TORRENT_ASSERT(is_ssl(s));
		m_incoming_sockets.erase(iter);

		error_code e;
		tcp::endpoint endp = s.remote_endpoint(e);
		if (e) return;

#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log(" *** peer SSL handshake done [ ip: %s ec: %s socket: %s ]"
				, print_endpoint(endp).c_str(), ec.message().c_str(), socket_type_name(s));
		}
#endif

		if (ec)
		{
			return;
		}

		incoming_connection(std::move(s));
	}

#endif // TORRENT_SSL_PEERS

	void session_impl::incoming_connection(socket_type s)
	{
		TORRENT_ASSERT(is_single_thread());

		if (m_abort)
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log(" <== INCOMING CONNECTION [ ignored, aborting ]");
#endif
			return;
		}

		// don't accept any connections from our local sockets if we're using a
		// proxy
		if (m_settings.get_int(settings_pack::proxy_type) != settings_pack::none)
			return;

		if (m_paused)
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log(" <== INCOMING CONNECTION [ ignored, paused ]");
#endif
			return;
		}

		error_code ec;
		// we got a connection request!
		tcp::endpoint endp = s.remote_endpoint(ec);

		if (ec)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log(" <== INCOMING CONNECTION [ rejected, could "
					"not retrieve remote endpoint: %s ]"
					, print_error(ec).c_str());
			}
#endif
			return;
		}

		if (!m_settings.get_bool(settings_pack::enable_incoming_utp)
			&& is_utp(s))
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log("<== INCOMING CONNECTION [ rejected uTP connection ]");
#endif
			return;
		}

		if (!m_settings.get_bool(settings_pack::enable_incoming_tcp)
			&& std::get_if<tcp::socket>(&s))
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log("<== INCOMING CONNECTION [ rejected TCP connection ]");
#endif
			return;
		}

		// if there are outgoing interfaces specified, verify this
		// peer is correctly bound to one of them
		if (!m_outgoing_interfaces.empty())
		{
			tcp::endpoint local = s.local_endpoint(ec);
			if (ec)
			{
#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("<== INCOMING CONNECTION [ rejected connection: %s ]"
						, print_error(ec).c_str());
				}
#endif
				return;
			}

			if (!verify_incoming_interface(local.address()))
			{
#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("<== INCOMING CONNECTION [ rejected, local interface has incoming connections disabled: %s ]"
						, local.address().to_string().c_str());
				}
#endif
				return;
			}
			if (!verify_bound_address(local.address(), is_utp(s), ec))
			{
				if (ec)
				{
#ifndef TORRENT_DISABLE_LOGGING
					if (should_log())
					{
						session_log("<== INCOMING CONNECTION [ rejected, not allowed local interface: %s ]"
							, print_error(ec).c_str());
					}
#endif
					return;
				}

#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("<== INCOMING CONNECTION [ rejected, not allowed local interface: %s ]"
						, local.address().to_string().c_str());
				}
#endif
				return;
			}
		}

		// local addresses do not count, since it's likely
		// coming from our own client through local service discovery
		// and it does not reflect whether or not a router is open
		// for incoming connections or not.
		if (!is_local(endp.address()))
			m_stats_counters.set_value(counters::has_incoming_connections, 1);

		// this filter is ignored if a single torrent
		// is set to ignore the filter, since this peer might be
		// for that torrent
		if (m_stats_counters[counters::non_filter_torrents] == 0
			&& m_ip_filter
			&& (m_ip_filter->access(endp.address()) & ip_filter::blocked))
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log("<== INCOMING CONNECTION [ filtered blocked ip ]");
#endif
			return;
		}

		m_stats_counters.inc_stats_counter(counters::incoming_connections);

		if (m_alerts.should_post<incoming_connection_alert>())
			m_alerts.emplace_alert<incoming_connection_alert>(socket_type_idx(s), endp);

    }

#if TORRENT_ABI_VERSION == 1
	peer_id session_impl::deprecated_get_peer_id() const
	{
		return aux::generate_peer_id(m_settings);
	}
#endif

	int session_impl::next_port() const
	{
		int start = m_settings.get_int(settings_pack::outgoing_port);
		int num = m_settings.get_int(settings_pack::num_outgoing_ports);
		std::pair<int, int> out_ports(start, start + num);
		if (m_next_port < out_ports.first || m_next_port > out_ports.second)
			m_next_port = out_ports.first;

		int port = m_next_port;
		++m_next_port;
		if (m_next_port > out_ports.second) m_next_port = out_ports.first;
#ifndef TORRENT_DISABLE_LOGGING
		session_log(" *** BINDING OUTGOING CONNECTION [ port: %d ]", port);
#endif
		return port;
	}

	void session_impl::sent_bytes(int bytes_payload, int bytes_protocol)
	{
		TORRENT_ASSERT(bytes_payload >= 0);
		TORRENT_ASSERT(bytes_protocol >= 0);
		m_stats_counters.inc_stats_counter(counters::sent_bytes
			, bytes_payload + bytes_protocol);
		m_stats_counters.inc_stats_counter(counters::sent_payload_bytes
			, bytes_payload);

		m_stat.sent_bytes(bytes_payload, bytes_protocol);
	}

	void session_impl::received_bytes(int bytes_payload, int bytes_protocol)
	{
		TORRENT_ASSERT(bytes_payload >= 0);
		TORRENT_ASSERT(bytes_protocol >= 0);
		m_stats_counters.inc_stats_counter(counters::recv_bytes
			, bytes_payload + bytes_protocol);
		m_stats_counters.inc_stats_counter(counters::recv_payload_bytes
			, bytes_payload);

		m_stat.received_bytes(bytes_payload, bytes_protocol);
	}

	void session_impl::trancieve_ip_packet(int bytes, bool ipv6)
	{
		TORRENT_ASSERT(bytes >= 0);
		// one TCP/IP packet header for the packet
		// sent or received, and one for the ACK
		// The IPv4 header is 20 bytes
		// and IPv6 header is 40 bytes
		int const header = (ipv6 ? 40 : 20) + 20;
		int const mtu = 1500;
		int const packet_size = mtu - header;
		int const overhead = std::max(1, (bytes + packet_size - 1) / packet_size) * header;
		m_stats_counters.inc_stats_counter(counters::sent_ip_overhead_bytes
			, overhead);
		m_stats_counters.inc_stats_counter(counters::recv_ip_overhead_bytes
			, overhead);

		m_stat.trancieve_ip_packet(bytes, ipv6);
	}

	void session_impl::sent_syn(bool ipv6)
	{
		int const overhead = ipv6 ? 60 : 40;
		m_stats_counters.inc_stats_counter(counters::sent_ip_overhead_bytes
			, overhead);

		m_stat.sent_syn(ipv6);
	}

	void session_impl::received_synack(bool ipv6)
	{
		int const overhead = ipv6 ? 60 : 40;
		m_stats_counters.inc_stats_counter(counters::sent_ip_overhead_bytes
			, overhead);
		m_stats_counters.inc_stats_counter(counters::recv_ip_overhead_bytes
			, overhead);

		m_stat.received_synack(ipv6);
	}

	void session_impl::on_tick(error_code const& e)
	{
		COMPLETE_ASYNC("session_impl::on_tick");
		m_stats_counters.inc_stats_counter(counters::on_tick_counter);

		TORRENT_ASSERT(is_single_thread());

		time_point const now = aux::time_now();

		// we have to keep ticking the utp socket manager
		// until they're all closed
		// we also have to keep updating the aux time while
		// there are outstanding announces
		if (m_abort)
		{
			if (m_utp_socket_manager.num_sockets() == 0
#ifdef TORRENT_SSL_PEERS
				&& m_ssl_utp_socket_manager.num_sockets() == 0
#endif
				&& m_undead_peers.empty())
			{
				// this is where shutdown completes. We won't issue another
				// on_tick()
				return;
			}
#if defined TORRENT_ASIO_DEBUGGING
			std::fprintf(stderr, "uTP sockets: %d ssl-uTP sockets: %d undead-peers left: %d\n"
				, m_utp_socket_manager.num_sockets()
#ifdef TORRENT_SSL_PEERS
				, m_ssl_utp_socket_manager.num_sockets()
#else
				, 0
#endif
				, int(m_undead_peers.size()));
#endif
		}

		if (e && e != boost::asio::error::operation_aborted)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
				session_log("*** TICK TIMER FAILED %s", e.message().c_str());
#endif
			std::abort();
		}

		ADD_OUTSTANDING_ASYNC("session_impl::on_tick");
		milliseconds const tick_interval(m_abort ? 100 : m_settings.get_int(settings_pack::tick_interval));
		m_timer.expires_at(now + tick_interval);
		m_timer.async_wait(aux::make_handler([this](error_code const& err)
		{ wrap(&session_impl::on_tick, err); }, m_tick_handler_storage, *this));

		m_last_tick = now;

		m_utp_socket_manager.tick(now);
#ifdef TORRENT_SSL_PEERS
		m_ssl_utp_socket_manager.tick(now);
#endif

		// only tick the following once per second
		if (now - m_last_second_tick < seconds(1)) return;

		m_utp_socket_manager.decay();
#ifdef TORRENT_SSL_PEERS
		m_ssl_utp_socket_manager.decay();
#endif

		int const tick_interval_ms = aux::numeric_cast<int>(total_milliseconds(now - m_last_second_tick));
		m_last_second_tick = now;

#ifndef TORRENT_DISABLE_EXTENSIONS
		for (auto& ext : m_ses_extensions[plugins_tick_idx])
		{
			ext->on_tick();
		}
#endif

		// don't do any of the following while we're shutting down
		if (m_abort) return;

#if TORRENT_ABI_VERSION == 1
		m_peak_up_rate = std::max(m_stat.upload_rate(), m_peak_up_rate);
#endif

		m_stat.second_tick(tick_interval_ms);

	}

	void session_impl::received_buffer(int s)
	{
		int index = std::min(aux::log2p1(std::uint32_t(s >> 3)), 17);
		m_stats_counters.inc_stats_counter(counters::socket_recv_size3 + index);
	}

	void session_impl::sent_buffer(int s)
	{
		int index = std::min(aux::log2p1(std::uint32_t(s >> 3)), 17);
		m_stats_counters.inc_stats_counter(counters::socket_send_size3 + index);
	}

	void session_impl::add_dht_node(udp::endpoint const& n)
	{
		TORRENT_ASSERT(is_single_thread());
		if (m_dht) m_dht->add_node(n);
		else m_dht_nodes.push_back(n);
	}

	bool session_impl::has_dht() const
	{
		return m_dht != nullptr;
	}

#ifndef TORRENT_DISABLE_LOGGING
    bool session_impl::should_log() const
    {    
        return m_alerts.should_post<log_alert>();
    }    

    TORRENT_FORMAT(2,3)
    void session_impl::session_log(char const* fmt, ...) const noexcept try
    {    
        if (!m_alerts.should_post<log_alert>()) return;

        va_list v;
        va_start(v, fmt);
        m_alerts.emplace_alert<log_alert>(fmt, v);
        va_end(v);
    }    
    catch (std::exception const&) {}
#endif

	int session_impl::get_int_setting(int n) const
	{
		int const v = settings().get_int(n);
		if (v < 0) return std::numeric_limits<int>::max();
		return v;
	}

	void session_impl::post_session_stats()
	{
		if (!m_posted_stats_header)
		{
			m_posted_stats_header = true;
			m_alerts.emplace_alert<session_stats_header_alert>();
		}
		m_disk_thread->update_stats_counters(m_stats_counters);

		if (m_dht)
			m_dht->update_stats_counters(m_stats_counters);

		m_alerts.emplace_alert<session_stats_alert>(m_stats_counters);
	}

	void session_impl::post_dht_stats()
	{
		std::vector<dht::dht_status> dht_stats;
		if (m_dht)
			dht_stats = m_dht->dht_status();

		if (dht_stats.empty())
		{
			// for backwards compatibility, still post an empty alert if we don't
			// have any active DHT nodes
			m_alerts.emplace_alert<dht_stats_alert>(std::vector<dht_routing_bucket>{}
				, std::vector<dht_lookup>{}, dht::node_id{}, udp::endpoint{});
		}
		else
		{
			for (auto& s : dht_stats)
			{
				m_alerts.emplace_alert<dht_stats_alert>(
					std::move(s.table), std::move(s.requests)
					, s.our_id, s.local_endpoint);
			}
		}
	}

	void session_impl::update_outgoing_interfaces()
	{
		std::string const net_interfaces = m_settings.get_str(settings_pack::outgoing_interfaces);

		// declared in string_util.hpp
		parse_comma_separated_string(net_interfaces, m_outgoing_interfaces);

#ifndef TORRENT_DISABLE_LOGGING
		if (!net_interfaces.empty() && m_outgoing_interfaces.empty())
		{
			session_log("ERROR: failed to parse outgoing interface list: %s"
				, net_interfaces.c_str());
		}
#endif
	}

	tcp::endpoint session_impl::bind_outgoing_socket(socket_type& s
		, address const& remote_address, error_code& ec) const
	{
		tcp::endpoint bind_ep(address_v4(), 0);
		if (m_settings.get_int(settings_pack::outgoing_port) > 0)
		{
#ifdef TORRENT_WINDOWS
			s.set_option(exclusive_address_use(true), ec);
#else
			s.set_option(tcp::acceptor::reuse_address(true), ec);
#endif
			// ignore errors because the underlying socket may not
			// be opened yet. This happens when we're routing through
			// a proxy. In that case, we don't yet know the address of
			// the proxy server, and more importantly, we don't know
			// the address family of its address. This means we can't
			// open the socket yet. The socks abstraction layer defers
			// opening it.
			ec.clear();
			bind_ep.port(std::uint16_t(next_port()));
		}

		if (is_utp(s))
		{
			// TODO: factor out this logic into a separate function for unit
			// testing

			utp_socket_impl* impl = nullptr;
			transport ssl = transport::plaintext;
#if TORRENT_USE_SSL
			if (std::get_if<ssl_stream<utp_stream>>(&s.var()) != nullptr)
			{
				impl = std::get<ssl_stream<utp_stream>>(s).next_layer().get_impl();
				ssl = transport::ssl;
			}
			else
#endif
				impl = std::get<utp_stream>(s).get_impl();

			std::vector<std::shared_ptr<listen_socket_t>> with_gateways;
			std::shared_ptr<listen_socket_t> match;
			for (auto const& ls : m_listen_sockets)
			{
				if (is_v4(ls->local_endpoint) != remote_address.is_v4()) continue;
				if (ls->ssl != ssl) continue;
				if (!(ls->flags & listen_socket_t::local_network))
					with_gateways.push_back(ls);

				if (match_addr_mask(ls->local_endpoint.address(), remote_address, ls->netmask))
				{
					// is this better than the previous match?
					match = ls;
				}
			}
			if (!match && !with_gateways.empty())
				match = with_gateways[random(std::uint32_t(with_gateways.size() - 1))];

			if (match)
			{
				impl->m_sock = match;
				return match->local_endpoint;
			}
			ec.assign(boost::system::errc::not_supported, generic_category());
			return {};
		}

		if (!m_outgoing_interfaces.empty())
		{
			if (m_interface_index >= m_outgoing_interfaces.size()) m_interface_index = 0;
			std::string const& ifname = m_outgoing_interfaces[m_interface_index++];

			bind_ep.address(bind_socket_to_device(m_io_context, s
				, remote_address.is_v4() ? tcp::v4() : tcp::v6()
				, ifname.c_str(), bind_ep.port(), ec));
			return bind_ep;
		}

		// if we're not binding to a specific interface, bind
		// to the same protocol family as the target endpoint
		if (bind_ep.address().is_unspecified())
		{
			if (remote_address.is_v6())
				bind_ep.address(address_v6::any());
			else
				bind_ep.address(address_v4::any());
		}

		s.bind(bind_ep, ec);
		return bind_ep;
	}

	// verify that ``addr``s interface allows incoming connections
	bool session_impl::verify_incoming_interface(address const& addr)
	{
		auto const iter = std::find_if(m_listen_sockets.begin(), m_listen_sockets.end()
			, [&addr](std::shared_ptr<listen_socket_t> const& s)
			{ return s->local_endpoint.address() == addr; });
		return iter == m_listen_sockets.end()
			? false
			: bool((*iter)->flags & listen_socket_t::accept_incoming);
	}

	// verify that the given local address satisfies the requirements of
	// the outgoing interfaces. i.e. that one of the allowed outgoing
	// interfaces has this address. For uTP sockets, which are all backed
	// by an unconnected udp socket, we won't be able to tell what local
	// address is used for this peer's packets, in that case, just make
	// sure one of the allowed interfaces exists and maybe that it's the
	// default route. For systems that have SO_BINDTODEVICE, it should be
	// enough to just know that one of the devices exist
	bool session_impl::verify_bound_address(address const& addr, bool utp
		, error_code& ec)
	{
		TORRENT_UNUSED(utp);

		// we have specific outgoing interfaces specified. Make sure the
		// local endpoint for this socket is bound to one of the allowed
		// interfaces. the list can be a mixture of interfaces and IP
		// addresses.
		for (auto const& s : m_outgoing_interfaces)
		{
			error_code err;
			address const ip = make_address(s.c_str(), err);
			if (err) continue;
			if (ip == addr) return true;
		}

		// we didn't find the address as an IP in the interface list. Now,
		// resolve which device (if any) has this IP address.
		std::string const device = device_for_address(addr, m_io_context, ec);
		if (ec) return false;

		// if no device was found to have this address, we fail
		if (device.empty()) return false;

		return std::any_of(m_outgoing_interfaces.begin(), m_outgoing_interfaces.end()
			, [&device](std::string const& s) { return s == device; });
	}

#if TORRENT_ABI_VERSION == 1

	void session_impl::update_ssl_listen()
	{
		// this function maps the previous functionality of just setting the ssl
		// listen port in order to enable the ssl listen sockets, to the new
		// mechanism where SSL sockets are specified in listen_interfaces.
		std::vector<std::string> ignore;
		auto current_ifaces = parse_listen_interfaces(
			m_settings.get_str(settings_pack::listen_interfaces), ignore);
		// these are the current interfaces we have, first remove all the SSL
		// interfaces
		current_ifaces.erase(std::remove_if(current_ifaces.begin(), current_ifaces.end()
			, std::bind(&listen_interface_t::ssl, _1)), current_ifaces.end());

		int const ssl_listen_port = m_settings.get_int(settings_pack::ssl_listen);

		// setting a port of 0 means to disable listening on SSL, so just update
		// the interface list with the new list, and we're done
		if (ssl_listen_port == 0)
		{
			m_settings.set_str(settings_pack::listen_interfaces
				, print_listen_interfaces(current_ifaces));
			return;
		}

		std::vector<listen_interface_t> new_ifaces;
		std::transform(current_ifaces.begin(), current_ifaces.end()
			, std::back_inserter(new_ifaces), [](listen_interface_t in)
			{ in.ssl = true; return in; });

		current_ifaces.insert(current_ifaces.end(), new_ifaces.begin(), new_ifaces.end());

		m_settings.set_str(settings_pack::listen_interfaces
			, print_listen_interfaces(current_ifaces));
	}
#endif // TORRENT_ABI_VERSION

	void session_impl::update_listen_interfaces()
	{
		std::string const net_interfaces = m_settings.get_str(settings_pack::listen_interfaces);
		std::vector<std::string> err;
		m_listen_interfaces = parse_listen_interfaces(net_interfaces, err);

		for (auto const& e : err)
		{
			m_alerts.emplace_alert<listen_failed_alert>(e, lt::address{}, 0
				, operation_t::parse_address, errors::invalid_port, lt::socket_type_t::tcp);
		}

#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("update listen interfaces: %s", net_interfaces.c_str());
			session_log("parsed listen interfaces count: %d, ifaces: %s"
				, int(m_listen_interfaces.size())
				, print_listen_interfaces(m_listen_interfaces).c_str());
		}
#endif
	}

	void session_impl::update_privileged_ports()
	{
		if (m_settings.get_bool(settings_pack::no_connect_privileged_ports))
		{
			m_port_filter.add_rule(0, 1024, port_filter::blocked);
		}
		else
		{
			m_port_filter.add_rule(0, 1024, 0);
		}
	}

	void session_impl::update_resolver_cache_timeout()
	{
		int const timeout = m_settings.get_int(settings_pack::resolver_cache_timeout);
		m_host_resolver.set_cache_timeout(seconds(timeout));
	}

	void session_impl::update_proxy()
	{
		for (auto& i : m_listen_sockets)
			i->udp_sock->sock.set_proxy_settings(proxy(), m_alerts);
	}

	void session_impl::update_ip_notifier()
	{
		if (m_settings.get_bool(settings_pack::enable_ip_notifier))
			start_ip_notifier();
		else
			stop_ip_notifier();
	}

	void session_impl::update_upnp()
	{
		if (m_settings.get_bool(settings_pack::enable_upnp))
			start_upnp();
		else
			stop_upnp();
	}

	void session_impl::update_natpmp()
	{
		if (m_settings.get_bool(settings_pack::enable_natpmp))
			start_natpmp();
		else
			stop_natpmp();
	}

	void session_impl::update_dht()
	{
		if (!m_settings.get_str(settings_pack::dht_bootstrap_nodes).empty()
			&& m_dht_router_nodes.empty())
		{
			// if we have bootstrap nodes configured, make sure we initiate host
			// name lookups. once these complete, the DHT will be started.
			// they are tracked by m_outstanding_router_lookups
			update_dht_bootstrap_nodes();
		}
		else
		{
			start_dht();
		}
	}

    void session_impl::update_db_dir()
    {    

        std::string home_dir = boost::filesystem::path(getenv("HOME")).string();
        std::string const& kvdb_dir = home_dir + m_settings.get_str(settings_pack::db_dir)+ "/kvdb";
        std::string const& sqldb_dir = home_dir + m_settings.get_str(settings_pack::db_dir)+ "/sqldb";
        std::string const& sqldb_path = sqldb_dir + "/tau_sql.db";

#ifndef TORRENT_DISABLE_LOGGING
		session_log("start to  create directory for storing db data kvdb dir: %s, sqldb dir: %s", 
					 kvdb_dir.c_str(), sqldb_dir.c_str());
#endif
        // create the directory for storing leveldb data
 		if(!std::filesystem::is_directory(kvdb_dir)) {
			if(!std::filesystem::create_directories(kvdb_dir)){
#ifndef TORRENT_DISABLE_LOGGING
				session_log("failed create directory for storing kvdb data: %s", kvdb_dir.c_str());
#endif
				TORRENT_ASSERT(!std::filesystem::create_directories(kvdb_dir));
				alerts().emplace_alert<session_error_alert>(error_code(),
					 "libTAU ERROR: create kvdb directory falied");
				m_abort = true;	
			}
		}

        // create the directory for storing sqldb data
 		if(!std::filesystem::is_directory(sqldb_dir)) {
			if(!std::filesystem::create_directories(sqldb_dir)){
#ifndef TORRENT_DISABLE_LOGGING
				session_log("failed create directory for storing sqldb data: %s", sqldb_dir.c_str());
#endif
				TORRENT_ASSERT(!std::filesystem::create_directories(sqldb_dir));
				alerts().emplace_alert<session_error_alert>(error_code(),
					 "libTAU ERROR: create sqldb directory falied");
				m_abort = true;	
			}
		}

		// open kvdb - leveldb
		leveldb::Options options;
		options.create_if_missing = true;
		leveldb::Status status = leveldb::DB::Open(options, kvdb_dir, &m_kvdb);
		if (!status.ok()){
			TORRENT_ASSERT(!status.ok());
			alerts().emplace_alert<session_error_alert>(error_code(),
					 "libTAU ERROR: open kvdb failed");
			m_abort = true;	
		}

		// open sqldb - sqlite3
		int sqlrc = sqlite3_open_v2(sqldb_path.c_str(), &m_sqldb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_SHAREDCACHE, NULL);
		if (sqlrc != SQLITE_OK) {
			TORRENT_ASSERT(sqlrc != SQLITE_OK);
			alerts().emplace_alert<session_error_alert>(error_code(),
					 "libTAU ERROR: open sqldb failed");
			m_abort = true;	
		}
    }

	void session_impl::update_dht_bootstrap_nodes()
	{

		//std::string const& node_list = m_settings.get_str(settings_pack::dht_bootstrap_nodes);
		std::string const& nodes_from_settings = m_settings.get_str(settings_pack::dht_bootstrap_nodes);

		std::string const nodes_key = "bootstrap_nodes";
		std::string nodes_list;

		leveldb::Status s = m_kvdb->Get(leveldb::ReadOptions(), nodes_key, &nodes_list);
#ifndef TORRENT_DISABLE_LOGGING
		session_log("start to  update dht bootstrap nodes default: %s, db: %s",
					 nodes_from_settings.c_str(), nodes_list.c_str());
#endif

		if (!s.ok()){

#ifndef TORRENT_DISABLE_LOGGING
			session_log("start to  put 1st dht bootstrap nodes:%s into kvdb", nodes_from_settings.c_str());
#endif
			s = m_kvdb->Put(leveldb::WriteOptions(), nodes_key, nodes_from_settings);
			nodes_list = nodes_from_settings;
		}

		std::vector<std::pair<std::string, int>> nodes;
		parse_comma_separated_string_port(nodes_list, nodes);

		TORRENT_ASSERT(nodes.empty());

		if (nodes.empty())
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log("ERROR: failed to parse DHT bootstrap list");
#endif
		}

		for (auto const& n : nodes)
			add_dht_router(n);
	}

	void session_impl::update_account_seed() {

		std::array<char, 32> seed;

		const char* account_seed = m_settings.get_str(settings_pack::account_seed).c_str();
        span<char const> hexseed(account_seed, 64);
        libTAU::aux::from_hex(hexseed, seed.data());

		m_keypair = dht::ed25519_create_keypair(seed);

	}

	// TODO: 2 this function should be removed and users need to deal with the
	// more generic case of having multiple listen ports
	std::uint16_t session_impl::listen_port() const
	{
		return listen_port(nullptr);
	}

	std::uint16_t session_impl::listen_port(listen_socket_t* sock) const
	{
		if (m_listen_sockets.empty()) return 0;
		if (sock)
		{
			// if we're using a proxy, we won't be able to accept any TCP
			// connections. Not even uTP connections via the port we know about.
			// The DHT may use the implied port to make it work, but the port we
			// announce here has no relevance for that.
			if (sock->flags & listen_socket_t::proxy)
				return 0;

			if (!(sock->flags & listen_socket_t::accept_incoming))
				return 0;

			return std::uint16_t(sock->tcp_external_port());
		}

#ifdef TORRENT_SSL_PEERS
		for (auto const& s : m_listen_sockets)
		{
			if (!(s->flags & listen_socket_t::accept_incoming)) continue;
			if (s->ssl == transport::plaintext)
				return std::uint16_t(s->tcp_external_port());
		}
		return 0;
#else
		sock = m_listen_sockets.front().get();
		if (!(sock->flags & listen_socket_t::accept_incoming)) return 0;
		return std::uint16_t(sock->tcp_external_port());
#endif
	}

	// TODO: 2 this function should be removed and users need to deal with the
	// more generic case of having multiple ssl ports
	std::uint16_t session_impl::ssl_listen_port() const
	{
		return ssl_listen_port(nullptr);
	}

	std::uint16_t session_impl::ssl_listen_port(listen_socket_t* sock) const
	{
#ifdef TORRENT_SSL_PEERS
		if (sock)
		{
			if (!(sock->flags & listen_socket_t::accept_incoming)) return 0;
			return std::uint16_t(sock->tcp_external_port());
		}

		if (m_settings.get_int(settings_pack::proxy_type) != settings_pack::none)
			return 0;

		for (auto const& s : m_listen_sockets)
		{
			if (!(s->flags & listen_socket_t::accept_incoming)) continue;
			if (s->ssl == transport::ssl)
				return std::uint16_t(s->tcp_external_port());
		}
#else
		TORRENT_UNUSED(sock);
#endif
		return 0;
	}

	int session_impl::get_listen_port(transport const ssl, aux::listen_socket_handle const& s)
	{
		auto* socket = s.get();
		if (socket->ssl != ssl)
		{
			auto alt_socket = std::find_if(m_listen_sockets.begin(), m_listen_sockets.end()
				, [&](std::shared_ptr<listen_socket_t> const& e)
			{
				return e->ssl == ssl
					&& e->external_address.external_address()
						== socket->external_address.external_address();
			});
			if (alt_socket != m_listen_sockets.end())
				socket = alt_socket->get();
		}
		return socket->udp_external_port();
	}

	int session_impl::listen_port(transport const ssl, address const& local_addr)
	{
		auto socket = std::find_if(m_listen_sockets.begin(), m_listen_sockets.end()
			, [&](std::shared_ptr<listen_socket_t> const& e)
		{
			if (!(e->flags & listen_socket_t::accept_incoming)) return false;
			auto const& listen_addr = e->external_address.external_address();
			return e->ssl == ssl
				&& (listen_addr == local_addr
					|| (listen_addr.is_v4() == local_addr.is_v4() && listen_addr.is_unspecified()));
		});
		if (socket != m_listen_sockets.end())
			return (*socket)->tcp_external_port();
		return 0;
	}

	void session_impl::start_natpmp(std::shared_ptr<aux::listen_socket_t> const& s)
	{
		// don't create mappings for local IPv6 addresses
		// they can't be reached from outside of the local network anyways
		if (is_v6(s->local_endpoint) && is_local(s->local_endpoint.address()))
			return;

		if (!s->natpmp_mapper
			&& !(s->flags & listen_socket_t::local_network)
			&& !(s->flags & listen_socket_t::proxy))
		{
			// the natpmp constructor may fail and call the callbacks
			// into the session_impl.
			s->natpmp_mapper = std::make_shared<natpmp>(m_io_context, *this, listen_socket_handle(s));
			ip_interface ip;
			ip.interface_address = s->local_endpoint.address();
			ip.netmask = s->netmask;
			std::strncpy(ip.name, s->device.c_str(), sizeof(ip.name) - 1);
			ip.name[sizeof(ip.name) - 1] = '\0';
			s->natpmp_mapper->start(ip);
		}
	}

	void session_impl::on_port_mapping(port_mapping_t const mapping
		, address const& external_ip, int port
		, portmap_protocol const proto, error_code const& ec
		, portmap_transport const transport
		, listen_socket_handle const& ls)
	{
		TORRENT_ASSERT(is_single_thread());

		listen_socket_t* listen_socket = ls.get();

		// NOTE: don't assume that if ec != 0, the rest of the logic
		// is not necessary, the ports still need to be set, in other
		// words, don't early return without careful review of the
		// remaining logic
		if (ec && m_alerts.should_post<portmap_error_alert>())
		{
			m_alerts.emplace_alert<portmap_error_alert>(mapping
				, transport, ec, listen_socket ? listen_socket->local_endpoint.address() : address());
		}

		if (!listen_socket) return;

		if (!ec && !external_ip.is_unspecified())
		{
			// TODO: 1 report the proper address of the router as the source IP of
			// this vote of our external address, instead of the empty address
			listen_socket->external_address.cast_vote(external_ip, source_router, address());
		}

		if (proto == portmap_protocol::tcp) listen_socket->tcp_port_mapping[transport].port = port;
		else if (proto == portmap_protocol::udp) listen_socket->udp_port_mapping[transport].port = port;

		if (!ec && m_alerts.should_post<portmap_alert>())
		{
			m_alerts.emplace_alert<portmap_alert>(mapping, port
				, transport, proto, listen_socket->local_endpoint.address());
		}
	}

#if TORRENT_ABI_VERSION == 1
	session_status session_impl::status() const
	{
		TORRENT_ASSERT(is_single_thread());

		session_status s;

		s.num_peers = int(m_stats_counters[counters::num_peers_connected]);

		s.total_redundant_bytes = m_stats_counters[counters::recv_redundant_bytes];
		s.total_failed_bytes = m_stats_counters[counters::recv_failed_bytes];

		s.up_bandwidth_queue = int(m_stats_counters[counters::limiter_up_queue]);
		s.down_bandwidth_queue = int(m_stats_counters[counters::limiter_down_queue]);

		s.up_bandwidth_bytes_queue = int(m_stats_counters[counters::limiter_up_bytes]);
		s.down_bandwidth_bytes_queue = int(m_stats_counters[counters::limiter_down_bytes]);

		s.disk_write_queue = int(m_stats_counters[counters::num_peers_down_disk]);
		s.disk_read_queue = int(m_stats_counters[counters::num_peers_up_disk]);

		s.has_incoming_connections = m_stats_counters[counters::has_incoming_connections] != 0;

		// total
		s.download_rate = m_stat.download_rate();
		s.total_upload = m_stat.total_upload();
		s.upload_rate = m_stat.upload_rate();
		s.total_download = m_stat.total_download();

		// payload
		s.payload_download_rate = m_stat.transfer_rate(stat::download_payload);
		s.total_payload_download = m_stat.total_transfer(stat::download_payload);
		s.payload_upload_rate = m_stat.transfer_rate(stat::upload_payload);
		s.total_payload_upload = m_stat.total_transfer(stat::upload_payload);

		// IP-overhead
		s.ip_overhead_download_rate = m_stat.transfer_rate(stat::download_ip_protocol);
		s.total_ip_overhead_download = m_stats_counters[counters::recv_ip_overhead_bytes];
		s.ip_overhead_upload_rate = m_stat.transfer_rate(stat::upload_ip_protocol);
		s.total_ip_overhead_upload = m_stats_counters[counters::sent_ip_overhead_bytes];

		// tracker
		s.total_tracker_download = m_stats_counters[counters::recv_tracker_bytes];
		s.total_tracker_upload = m_stats_counters[counters::sent_tracker_bytes];

		// dht
		s.total_dht_download = m_stats_counters[counters::dht_bytes_in];
		s.total_dht_upload = m_stats_counters[counters::dht_bytes_out];

		// deprecated
		s.tracker_download_rate = 0;
		s.tracker_upload_rate = 0;
		s.dht_download_rate = 0;
		s.dht_upload_rate = 0;

		if (m_dht)
		{
			m_dht->dht_status(s);
		}
		else
		{
			s.dht_nodes = 0;
			s.dht_node_cache = 0;
			s.dht_global_nodes = 0;
			s.dht_total_allocations = 0;
		}

		s.utp_stats.packet_loss = std::uint64_t(m_stats_counters[counters::utp_packet_loss]);
		s.utp_stats.timeout = std::uint64_t(m_stats_counters[counters::utp_timeout]);
		s.utp_stats.packets_in = std::uint64_t(m_stats_counters[counters::utp_packets_in]);
		s.utp_stats.packets_out = std::uint64_t(m_stats_counters[counters::utp_packets_out]);
		s.utp_stats.fast_retransmit = std::uint64_t(m_stats_counters[counters::utp_fast_retransmit]);
		s.utp_stats.packet_resend = std::uint64_t(m_stats_counters[counters::utp_packet_resend]);
		s.utp_stats.samples_above_target = std::uint64_t(m_stats_counters[counters::utp_samples_above_target]);
		s.utp_stats.samples_below_target = std::uint64_t(m_stats_counters[counters::utp_samples_below_target]);
		s.utp_stats.payload_pkts_in = std::uint64_t(m_stats_counters[counters::utp_payload_pkts_in]);
		s.utp_stats.payload_pkts_out = std::uint64_t(m_stats_counters[counters::utp_payload_pkts_out]);
		s.utp_stats.invalid_pkts_in = std::uint64_t(m_stats_counters[counters::utp_invalid_pkts_in]);
		s.utp_stats.redundant_pkts_in = std::uint64_t(m_stats_counters[counters::utp_redundant_pkts_in]);

		s.utp_stats.num_idle = int(m_stats_counters[counters::num_utp_idle]);
		s.utp_stats.num_syn_sent = int(m_stats_counters[counters::num_utp_syn_sent]);
		s.utp_stats.num_connected = int(m_stats_counters[counters::num_utp_connected]);
		s.utp_stats.num_fin_sent = int(m_stats_counters[counters::num_utp_fin_sent]);
		s.utp_stats.num_close_wait = int(m_stats_counters[counters::num_utp_close_wait]);

		return s;
	}
#endif // TORRENT_ABI_VERSION

	void session_impl::start_communication()
	{

		stop_communication();

		if (m_abort)
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log("not starting Communication, aborting");
#endif
			return;
		}
		// todo: initialize device_id
		m_communication = std::make_shared<communication::communication>(m_device_id, m_io_context, *this);

#ifndef TORRENT_DISABLE_LOGGING
		session_log("starting Communication");
#endif
		m_communication->start();

	}

	void session_impl::start_dht()
	{
		stop_dht();

		// postpone starting the DHT if we're still resolving the DHT router
		if (m_outstanding_router_lookups > 0)
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log("not starting DHT, outstanding router lookups: %d"
				, m_outstanding_router_lookups);
#endif
			return;
		}

		if (m_abort)
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log("not starting DHT, aborting");
#endif
			return;
		}

#ifndef TORRENT_DISABLE_LOGGING
		session_log("starting DHT, running: %s, router lookups: %d"
			, m_dht ? "true" : "false", m_outstanding_router_lookups);
#endif

		// TODO: refactor, move the storage to dht_tracker
		m_dht_storage = m_dht_storage_constructor(m_settings);
		m_dht = std::make_shared<dht::dht_tracker>(
			static_cast<dht::dht_observer*>(this)
			, m_io_context
			, [this](aux::listen_socket_handle const& sock
				, udp::endpoint const& ep
				, span<char const> p
				, error_code& ec
				, udp_send_flags_t const flags)
				{ send_udp_packet_listen(sock, ep, p, ec, flags); }
			, m_settings
			, m_stats_counters
			, *m_dht_storage
			, std::move(m_dht_state));

		for (auto& s : m_listen_sockets)
		{
			if (s->ssl != transport::ssl
				&& !(s->flags & listen_socket_t::local_network))
			{
				m_dht->new_socket(s);
			}
		}

		for (auto const& n : m_dht_router_nodes)
		{
			m_dht->add_router_node(n);
		}

		for (auto const& n : m_dht_nodes)
		{
			m_dht->add_node(n);
		}
		m_dht_nodes.clear();
		m_dht_nodes.shrink_to_fit();

		auto cb = [this](
			std::vector<std::pair<dht::node_entry, std::string>> const&)
		{
			if (m_alerts.should_post<dht_bootstrap_alert>())
				m_alerts.emplace_alert<dht_bootstrap_alert>();
		};

		m_dht->start(cb);
	}

	void session_impl::stop_communication()
	{

#ifndef TORRENT_DISABLE_LOGGING
		session_log("about to stop Communication, running: %s", m_communication ? "true" : "false");
#endif

		if(m_communication)
		{
			m_communication->stop();
		}

	}

	void session_impl::stop_dht()
	{
#ifndef TORRENT_DISABLE_LOGGING
		session_log("about to stop DHT, running: %s", m_dht ? "true" : "false");
#endif

		if (m_dht)
		{
			m_dht->stop();
			m_dht.reset();
		}

		m_dht_storage.reset();
	}

	void session_impl::set_loop_time_interval(int milliseconds)
	{
		m_communication->set_loop_time_interval(milliseconds);
	}

	bool session_impl::add_new_friend(const aux::bytes& pubkey)
	{
		return m_communication->add_new_friend(pubkey);
	}

	bool session_impl::delete_friend(const aux::bytes& pubkey)
	{
		return m_communication->delete_friend(pubkey);
	}

	void session_impl::get_friend_info(aux::bytes pubkey, std::vector<unsigned char>& info)
	{
		info = m_communication->get_friend_info(pubkey);
	}

	bool session_impl::update_friend_info(aux::bytes pubkey, aux::bytes friend_info)
	{
		return m_communication->update_friend_info(pubkey, friend_info);
	}

	void session_impl::unset_chatting_friend()
	{
		m_communication->unset_chatting_friend();
	}
	
	void session_impl::set_chatting_friend(aux::bytes chatting_friend){
		m_communication->set_chatting_friend(chatting_friend);
	}

	void session_impl::set_active_friends(std::vector<aux::bytes> active_friends)
	{
		m_communication->set_active_friends(active_friends);
	}

	bool session_impl::add_new_message(const aux::vector_ref<unsigned char>& msg)
	{
		return m_communication->add_new_message(communication::message(msg));
	}	

#if TORRENT_ABI_VERSION <= 2
	void session_impl::set_dht_settings(dht::dht_settings const& settings)
	{
#define SET_BOOL(name) m_settings.set_bool(settings_pack::dht_ ## name, settings.name)
#define SET_INT(name) m_settings.set_int(settings_pack::dht_ ## name, settings.name)

		SET_INT(max_peers_reply);
		SET_INT(search_branching);
		SET_INT(max_fail_count);
		SET_INT(max_dht_items);
		SET_INT(max_peers);
		SET_INT(max_torrent_search_reply);
		SET_BOOL(restrict_routing_ips);
		SET_BOOL(restrict_search_ips);
		SET_BOOL(extended_routing_table);
		SET_BOOL(aggressive_lookups);
		SET_BOOL(privacy_lookups);
		SET_BOOL(enforce_node_id);
		SET_BOOL(ignore_dark_internet);
		SET_INT(block_timeout);
		SET_INT(block_ratelimit);
		SET_BOOL(read_only);
		SET_INT(item_lifetime);
		SET_INT(upload_rate_limit);
		SET_INT(sample_infohashes_interval);
		SET_INT(max_infohashes_sample_count);
#undef SET_BOOL
#undef SET_INT
		update_dht_upload_rate_limit();
	}

	dht::dht_settings session_impl::get_dht_settings() const
	{
		dht::dht_settings sett;
#define SET_BOOL(name) \
		sett.name = m_settings.get_bool( settings_pack::dht_ ## name )
#define SET_INT(name) \
		sett.name = m_settings.get_int( settings_pack::dht_ ## name )

		SET_INT(max_peers_reply);
		SET_INT(search_branching);
		SET_INT(max_fail_count);
		SET_INT(max_dht_items);
		SET_INT(max_peers);
		SET_INT(max_torrent_search_reply);
		SET_BOOL(restrict_routing_ips);
		SET_BOOL(restrict_search_ips);
		SET_BOOL(extended_routing_table);
		SET_BOOL(aggressive_lookups);
		SET_BOOL(privacy_lookups);
		SET_BOOL(enforce_node_id);
		SET_BOOL(ignore_dark_internet);
		SET_INT(block_timeout);
		SET_INT(block_ratelimit);
		SET_BOOL(read_only);
		SET_INT(item_lifetime);
		SET_INT(upload_rate_limit);
		SET_INT(sample_infohashes_interval);
		SET_INT(max_infohashes_sample_count);
#undef SET_BOOL
#undef SET_INT
		return sett;
	}
#endif

	void session_impl::set_dht_state(dht::dht_state&& state)
	{
		m_dht_state = std::move(state);
	}

	void session_impl::set_dht_storage(dht::dht_storage_constructor_type sc)
	{
		m_dht_storage_constructor = std::move(sc);
	}

#if TORRENT_ABI_VERSION == 1
	entry session_impl::dht_state() const
	{
		return m_dht ? dht::save_dht_state(m_dht->state()) : entry();
	}

	void session_impl::start_dht_deprecated(entry const& startup_state)
	{
		m_settings.set_bool(settings_pack::enable_dht, true);
		std::vector<char> tmp;
		bencode(std::back_inserter(tmp), startup_state);

		bdecode_node e;
		error_code ec;
		if (tmp.empty() || bdecode(&tmp[0], &tmp[0] + tmp.size(), e, ec) != 0)
			return;
		m_dht_state = dht::read_dht_state(e);
		start_dht();
	}
#endif

	void session_impl::add_dht_node_name(std::pair<std::string, int> const& node)
	{
		ADD_OUTSTANDING_ASYNC("session_impl::on_dht_name_lookup");
		m_host_resolver.async_resolve(node.first, resolver::abort_on_shutdown
			, std::bind(&session_impl::on_dht_name_lookup
				, this, _1, _2, node.second));
	}

	void session_impl::on_dht_name_lookup(error_code const& e
		, std::vector<address> const& addresses, int port)
	{
		COMPLETE_ASYNC("session_impl::on_dht_name_lookup");

		if (e)
		{
			if (m_alerts.should_post<dht_error_alert>())
				m_alerts.emplace_alert<dht_error_alert>(
					operation_t::hostname_lookup, e);
			return;
		}

		for (auto const& addr : addresses)
		{
			udp::endpoint ep(addr, std::uint16_t(port));
			add_dht_node(ep);
		}
	}

	void session_impl::add_dht_router(std::pair<std::string, int> const& node)
	{
		ADD_OUTSTANDING_ASYNC("session_impl::on_dht_router_name_lookup");
		++m_outstanding_router_lookups;
		m_host_resolver.async_resolve(node.first, resolver::abort_on_shutdown
			, std::bind(&session_impl::on_dht_router_name_lookup
				, this, _1, _2, node.second));
	}

	void session_impl::on_dht_router_name_lookup(error_code const& e
		, std::vector<address> const& addresses, int port)
	{
		COMPLETE_ASYNC("session_impl::on_dht_router_name_lookup");
		--m_outstanding_router_lookups;

		if (e)
		{
			if (m_alerts.should_post<dht_error_alert>())
				m_alerts.emplace_alert<dht_error_alert>(
					operation_t::hostname_lookup, e);

			if (m_outstanding_router_lookups == 0) start_dht();
			return;
		}


		for (auto const& addr : addresses)
		{
			// router nodes should be added before the DHT is started (and bootstrapped)
			udp::endpoint ep(addr, std::uint16_t(port));
			if (m_dht) m_dht->add_router_node(ep);
			m_dht_router_nodes.push_back(ep);
		}

		if (m_outstanding_router_lookups == 0) start_dht();
	}

	// callback for dht_immutable_get
	void session_impl::get_immutable_callback(sha256_hash target
		, dht::item const& i)
	{
		TORRENT_ASSERT(!i.is_mutable());
		m_alerts.emplace_alert<dht_immutable_item_alert>(target, i.value());
	}

	void session_impl::dht_get_immutable_item(sha256_hash const& target)
	{
		if (!m_dht) return;
		m_dht->get_item(target, std::bind(&session_impl::get_immutable_callback
			, this, target, _1));
	}

	// callback for dht_mutable_get
	void session_impl::get_mutable_callback(dht::item const& i
		, bool const authoritative)
	{
		TORRENT_ASSERT(i.is_mutable());
		m_alerts.emplace_alert<dht_mutable_item_alert>(i.pk().bytes
			, i.sig().bytes, i.seq().value
			, i.salt(), i.value(), authoritative);
	}

	// key is a 32-byte binary string, the public key to look up.
	// the salt is optional
	// TODO: 3 use public_key here instead of std::array
	void session_impl::dht_get_mutable_item(std::array<char, 32> key
		, std::string salt)
	{
		if (!m_dht) return;
		m_dht->get_item(dht::public_key(key.data()), std::bind(&session_impl::get_mutable_callback
			, this, _1, _2), std::move(salt));
	}

	namespace {

		void on_dht_put_immutable_item(aux::alert_manager& alerts, sha256_hash target, int num)
		{
			if (alerts.should_post<dht_put_alert>())
				alerts.emplace_alert<dht_put_alert>(target, num);
		}

		void on_dht_put_mutable_item(aux::alert_manager& alerts, dht::item const& i, int num)
		{
			if (alerts.should_post<dht_put_alert>())
			{
				dht::signature const sig = i.sig();
				dht::public_key const pk = i.pk();
				dht::sequence_number const seq = i.seq();
				std::string salt = i.salt();
				alerts.emplace_alert<dht_put_alert>(pk.bytes, sig.bytes
					, std::move(salt), seq.value, num);
			}
		}

		void put_mutable_callback(dht::item& i
			, std::function<void(entry&, std::array<char, 64>&
				, std::int64_t&, std::string const&)> cb)
		{
			entry value = i.value();
			dht::signature sig = i.sig();
			dht::public_key pk = i.pk();
			dht::sequence_number seq = i.seq();
			std::string salt = i.salt();
			cb(value, sig.bytes, seq.value, salt);
			i.assign(std::move(value), salt, seq, pk, sig);
		}

	} // anonymous namespace

	void session_impl::dht_put_immutable_item(entry const& data, sha256_hash target)
	{
		if (!m_dht) return;
		m_dht->put_item(data, std::bind(&on_dht_put_immutable_item, std::ref(m_alerts)
			, target, _1));
	}

	void session_impl::dht_put_mutable_item(std::array<char, 32> key
		, std::function<void(entry&, std::array<char,64>&
		, std::int64_t&, std::string const&)> cb
		, std::string salt)
	{
		if (!m_dht) return;
		m_dht->put_item(dht::public_key(key.data())
			, std::bind(&on_dht_put_mutable_item, std::ref(m_alerts), _1, _2)
			, std::bind(&put_mutable_callback, _1, std::move(cb)), salt);
	}

	void session_impl::dht_live_nodes(sha256_hash const& nid)
	{
		if (!m_dht) return;
		auto nodes = m_dht->live_nodes(nid);
		m_alerts.emplace_alert<dht_live_nodes_alert>(nid, nodes);
	}

	bool session_impl::is_listening() const
	{
		return !m_listen_sockets.empty();
	}

	session_impl::~session_impl()
	{
		// since we're destructing the session, no more alerts will make it out to
		// the user. So stop posting them now
		m_alerts.set_alert_mask({});

		// this is not allowed to be the network thread!
//		TORRENT_ASSERT(is_not_thread());
// TODO: asserts that no outstanding async operations are still in flight

#if defined TORRENT_ASIO_DEBUGGING
		FILE* f = fopen("wakeups.log", "w+");
		if (f != nullptr)
		{
			time_point m = min_time();
			if (!_wakeups.empty()) m = _wakeups[0].timestamp;
			time_point prev = m;
			std::uint64_t prev_csw = 0;
			if (!_wakeups.empty()) prev_csw = _wakeups[0].context_switches;
			std::fprintf(f, "abs. time\trel. time\tctx switch\tidle-wakeup\toperation\n");
			for (wakeup_t const& w : _wakeups)
			{
				bool const idle_wakeup = w.context_switches > prev_csw;
				std::fprintf(f, "%" PRId64 "\t%" PRId64 "\t%" PRId64 "\t%c\t%s\n"
					, total_microseconds(w.timestamp - m)
					, total_microseconds(w.timestamp - prev)
					, w.context_switches
					, idle_wakeup ? '*' : '.'
					, w.operation);
				prev = w.timestamp;
				prev_csw = w.context_switches;
			}
			fclose(f);
		}
#endif
	}

#if TORRENT_ABI_VERSION == 1
	int session_impl::max_connections() const
	{
		return m_settings.get_int(settings_pack::connections_limit);
	}

	int session_impl::max_uploads() const
	{
		return m_settings.get_int(settings_pack::unchoke_slots_limit);
	}

	void session_impl::set_local_download_rate_limit(int bytes_per_second)
	{
		settings_pack p;
		p.set_int(settings_pack::local_download_rate_limit, bytes_per_second);
		apply_settings_pack_impl(p);
	}

	void session_impl::set_local_upload_rate_limit(int bytes_per_second)
	{
		settings_pack p;
		p.set_int(settings_pack::local_upload_rate_limit, bytes_per_second);
		apply_settings_pack_impl(p);
	}

	void session_impl::set_download_rate_limit_depr(int bytes_per_second)
	{
		settings_pack p;
		p.set_int(settings_pack::download_rate_limit, bytes_per_second);
		apply_settings_pack_impl(p);
	}

	void session_impl::set_upload_rate_limit_depr(int bytes_per_second)
	{
		settings_pack p;
		p.set_int(settings_pack::upload_rate_limit, bytes_per_second);
		apply_settings_pack_impl(p);
	}

	void session_impl::set_max_connections(int limit)
	{
		settings_pack p;
		p.set_int(settings_pack::connections_limit, limit);
		apply_settings_pack_impl(p);
	}

	void session_impl::set_max_uploads(int limit)
	{
		settings_pack p;
		p.set_int(settings_pack::unchoke_slots_limit, limit);
		apply_settings_pack_impl(p);
	}

	int session_impl::local_upload_rate_limit() const
	{
		return upload_rate_limit(m_local_peer_class);
	}

	int session_impl::local_download_rate_limit() const
	{
		return download_rate_limit(m_local_peer_class);
	}

	int session_impl::upload_rate_limit_depr() const
	{
		return upload_rate_limit(m_global_class);
	}

	int session_impl::download_rate_limit_depr() const
	{
		return download_rate_limit(m_global_class);
	}
#endif // DEPRECATE

	namespace {
		template <typename Socket>
		void set_tos(Socket& s, int v, error_code& ec)
		{
#if defined IPV6_TCLASS
			if (is_v6(s.local_endpoint(ec)))
				s.set_option(traffic_class(char(v)), ec);
			else if (!ec)
#endif
				s.set_option(type_of_service(char(v)), ec);
		}
	}

	// TODO: 2 this should be factored into the udp socket, so we only have the
	// code once
	void session_impl::update_peer_tos()
	{
		int const tos = m_settings.get_int(settings_pack::peer_tos);
		for (auto const& l : m_listen_sockets)
		{
			if (l->sock)
			{
				error_code ec;
				set_tos(*l->sock, tos, ec);

#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log(">>> SET_TOS [ tcp (%s %d) tos: %x e: %s ]"
						, l->sock->local_endpoint().address().to_string().c_str()
						, l->sock->local_endpoint().port(), tos, ec.message().c_str());
				}
#endif
			}

			if (l->udp_sock)
			{
				error_code ec;
				set_tos(l->udp_sock->sock, tos, ec);

#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log(">>> SET_TOS [ udp (%s %d) tos: %x e: %s ]"
						, l->udp_sock->sock.local_endpoint().address().to_string().c_str()
						, l->udp_sock->sock.local_port()
						, tos, ec.message().c_str());
				}
#endif
			}
		}
	}

	void session_impl::update_user_agent()
	{
		// replace all occurrences of '\n' with ' '.
		std::string agent = m_settings.get_str(settings_pack::user_agent);
		std::string::iterator i = agent.begin();
		while ((i = std::find(i, agent.end(), '\n'))
			!= agent.end())
			*i = ' ';
		m_settings.set_str(settings_pack::user_agent, agent);
	}

	void session_impl::update_connection_speed()
	{
		if (m_settings.get_int(settings_pack::connection_speed) < 0)
			m_settings.set_int(settings_pack::connection_speed, 200);
	}

	void session_impl::update_alert_queue_size()
	{
		m_alerts.set_alert_queue_size_limit(m_settings.get_int(settings_pack::alert_queue_size));
	}

	void session_impl::update_dht_upload_rate_limit()
	{
		if (m_settings.get_int(settings_pack::dht_upload_rate_limit) > std::numeric_limits<int>::max() / 3)
		{
			m_settings.set_int(settings_pack::dht_upload_rate_limit, std::numeric_limits<int>::max() / 3);
		}
	}

	void session_impl::update_disk_threads()
	{
		if (m_settings.get_int(settings_pack::aio_threads) < 0)
			m_settings.set_int(settings_pack::aio_threads, 0);
		if (m_settings.get_int(settings_pack::hashing_threads) < 0)
			m_settings.set_int(settings_pack::hashing_threads, 0);
	}

	void session_impl::update_socket_buffer_size()
	{
		for (auto const& l : m_listen_sockets)
		{
			error_code ec;
			set_socket_buffer_size(l->udp_sock->sock, m_settings, ec);
#ifndef TORRENT_DISABLE_LOGGING
			if (ec && should_log())
			{
				session_log("listen socket buffer size [ udp %s:%d ] %s"
					, l->udp_sock->sock.local_endpoint().address().to_string().c_str()
					, l->udp_sock->sock.local_port(), print_error(ec).c_str());
			}
#endif
			ec.clear();
			set_socket_buffer_size(*l->sock, m_settings, ec);
#ifndef TORRENT_DISABLE_LOGGING
			if (ec && should_log())
			{
				session_log("listen socket buffer size [ tcp %s:%d] %s"
					, l->sock->local_endpoint().address().to_string().c_str()
					, l->sock->local_endpoint().port(), print_error(ec).c_str());
			}
#endif
		}
	}

	void session_impl::update_connections_limit()
	{
		int limit = m_settings.get_int(settings_pack::connections_limit);

		if (limit <= 0) limit = max_open_files();

		m_settings.set_int(settings_pack::connections_limit, limit);

	}

	void session_impl::update_alert_mask()
	{
		m_alerts.set_alert_mask(alert_category_t(
			static_cast<std::uint32_t>(m_settings.get_int(settings_pack::alert_mask))));
	}

	void session_impl::update_validate_https()
	{
#if TORRENT_USE_SSL
		auto const flags = m_settings.get_bool(settings_pack::validate_https_trackers)
			? ssl::context::verify_peer
				| ssl::context::verify_fail_if_no_peer_cert
				| ssl::context::verify_client_once
			: ssl::context::verify_none;
		error_code ec;
		m_ssl_ctx.set_verify_mode(flags, ec);

#ifndef TORRENT_DISABLE_LOGGING
		if (ec) session_log("SSL set_verify_mode failed: %s", ec.message().c_str());
#endif
#endif
	}

	void session_impl::pop_alerts(std::vector<alert*>* alerts)
	{
		m_alerts.get_all(*alerts);
	}

#if TORRENT_ABI_VERSION == 1
	void session_impl::update_rate_limit_utp()
	{
		if (m_settings.get_bool(settings_pack::rate_limit_utp))
		{
			// allow the global or local peer class to limit uTP peers
			m_peer_class_type_filter.allow(peer_class_type_filter::utp_socket
				, m_global_class);
			m_peer_class_type_filter.allow(peer_class_type_filter::ssl_utp_socket
				, m_global_class);
		}
		else
		{
			// don't add the global or local peer class to limit uTP peers
			m_peer_class_type_filter.disallow(peer_class_type_filter::utp_socket
				, m_global_class);
			m_peer_class_type_filter.disallow(peer_class_type_filter::ssl_utp_socket
				, m_global_class);
		}
	}

	void session_impl::update_ignore_rate_limits_on_local_network()
	{
		init_peer_class_filter(
			m_settings.get_bool(settings_pack::ignore_limits_on_local_network));
	}

	// this function is called on the user's thread
	// not the network thread
	void session_impl::pop_alerts()
	{
		// if we don't have any alerts in our local cache, we have to ask
		// the alert_manager for more. It will swap our vector with its and
		// destruct eny left-over alerts in there.
		if (m_alert_pointer_pos >= int(m_alert_pointers.size()))
		{
			pop_alerts(&m_alert_pointers);
			m_alert_pointer_pos = 0;
		}
	}

	alert const* session_impl::pop_alert()
	{
		if (m_alert_pointer_pos >= int(m_alert_pointers.size()))
		{
			pop_alerts();
			if (m_alert_pointers.empty())
				return nullptr;
		}

		if (m_alert_pointers.empty()) return nullptr;

		// clone here to be backwards compatible, to make the client delete the
		// alert object
		return m_alert_pointers[m_alert_pointer_pos++];
	}

#endif

	alert* session_impl::wait_for_alert(time_duration max_wait)
	{
		return m_alerts.wait_for_alert(max_wait);
	}

#if TORRENT_ABI_VERSION == 1
	std::size_t session_impl::set_alert_queue_size_limit(std::size_t queue_size_limit_)
	{
		m_settings.set_int(settings_pack::alert_queue_size, int(queue_size_limit_));
		return std::size_t(m_alerts.set_alert_queue_size_limit(int(queue_size_limit_)));
	}
#endif

	void session_impl::start_ip_notifier()
	{
		if (m_ip_notifier) return;

		m_ip_notifier = create_ip_notifier(m_io_context);
		m_ip_notifier->async_wait([this](error_code const& e)
			{ wrap(&session_impl::on_ip_change, e); });
	}

	void session_impl::start_natpmp()
	{
		for (auto& s : m_listen_sockets)
		{
			start_natpmp(s);
			remap_ports(remap_natpmp, *s);
		}
	}

	void session_impl::start_upnp()
	{
		for (auto const& s : m_listen_sockets)
		{
			start_upnp(s);
			remap_ports(remap_upnp, *s);
		}
	}

	void session_impl::start_upnp(std::shared_ptr<aux::listen_socket_t> const& s)
	{
		// until we support SSDP over an IPv6 network (
		// https://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol )
		// there's no point in starting upnp on one.
		if (is_v6(s->local_endpoint))
			return;

		// there's no point in starting the UPnP mapper for a network that isn't
		// connected to the internet. The whole point is to forward ports through
		// the gateway
		if ((s->flags & listen_socket_t::local_network)
			|| (s->flags & listen_socket_t::proxy))
			return;

		if (!s->upnp_mapper)
		{
			// the upnp constructor may fail and call the callbacks
			// into the session_impl.
			s->upnp_mapper = std::make_shared<upnp>(m_io_context, m_settings
				, *this, s->local_endpoint.address().to_v4(), s->netmask.to_v4(), s->device
				, listen_socket_handle(s));
			s->upnp_mapper->start();
		}
	}

	std::vector<port_mapping_t> session_impl::add_port_mapping(portmap_protocol const t
		, int const external_port
		, int const local_port)
	{
		std::vector<port_mapping_t> ret;
		for (auto& s : m_listen_sockets)
		{
			if (s->upnp_mapper) ret.push_back(s->upnp_mapper->add_mapping(t, external_port
				, tcp::endpoint(s->local_endpoint.address(), static_cast<std::uint16_t>(local_port))));
			if (s->natpmp_mapper) ret.push_back(s->natpmp_mapper->add_mapping(t, external_port
				, tcp::endpoint(s->local_endpoint.address(), static_cast<std::uint16_t>(local_port))));
		}
		return ret;
	}

	void session_impl::delete_port_mapping(port_mapping_t handle)
	{
		for (auto& s : m_listen_sockets)
		{
			if (s->upnp_mapper) s->upnp_mapper->delete_mapping(handle);
			if (s->natpmp_mapper) s->natpmp_mapper->delete_mapping(handle);
		}
	}

	void session_impl::stop_ip_notifier()
	{
		if (!m_ip_notifier) return;

		m_ip_notifier->cancel();
		m_ip_notifier.reset();
	}

	void session_impl::stop_natpmp()
	{
		for (auto& s : m_listen_sockets)
		{
			s->tcp_port_mapping[portmap_transport::natpmp] = listen_port_mapping();
			s->udp_port_mapping[portmap_transport::natpmp] = listen_port_mapping();
			if (!s->natpmp_mapper) continue;
			s->natpmp_mapper->close();
			s->natpmp_mapper.reset();
		}
	}

	void session_impl::stop_upnp()
	{
		for (auto& s : m_listen_sockets)
		{
			if (!s->upnp_mapper) continue;
			s->tcp_port_mapping[portmap_transport::upnp] = listen_port_mapping();
			s->udp_port_mapping[portmap_transport::upnp] = listen_port_mapping();
			s->upnp_mapper->close();
			s->upnp_mapper.reset();
		}
	}

	aux::external_ip session_impl::external_address() const
	{
		address ips[2][2];

		// take the first IP we find which matches each category
		for (auto const& i : m_listen_sockets)
		{
			address external_addr = i->external_address.external_address();
			if (ips[0][external_addr.is_v6()] == address())
				ips[0][external_addr.is_v6()] = external_addr;
			address local_addr = i->local_endpoint.address();
			if (ips[is_local(local_addr)][local_addr.is_v6()] == address())
				ips[is_local(local_addr)][local_addr.is_v6()] = local_addr;
		}

		return {ips[1][0], ips[0][0], ips[1][1], ips[0][1]};
	}

	// this is the DHT observer version. DHT is the implied source
	void session_impl::set_external_address(aux::listen_socket_handle const& iface
		, address const& ip, address const& source)
	{
		auto i = iface.m_sock.lock();
		TORRENT_ASSERT(i);
		if (!i) return;
		set_external_address(i, ip, source_dht, source);
	}

	void session_impl::get_peers(sha256_hash const& ih)
	{
		if (!m_alerts.should_post<dht_get_peers_alert>()) return;
		//m_alerts.emplace_alert<dht_get_peers_alert>(ih);
	}

	void session_impl::announce(sha256_hash const& ih, address const& addr
		, int port)
	{
		if (!m_alerts.should_post<dht_announce_alert>()) return;
		//m_alerts.emplace_alert<dht_announce_alert>(addr, port, ih);
	}

	void session_impl::outgoing_get_peers(sha256_hash const& target
		, sha256_hash const& sent_target, udp::endpoint const& ep)
	{
		if (!m_alerts.should_post<dht_outgoing_get_peers_alert>()) return;
		//m_alerts.emplace_alert<dht_outgoing_get_peers_alert>(target, sent_target, ep);
	}

#ifndef TORRENT_DISABLE_LOGGING
	bool session_impl::should_log(module_t) const
	{
		return m_alerts.should_post<dht_log_alert>();
	}

	TORRENT_FORMAT(3,4)
	void session_impl::log(module_t m, char const* fmt, ...)
	{
		if (!m_alerts.should_post<dht_log_alert>()) return;

		va_list v;
		va_start(v, fmt);
		m_alerts.emplace_alert<dht_log_alert>(
			static_cast<dht_log_alert::dht_module_t>(m), fmt, v);
		va_end(v);
	}

	void session_impl::log_packet(message_direction_t dir, span<char const> pkt
		, udp::endpoint const& node)
	{
		if (!m_alerts.should_post<dht_pkt_alert>()) return;

		dht_pkt_alert::direction_t d = dir == dht::dht_logger::incoming_message
			? dht_pkt_alert::incoming : dht_pkt_alert::outgoing;

		m_alerts.emplace_alert<dht_pkt_alert>(pkt, d, node);
	}

	bool session_impl::should_log_portmap(portmap_transport) const
	{
		return m_alerts.should_post<portmap_log_alert>();
	}

	void session_impl::log_portmap(portmap_transport transport, char const* msg
		, listen_socket_handle const& ls) const
	{
		listen_socket_t const* listen_socket = ls.get();
		if (m_alerts.should_post<portmap_log_alert>())
			m_alerts.emplace_alert<portmap_log_alert>(transport, msg
				, listen_socket ? listen_socket->local_endpoint.address() : address());
	}

	bool session_impl::should_log_lsd() const
	{
		return m_alerts.should_post<log_alert>();
	}

	void session_impl::log_lsd(char const* msg) const
	{
		if (m_alerts.should_post<log_alert>())
			m_alerts.emplace_alert<log_alert>(msg);
	}
#endif

	bool session_impl::on_dht_request(string_view query
		, dht::msg const& request, entry& response)
	{
#ifndef TORRENT_DISABLE_EXTENSIONS
		for (auto const& ext : m_ses_extensions[plugins_dht_request_idx])
		{
			if (ext->on_dht_request(query
				, request.addr, request.message, response))
				return true;
		}
#else
		TORRENT_UNUSED(query);
		TORRENT_UNUSED(request);
		TORRENT_UNUSED(response);
#endif
		return false;
	}

	void session_impl::set_external_address(
		tcp::endpoint const& local_endpoint, address const& ip
		, ip_source_t const source_type, address const& source)
	{
		auto sock = std::find_if(m_listen_sockets.begin(), m_listen_sockets.end()
			, [&](std::shared_ptr<listen_socket_t> const& v)
			{ return v->local_endpoint.address() == local_endpoint.address(); });

		if (sock != m_listen_sockets.end())
			set_external_address(*sock, ip, source_type, source);
	}

	void session_impl::set_external_address(std::shared_ptr<listen_socket_t> const& sock
		, address const& ip, ip_source_t const source_type, address const& source)
	{
		if (!sock->external_address.cast_vote(ip, source_type, source)) return;

#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("external address updated for %s [ new-ip: %s type: %d last-voter: %s ]"
				, sock->device.empty() ? print_endpoint(sock->local_endpoint).c_str() : sock->device.c_str()
				, print_address(ip).c_str()
				, static_cast<std::uint8_t>(source_type)
				, print_address(source).c_str());
		}
#endif

		if (m_alerts.should_post<external_ip_alert>())
			m_alerts.emplace_alert<external_ip_alert>(ip);
	}

#ifndef TORRENT_DISABLE_LOGGING
        tracker_logger::tracker_logger(session_interface& ses): m_ses(ses) {}
        void tracker_logger::tracker_warning(tracker_request const&
            , std::string const& str)
        {
            debug_log("*** tracker warning: %s", str.c_str());
        }

        void tracker_logger::tracker_response(tracker_request const&
            , libTAU::address const& tracker_ip
            , std::list<address> const& tracker_ips
            , struct tracker_response const& resp)
        {
            TORRENT_UNUSED(tracker_ips);
            debug_log("TRACKER RESPONSE\n"
                "interval: %d\n"
                "external ip: %s\n"
                "we connected to: %s\n"
                "peers:"
                , resp.interval.count()
                , print_address(resp.external_ip).c_str()
                , print_address(tracker_ip).c_str());

            for (auto const& p : resp.peers)
            {
                debug_log("  %16s %5d %s", p.hostname.c_str(), p.port
                    , p.pid.is_all_zeros() ? "" : to_hex(p.pid).c_str());
            }
            for (auto const& p : resp.peers4)
            {
                debug_log("  %s:%d", print_address(address_v4(p.ip)).c_str(), p.port);
            }
            for (auto const& p : resp.peers6)
            {
                debug_log("  [%s]:%d", print_address(address_v6(p.ip)).c_str(), p.port);
            }
        }

        void tracker_logger::tracker_request_error(tracker_request const&
            , error_code const& ec, operation_t const op, std::string const& str
            , seconds32 const retry_interval)
        {
            TORRENT_UNUSED(retry_interval);
            debug_log("*** tracker error: [%s] %s %s"
                , operation_name(op), ec.message().c_str(), str.c_str());
        }

        bool tracker_logger::should_log() const
        {
            return m_ses.alerts().should_post<log_alert>();
        }

        void tracker_logger::debug_log(const char* fmt, ...) const noexcept try
        {
            if (!m_ses.alerts().should_post<log_alert>()) return;

            va_list v;
            va_start(v, fmt);
            m_ses.alerts().emplace_alert<log_alert>(fmt, v);
            va_end(v);
        }
        catch (std::exception const&) {}
#endif // TORRENT_DISABLE_LOGGING
}
