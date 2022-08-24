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
#include <tuple>

#include "libTAU/aux_/disable_warnings_push.hpp"
#include <filesystem>
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
#include "libTAU/ip_filter.hpp"
#include "libTAU/socket.hpp"
#include "libTAU/account_manager.hpp"
#include "libTAU/crypto.hpp"
#include "libTAU/aux_/generate_port.hpp"
#include "libTAU/aux_/session_impl.hpp"
#include "libTAU/aux_/ip_helpers.hpp" // for is_local() etc.

#include "libTAU/aux_/common.h"

#include "libTAU/kademlia/ed25519.hpp"
#include "libTAU/kademlia/dht_tracker.hpp"
#include "libTAU/kademlia/types.hpp"
#include "libTAU/kademlia/node_entry.hpp"
#include "libTAU/kademlia/node_id.hpp"
#include "libTAU/kademlia/bs_nodes_db_sqlite.hpp"

#include "libTAU/communication/message.hpp"
#include "libTAU/communication/communication.hpp"

#include "libTAU/blockchain/account.hpp"
#include "libTAU/blockchain/block.hpp"
#include "libTAU/blockchain/transaction.hpp"

#include "libTAU/aux_/enum_net.hpp"
#include "libTAU/upnp.hpp"
#include "libTAU/natpmp.hpp"
#include "libTAU/aux_/instantiate_connection.hpp"
#include "libTAU/aux_/random.hpp"
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
#include <snappy-c.h>
#ifdef TORRENT_ENABLE_CRASH_ANA
#include <breakpad/client/linux/handler/exception_handler.h>
#endif

// for logging the size of DHT structures
#include <libTAU/kademlia/find_data.hpp>
#include <libTAU/kademlia/refresh.hpp>
#include <libTAU/kademlia/node.hpp>
#include <libTAU/kademlia/observer.hpp>
#include <libTAU/kademlia/item.hpp>

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
	val = s.dict_find_int("invoke_limit");
	if (val) sett.set_int(settings_pack::dht_invoke_limit, int(val.int_value()));
	val = s.dict_find_int("invoke_window");
	if (val) sett.set_int(settings_pack::dht_invoke_window, int(val.int_value()));
	val = s.dict_find_int("bootstrap_interval");
	if (val) sett.set_int(settings_pack::dht_bootstrap_interval, int(val.int_value()));
	val = s.dict_find_int("time_offset");
	if (val) sett.set_int(settings_pack::dht_time_offset, int(val.int_value()));
	val = s.dict_find_int("ping_interval");
	if (val) sett.set_int(settings_pack::dht_ping_interval, int(val.int_value()));
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
		//rx, tx max
		unsigned long int total_bytes = 0;
		for (auto const& uep : unspecified_eps)
		{
			for (auto const& ipface : ifs)
			{
				if (!uep.device.empty() && uep.device != ipface.name)
					continue;
				if (std::any_of(eps.begin(), eps.end(), [&](listen_endpoint_t const& e)
				{
					// ignore device name because we don't want to create
					// duplicates if the user explicitly configured an address
					// without a device name
					return e.addr == ipface.interface_address
						&& e.port == uep.port;
				}))
				{
					continue;
				}

				// 1st
				if(ipface.interface_address == uep.addr)
				{
					eps.emplace_back(ipface.interface_address, uep.port, uep.device
						, uep.ssl, uep.flags | listen_socket_t::was_expanded
					| listen_socket_flags_t{});
					break;	
				}

				unsigned long int tmp_bytes = ipface.rx_bytes + ipface.tx_bytes
                                 + ipface.rx_errors + ipface.tx_errors
                                 + ipface.rx_dropped + ipface.tx_dropped;

				if_state ipface_state = if_state::unknown;

				if(0 == total_bytes) {
					eps.emplace_back(ipface.interface_address, uep.port, uep.device
						, uep.ssl, uep.flags | listen_socket_t::was_expanded | listen_socket_flags_t{});
					total_bytes = tmp_bytes;
					ipface_state = ipface.state; 
				}

				if(ipface_state == if_state::unknown) {
					if(ipface.state == if_state::up) {
						eps.pop_back();
						eps.emplace_back(ipface.interface_address, uep.port, uep.device
							, uep.ssl, uep.flags | listen_socket_t::was_expanded | listen_socket_flags_t{});
						total_bytes = tmp_bytes;
					} else if(tmp_bytes > total_bytes) {
						eps.pop_back();
						eps.emplace_back(ipface.interface_address, uep.port, uep.device
							, uep.ssl, uep.flags | listen_socket_t::was_expanded | listen_socket_flags_t{});
						total_bytes = tmp_bytes;
					}
				} else {
					if(ipface.state == if_state::up && tmp_bytes > total_bytes) {
						eps.pop_back();
						eps.emplace_back(ipface.interface_address, uep.port, uep.device
							, uep.ssl, uep.flags | listen_socket_t::was_expanded | listen_socket_flags_t{});
						total_bytes = tmp_bytes;
					}
					ipface_state = if_state::up;
				}
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

#ifdef TORRENT_ENABLE_CRASH_ANA
	bool crash_dump_call_before(void* context)
    {
        alert_manager* ma = static_cast<alert_manager*>(context);
        ma->emplace_alert<session_error_alert>(error_code(), "Crashed ERROR");
        return true;
    }
#endif

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
		, session_flags_t const flags)
		: m_settings(pack)
		, m_io_context(ioc)
		, m_alerts(m_settings.get_int(settings_pack::alert_queue_size)
			, alert_category_t{static_cast<unsigned int>(m_settings.get_int(settings_pack::alert_mask))})
		, m_host_resolver(m_io_context)
		, m_work(make_work_guard(m_io_context))
		, m_timer(m_io_context)
		, m_refer_switch(m_settings.get_bool(settings_pack::auto_relay))
		, m_session_time(total_milliseconds(std::chrono::system_clock::now().time_since_epoch()))
		, m_created(clock_type::now())
		, m_last_tick(total_milliseconds(std::chrono::system_clock::now().time_since_epoch()))
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
		m_local_peer_class = m_classes.new_peer_class("local");
		// local peers are always unchoked
		m_classes.at(m_local_peer_class)->ignore_unchoke_slots = true;
		// local peers are allowed to exceed the normal connection
		// limit by 50%
		m_classes.at(m_local_peer_class)->connection_limit_factor = 150;

		TORRENT_ASSERT(m_global_class == session::global_peer_class_id);
		TORRENT_ASSERT(m_local_peer_class == session::local_peer_class_id);

		init_peer_class_filter(true);

#ifndef TORRENT_DISABLE_LOGGING

		session_log("version: %s " PRIx64 , lt::version_str);

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
		if (should_log(aux::LOG_LEVEL::LOG_INFO))
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

        if(m_last_reopen == 0) {
		    reopen_listen_sockets(false);
            m_last_reopen = m_session_time;
            m_dht_nodes_non_zero = m_last_reopen;
        }
	}

	void session_impl::on_tick(error_code const& e)
	{
		TORRENT_ASSERT(is_single_thread());

		if (!m_abort) {

            //time modify 
			session_time_modification();
        	m_timer.expires_after(seconds(1));
			m_timer.async_wait([this](error_code const& e) {
					this->wrap(&session_impl::on_tick, e); });

            //peer check and reopen
		    if (m_dht)
			    m_dht->update_stats_counters(m_stats_counters);

            int num_dht_nodes = m_stats_counters[counters::dht_nodes];

            if(0 == num_dht_nodes) {
                int max_time = m_settings.get_int(settings_pack::max_time_peers_zero);
                if(m_session_time - m_dht_nodes_non_zero >= max_time) {
                    reopen_listen_sockets(false);
                    m_dht_nodes_non_zero = m_session_time;
                }
            } else {
                m_dht_nodes_non_zero = m_session_time;
            }

#ifndef TORRENT_DISABLE_LOGGING
		    session_log("TICK, dht nodes number: %d", num_dht_nodes);
#endif
		}
	}

	void session_impl::session_time_modification(std::int64_t time)
	{
		std::int64_t current_time = total_milliseconds(std::chrono::system_clock::now().time_since_epoch());
		std::int64_t delta_time = current_time - m_last_tick;
		m_session_time += delta_time;
		m_last_tick = current_time;

		if(time != 0) {
			std::int64_t time_s  = time/1000;
			std::int64_t m_time_s  = m_session_time/1000;
			double sigma = 30;
			double f1 = 1.0/(sigma * 2.50663);
			double f21 = -1.0 * pow(time_s - m_time_s, 2);
			double f22 = 2.0 * pow(sigma, 2);
			double f2 = f21 / f22;
			double gauss_factor = f1* pow(2.71828, f2);
			m_session_time = ((1.0 - gauss_factor) * m_time_s + gauss_factor * time_s)* 1000;
		}

	}

#ifdef TORRENT_ENABLE_CRASH_ANA
	void session_impl::crash_dump_initial()
	{
        std::string dump_file_dir = "";
#ifdef TORRENT_ANDROID			
        dump_file_dir = m_settings.get_str(settings_pack::dump_dir);
#else
        dump_file_dir = std::filesystem::path(getenv("HOME")).string() + "/"+ m_settings.get_str(settings_pack::dump_dir);
#endif
        // create the directory for storing dump data
 		if(!std::filesystem::is_directory(dump_file_dir)) {
			if(!std::filesystem::create_directories(dump_file_dir)){
#ifndef TORRENT_DISABLE_LOGGING
				session_log("failed create directory for storing dump data: %s", dump_file_dir.c_str());
#endif
				TORRENT_ASSERT(!std::filesystem::create_directories(dump_file_dir));
				m_abort = true;	
			}
		}

        google_breakpad::MinidumpDescriptor descriptor(dump_file_dir);
        //google_breakpad::ExceptionHandler eh(descriptor, crash_dump_call_before, NULL, static_cast<void*>(&m_alerts), true, -1);
        google_breakpad::ExceptionHandler eh(descriptor, NULL, NULL, NULL, true, -1);
	}
#endif

    void session_impl::crash_test()
    {
#ifdef TORRENT_ENABLE_CRASH_ANA
        std::string dump_file_dir = "";
#ifdef TORRENT_ANDROID			
        dump_file_dir = m_settings.get_str(settings_pack::dump_dir);
#else
        dump_file_dir = std::filesystem::path(getenv("HOME")).string() + "/"+ m_settings.get_str(settings_pack::dump_dir);
#endif
        // create the directory for storing dump data
 		if(!std::filesystem::is_directory(dump_file_dir)) {
			if(!std::filesystem::create_directories(dump_file_dir)){
#ifndef TORRENT_DISABLE_LOGGING
				session_log("failed create directory for storing dump data: %s", dump_file_dir.c_str());
#endif
				TORRENT_ASSERT(!std::filesystem::create_directories(dump_file_dir));
				m_abort = true;	
			}
		}

        google_breakpad::MinidumpDescriptor descriptor(dump_file_dir);
        //google_breakpad::ExceptionHandler eh(descriptor, crash_dump_call_before, NULL, static_cast<void*>(&m_alerts), true, -1);
        google_breakpad::ExceptionHandler eh(descriptor, NULL, NULL, NULL, true, -1);
        volatile int* a = (int*)(NULL);
        *a = 1; 
#endif
    }

    void session_impl::sql_test()
    {
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log(aux::LOG_LEVEL::LOG_INFO))
		{
			session_log("sql test start");
		}
#endif

        //create test table; key, timestamp, value
        std::string create_table_sql = "CREATE TABLE IF NOT EXISTS SQL_TEST (key char(33), time int, value text, PRIMARY KEY(key));";
        char *errmsg = nullptr;
        int ok = sqlite3_exec(m_sqldb, create_table_sql.c_str(), nullptr, nullptr, &errmsg);
        if (ok != SQLITE_OK) {
#ifndef TORRENT_DISABLE_LOGGING
		    if (should_log(aux::LOG_LEVEL::LOG_INFO))
		    {
			    session_log("sql test create table error: %s", errmsg);
		    }
#endif
            sqlite3_free(errmsg);
            return;
        }

        //create index on time
        std::string create_index_sql = "CREATE INDEX time_id ON SQL_TEST(time);";
        errmsg = nullptr;
        ok = sqlite3_exec(m_sqldb, create_index_sql.c_str(), nullptr, nullptr, &errmsg);
        if (ok != SQLITE_OK) {
#ifndef TORRENT_DISABLE_LOGGING
		    if (should_log(aux::LOG_LEVEL::LOG_INFO))
		    {
			    session_log("sql test create index error: %s", errmsg);
		    }
#endif
            sqlite3_free(errmsg);
            return;
        }

#ifndef TORRENT_DISABLE_LOGGING
		if (should_log(aux::LOG_LEVEL::LOG_INFO))
		{
			session_log("sql test insert start");
		}
#endif
        //value
        int account_total = 30;
        std::string account_temp = "9df518ee450ded0a659aeb4bc5bec636_1000000_1000_1231";
        std::string account = "";
        for(int i = 0; i < account_total; i++) {
            account += (account_temp + "_");
        }
        account += account_temp;

        //insert
        int count = 10;
        int seg = 5000;
        int icount = 1;
        std::string key_value[seg];
        int time_value[seg];
        while(icount <= count)
        {
            time_point const data_start = aux::time_now();
            for(int i = 0; i < seg; i++) {

                //key
                std::vector<char> t_key = {'s','q','l','_', 't','e','s', 't'}; //len:13, + \0
                char k_cc[8] = {'0','0','0','0','0','0','0'};
                sprintf(k_cc, "%d", i+icount*seg);
                for(int j = 0; j < 8; j++)
                    t_key.push_back(k_cc[j]);
                sha1_hash hash_temp = hasher(t_key).final();
                key_value[i] = aux::toHex(hash_temp);

                //time
                time_value[i] = 1655769821 + i%90;
            }
            time_point const data_end = aux::time_now();
            int const data_interval_ms = aux::numeric_cast<int>(total_milliseconds(data_end - data_start));
#ifndef TORRENT_DISABLE_LOGGING
		    if (should_log(aux::LOG_LEVEL::LOG_INFO))
		    {
			    session_log("%d round, data takes in: %d items, takes: %d ms" , icount, seg, data_interval_ms);
		    }
#endif
            time_point const insert_start = aux::time_now();

            sqlite3_exec(m_sqldb, "BEGIN TRANSACTION", NULL, NULL, &errmsg);

            sqlite3_stmt * stmt;
            std::string insert_sql_temp = "INSERT INTO SQL_TEST VALUES (?, ?, ?)";
            ok = sqlite3_prepare_v2(m_sqldb, insert_sql_temp.c_str(), -1, &stmt, nullptr);
            if (ok != SQLITE_OK) {
                return;
            }
            for(int i = 0; i < seg; i++) {
                sqlite3_bind_text(stmt, 1, key_value[i].c_str(), key_value[i].size(), nullptr);
                sqlite3_bind_int(stmt, 2, time_value[i]);
                sqlite3_bind_text(stmt, 3, account.c_str(), account.size(), nullptr);
                ok = sqlite3_step(stmt);
                if (ok != SQLITE_DONE) {
                    return;
                }
                sqlite3_reset(stmt);
            }

            sqlite3_exec(m_sqldb, "COMMIT TRANSACTION", NULL, NULL, &errmsg);

            sqlite3_finalize(stmt);

            time_point const insert_end = aux::time_now();
            int const insert_interval_ms = aux::numeric_cast<int>(total_milliseconds(insert_end - insert_start));
#ifndef TORRENT_DISABLE_LOGGING
		    if (should_log(aux::LOG_LEVEL::LOG_INFO))
		    {
			    session_log("%d round, data insert takes in: %d items, takes: %d ms" , icount, seg, insert_interval_ms);
		    }
#endif
            icount++;
        }

        //select test
        time_point const select_start = aux::time_now();
        std::string select_sql = "SELECT * FROM SQL_TEST WHERE time= 1655769862;";
        sqlite3_stmt * stmt_select;
        ok = sqlite3_prepare_v2(m_sqldb, select_sql.c_str(), -1, &stmt_select, nullptr);
        if (ok == SQLITE_OK) {
            for (;sqlite3_step(stmt_select) == SQLITE_ROW;) {
                const unsigned char *key_char = sqlite3_column_text(stmt_select, 0);
                auto key_size = sqlite3_column_bytes(stmt_select, 0);
                std::string key_str(key_char, key_char + key_size);
            }
        }
        time_point const select_end = aux::time_now();
        int const sql_interval_ms = aux::numeric_cast<int>(total_microseconds(select_end - select_start));
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log(aux::LOG_LEVEL::LOG_INFO))
		{
			session_log("sql select test takes: %d us" , sql_interval_ms);
		}
#endif

        //insert test
        int insert_test_number = 100;
        for(int i = 0; i < insert_test_number; i++) {
            //key
            std::vector<char> t_key = {'s','q','l','_', 'i','n','s', 'e', 'r', 't'}; //len:13, + \0
            char k_cc[8] = {'0','0','0','0','0','0','0'};
            sprintf(k_cc, "%d", i);
            for(int j = 0; j < 8; j++)
                t_key.push_back(k_cc[j]);
            sha1_hash hash_temp = hasher(t_key).final();
            key_value[i] = aux::toHex(hash_temp);

            //time
            time_value[i] = 1655769821 + i%9000;
        }

        time_point const insert_start_test = aux::time_now();

        sqlite3_exec(m_sqldb, "BEGIN TRANSACTION", NULL, NULL, &errmsg);

        sqlite3_stmt * stmt_insert;
        std::string insert_sql_temp = "INSERT INTO SQL_TEST VALUES (?, ?, ?)";
        ok = sqlite3_prepare_v2(m_sqldb, insert_sql_temp.c_str(), -1, &stmt_insert, nullptr);
        if (ok != SQLITE_OK) {
            return;
        }
        for(int i = 0; i < insert_test_number; i++) {
            sqlite3_bind_text(stmt_insert, 1, key_value[i].c_str(), key_value[i].size(), nullptr);
            sqlite3_bind_int(stmt_insert, 2, time_value[i]);
            sqlite3_bind_text(stmt_insert, 3, account.c_str(), account.size(), nullptr);
            ok = sqlite3_step(stmt_insert);
            if (ok != SQLITE_DONE) {
                return;
            }
            sqlite3_reset(stmt_insert);
        }

        sqlite3_exec(m_sqldb, "COMMIT TRANSACTION", NULL, NULL, &errmsg);
        sqlite3_finalize(stmt_insert);

        time_point const insert_end_test = aux::time_now();
        int const insert_interval_test = aux::numeric_cast<int>(total_milliseconds(insert_end_test - insert_start_test));
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log(aux::LOG_LEVEL::LOG_INFO))
		{
		    session_log(" data insert %d items, test takes into: %d items, takes: %d ms" , insert_test_number, seg*count, insert_interval_test);
		}
#endif

    }

	session_params session_impl::session_state(save_state_flags_t const flags) const
	{
		TORRENT_ASSERT(is_single_thread());

		session_params ret;
		if (flags & session::save_settings)
			ret.settings = non_default_settings(m_settings);

		if (m_dht && (flags & session::save_dht_state))
			ret.dht_state = m_dht->state();

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
		stop_blockchain();


		if(m_kvdb) {
			delete m_kvdb;
		}

		if (m_sqldb) {
			sqlite3_close_v2(m_sqldb);
			m_sqldb = nullptr;
		}

#ifndef TORRENT_DISABLE_LOGGING
		session_log(" aborting all tracker requests");
#endif

		// close the listen sockets
		for (auto const& l : m_listening_sockets)
		{
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

		m_alerts.emplace_alert<session_stop_over_alert>(true);
	}

	void session_impl::abort_stage2() noexcept
	{
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
		apply_pack(&pack, m_settings, this);
	}

	std::shared_ptr<listen_socket_t> session_impl::setup_listener(
		listen_endpoint_t const& lep, error_code& ec)
	{
		int retries = m_settings.get_int(settings_pack::max_retry_port_bind);
		udp::endpoint udp_bind_ep(lep.addr, std::uint16_t(lep.port));

#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("attempting to open listen socket to: %s on device: %s %s%s%s%s%s"
				, print_endpoint(udp_bind_ep).c_str(), lep.device.c_str()
				, (lep.ssl == transport::ssl) ? "ssl " : ""
				, (lep.flags & listen_socket_t::local_network) ? "local-network " : ""
				, (lep.flags & listen_socket_t::accept_incoming) ? "accept-incoming " : "no-incoming "
				, (lep.flags & listen_socket_t::was_expanded) ? "expanded-ip " : ""
				, (lep.flags & listen_socket_t::proxy) ? "proxy " : "");
		}
#endif

		auto ret = std::make_shared<listen_socket_t>();
		ret->ssl = lep.ssl;
		ret->original_port = udp_bind_ep.port();
		ret->flags = lep.flags;
		ret->netmask = lep.netmask;
		operation_t last_op = operation_t::unknown;

		socket_type_t const udp_sock_type
			= (lep.ssl == transport::ssl)
			? socket_type_t::utp_ssl
			: socket_type_t::utp;

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
					, udp_bind_ep, last_op, ec, udp_sock_type);

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
					, print_endpoint(udp_bind_ep).c_str()
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
					, udp_bind_ep, last_op, ec, udp_sock_type);

			return ret;
		}

		// if we did not open a TCP listen socket, ret->local_endpoint was never
		// initialized, so do that now, based on the UDP socket
		if (ret->flags & listen_socket_t::accept_incoming)
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
			session_log(" listening on: %s UDP port: %d"
				, udp_bind_ep.address().to_string().c_str(), ret->udp_external_port());
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
			//default, libTAU this way
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

    // libTAU 
	void interface_to_endpoints(listen_socket_flags_t flags
		, span<ip_interface const> const ifs
		, std::vector<listen_endpoint_t>& eps
        , int port)
	{
		flags |= listen_socket_flags_t{};
		transport const ssl = transport::plaintext;

		flags |= listen_socket_t::was_expanded;

		// this is the case where device names a network device. We need to
		// enumerate all IPs associated with this device
		for (auto const& ipface : ifs)
		{
			bool const local = ipface.interface_address.is_loopback()
				|| is_link_local(ipface.interface_address);

			eps.emplace_back(ipface.interface_address, port, std::string{}
				, ssl, flags | (local ? listen_socket_t::local_network : listen_socket_flags_t{}));
		}
	}

    void session_impl::disconnect(){
		auto remove_iter = m_listening_sockets.begin();
		while (remove_iter != m_listening_sockets.end())
		{
			if (m_dht)
				m_dht->delete_socket(*remove_iter);

#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("disconnect, closing listen socket for %s on device \"%s\""
					, print_endpoint((*remove_iter)->local_endpoint).c_str()
					, (*remove_iter)->device.c_str());
			}
#endif
			if ((*remove_iter)->udp_sock) (*remove_iter)->udp_sock->sock.close();
			if ((*remove_iter)->natpmp_mapper) (*remove_iter)->natpmp_mapper->close();
			if ((*remove_iter)->upnp_mapper) (*remove_iter)->upnp_mapper->close();
			remove_iter = m_listening_sockets.erase(remove_iter);
		}
        //TODO: modify the tick
    }

    void session_impl::reconnect(){
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("reconnect listen socket");
			}
#endif
        reopen_listen_sockets(false);
        //TODO: modify the tick
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

			//delete unused ip_interface
			// preferred == true, v4, state(up, unknow), not local
			std::vector<ip_interface> ifs_tau;
			for (auto const& ipface : ifs)
			{
				if (!ipface.preferred || ipface.interface_address.is_v6())
				{
					continue;
				}

				if (ipface.state != if_state::up && ipface.state != if_state::unknown)
				{
					continue;
				}

				bool const local
					= ipface.interface_address.is_loopback()
					|| is_link_local(ipface.interface_address)
					|| (ipface.flags & if_flags::loopback)
					|| (!is_global(ipface.interface_address)
						&& !(ipface.flags & if_flags::pointopoint)
						&& !has_internet_route(ipface.name, family(ipface.interface_address), routes));
				if(local)
				{
					continue;
				}

#ifndef TORRENT_DISABLE_LOGGING
			session_log("ip_interface preferred %d, name: %s, netmask: %s, address: %s, flags: %d, state: %d, rx_bytes: %u, tx_bytes: %u, rx_errors: %u, tx_errors: %u, rx_dropped: %u, tx_dropped: %u", 
						 ipface.preferred, ipface.name, 
						 print_address(ipface.netmask).c_str(), 
						 print_address(ipface.interface_address).c_str(), 
						 ipface.flags & if_flags::up, ipface.state,
						 ipface.rx_bytes, ipface.tx_bytes,
						 ipface.rx_errors, ipface.tx_errors,
						 ipface.rx_dropped, ipface.tx_dropped);
#endif
				ifs_tau.push_back(ipface);
			}

#ifndef TORRENT_DISABLE_LOGGING
			session_log("initial listen sockets size: %d, netlink found size: %d", eps.size(), ifs_tau.size());
#endif
            //delete one useless when >=2 v4 ip addresses found
            if(ifs_tau.size() >= 2)
            {
                int ifs_tau_discovered = ifs_tau.size();
                int sockets_listened = m_listened_sockets.size();
                //process m_listened_sockets
                if(sockets_listened > 0) {
                    for(auto it = m_listened_sockets.begin() ; it != m_listened_sockets.end() ;)
                    {
                        bool flag = false;
                        for(int j = 0 ; j < ifs_tau_discovered ; j++)
                        {
                            if(!strcmp(ifs_tau[j].name, (*it)->device.c_str())) {
                                flag = true;
                            }
                        }

                        if(!flag) {
#ifndef TORRENT_DISABLE_LOGGING
                            session_log("delete listened sockets, diff from netlink interfaces: %s", (*it)->device.c_str());
#endif
                            it = m_listened_sockets.erase(it);
                        } else {
                            it++;
                        }
                    }
                    if(m_listened_sockets.size() >= ifs_tau_discovered) {
#ifndef TORRENT_DISABLE_LOGGING
                        session_log("clear listened sockets, try each socket again");
#endif
                        m_listened_sockets.clear();
                    }
                }
                // delete listened sockets
                for(auto it = ifs_tau.begin() ; it != ifs_tau.end() ;)
                {
                    if(m_listened_sockets.size() > 0) {
                        bool flag_delete = false;
                        for( int j = 0; j < m_listened_sockets.size(); j++) {
#ifndef TORRENT_DISABLE_LOGGING
                            session_log("ready to delete in 1st name: |%s|, former name: |%s|", it->name, m_listened_sockets[j]->device.c_str());
#endif
                            if(!strcmp(it->name, m_listened_sockets[j]->device.c_str())) {
#ifndef TORRENT_DISABLE_LOGGING
                                session_log("delete in 1st name: %s, former name: %s", it->name, m_listened_sockets[j]->device.c_str());
#endif
                                it = ifs_tau.erase(it);
                                flag_delete = true;
                            }
                        }
                        if(!flag_delete) it++;
                    } else {
                        it++;
                    }
                }
            }

#ifndef TORRENT_DISABLE_LOGGING
			session_log("libTAU netlink found after delete size: %d", ifs_tau.size());
#endif
#ifdef TORRENT_ANDROID			
            int port = get_port_from_local();
			interface_to_endpoints(listen_socket_t::accept_incoming, ifs_tau, eps, port);
#else
			// expand device names and populate eps
			for (auto & iface : m_listen_interfaces)
			{
                //update port 
				// now we have a device to bind to. This device may actually just be an
				// IP address or a device name. In case it's a device name, we want to
				// (potentially) end up binding a socket for each IP address associated
				// with that device.
				interface_to_endpoints(iface, listen_socket_t::accept_incoming, ifs_tau, eps);
			}
			expand_unspecified_address(ifs_tau, routes, eps);
#ifndef TORRENT_DISABLE_LOGGING
			session_log("expand unspecified listen sockets size: %d", eps.size());
#endif
#endif
			expand_devices(ifs_tau, eps);
#ifndef TORRENT_DISABLE_LOGGING
			session_log("expand listen sockets size: %d", eps.size());
#endif
		}

		//auto remove_iter = partition_listen_sockets(eps, m_listening_sockets);
		auto remove_iter = m_listening_sockets.begin();

		while (remove_iter != m_listening_sockets.end())
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
			if ((*remove_iter)->udp_sock) (*remove_iter)->udp_sock->sock.close();
			if ((*remove_iter)->natpmp_mapper) (*remove_iter)->natpmp_mapper->close();
			if ((*remove_iter)->upnp_mapper) (*remove_iter)->upnp_mapper->close();
			remove_iter = m_listening_sockets.erase(remove_iter);
		}

		// all sockets in there stayed the same. Only sockets after this point are
		// new and should post alerts
		int const existing_sockets = int(m_listening_sockets.size());

		m_stats_counters.set_value(counters::has_incoming_connections
			, std::any_of(m_listening_sockets.begin(), m_listening_sockets.end()
				, [](std::shared_ptr<listen_socket_t> const& l)
				{ return l->incoming_connection; }));

		// Only 1 ep in libTAU
        int eps_size = eps.size();
		while(eps_size > 1)
		{
			//only contain one ep for binding
			for(int i = 1; i <= eps_size - 1; i++)
			{
                srand((int)time(NULL));
	    		int rand_select = rand()%eps.size();
#ifndef TORRENT_DISABLE_LOGGING
				session_log("delete in random ep(%s) device: %s"
						, print_endpoint(eps[rand_select].addr, eps[rand_select].port).c_str()
						, eps[rand_select].device.c_str());
#endif
				eps.erase(eps.begin()+rand_select);
			}
            eps_size = eps.size();
		}

		// open new sockets on any endpoints that didn't match with
		// an existing socket
		for (auto const& ep : eps)
#ifndef BOOST_NO_EXCEPTIONS
			try
#endif
		{
			std::shared_ptr<listen_socket_t> s = setup_listener(ep, ec);
			if (!ec && s->udp_sock && !(s->flags & listen_socket_t::local_network) && m_listening_sockets.empty())
			{
#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("Setup Listener(%s) device: %s"
						, print_endpoint(ep.addr, ep.port).c_str()
						, ep.device.c_str());
				}
#endif // TORRENT_DISABLE_LOGGING
				m_listening_sockets.emplace_back(s);
                bool flag_listen = false;
                for(int i = 0; i < m_listened_sockets.size(); i++) {
#ifndef TORRENT_DISABLE_LOGGING
                    session_log("Listened sockets: %s", m_listened_sockets[i]->device.c_str());
#endif
                    if(!strcmp(ep.device.c_str(), m_listened_sockets[i]->device.c_str())) {
#ifndef TORRENT_DISABLE_LOGGING
                        session_log("Found in listened sockets: %s", m_listened_sockets[i]->device.c_str());
#endif
                        flag_listen = true;
                    }
                }
                if(!flag_listen)
				    m_listened_sockets.emplace_back(s);

				if (m_dht && s->ssl != transport::ssl)
				{
					reset_refer_switch();
					m_dht->stop();
					m_dht->new_socket(m_listening_sockets.back());
					//TODO: get and add nodes from former node's routing table
					for (auto const& n : m_dht_router_nodes)
					{
						m_dht->add_router_node(n);
					}

					auto cb = [this](
						std::vector<std::pair<dht::node_entry, std::string>> const&)
					{
						if (m_alerts.should_post<dht_bootstrap_alert>())
						m_alerts.emplace_alert<dht_bootstrap_alert>();
					};
					m_dht->start(cb);
				}
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

		if (m_listening_sockets.empty())
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log("giving up on binding listen sockets");
#endif
			return;
		}

		auto const new_sockets = span<std::shared_ptr<listen_socket_t>>(
			m_listening_sockets).subspan(existing_sockets);

		// now, send out listen_succeeded_alert for the listen sockets we are
		// listening on
		if (m_alerts.should_post<listen_succeeded_alert>())
		{
			for (auto const& l : new_sockets)
			{
				error_code err;
				if (l->udp_sock && !(l->flags & listen_socket_t::local_network))
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
			for (auto const& s : m_listening_sockets)
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
        int max_interval = m_settings.get_int(settings_pack::reopen_time_interval);
        if((m_session_time - m_last_reopen >= max_interval)||(m_last_reopen == 0)) {
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("Reopen network from application and remap %d", bool(options & session_handle::reopen_map_ports));
			}
#endif
		    reopen_listen_sockets(bool(options & session_handle::reopen_map_ports));
            m_last_reopen = m_session_time;
            m_dht_nodes_non_zero = m_last_reopen;
        }
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
		udp::endpoint const udp_ep = s.udp_sock ? s.udp_sock->sock.local_endpoint() : udp::endpoint();

		if ((mask & remap_natpmp) && s.natpmp_mapper)
		{
			map_port(*s.natpmp_mapper, portmap_protocol::udp, make_tcp(udp_ep)
				, s.udp_port_mapping[portmap_transport::natpmp].mapping);
		}
		if ((mask & remap_upnp) && s.upnp_mapper)
		{
			map_port(*s.upnp_mapper, portmap_protocol::udp, make_tcp(udp_ep)
				, s.udp_port_mapping[portmap_transport::upnp].mapping);
		}
	}

	int session_impl::external_udp_port(address const& local_address) const
	{
		auto ls = std::find_if(m_listening_sockets.begin(), m_listening_sockets.end()
			, [&](std::shared_ptr<listen_socket_t> const& e)
		{
			return e->local_endpoint.address() == local_address;
		});

		if (ls != m_listening_sockets.end())
			return (*ls)->udp_external_port();
		else
			return -1;
	}

	udp::endpoint session_impl::external_udp_endpoint() const
	{
		// take the first v4 IP
		for (auto const& i : m_listening_sockets)
		{
			address external_addr = i->external_address.external_address();
			address& upnp_mapping_addr = i->udp_address_mapping[portmap_transport::upnp];
			address& natpmp_mapping_addr = i->udp_address_mapping[portmap_transport::natpmp];

			if (!external_addr.is_unspecified() && external_addr.is_v4())
			{
				if (external_addr == upnp_mapping_addr
					&& i->udp_port_mapping[portmap_transport::upnp].port != 0)
				{
					return {external_addr, i->udp_port_mapping[portmap_transport::upnp].port};
				}

				if (external_addr == natpmp_mapping_addr
					&& i->udp_port_mapping[portmap_transport::natpmp].port != 0)
				{
					return {external_addr, i->udp_port_mapping[portmap_transport::natpmp].port};
				}
			}
		}

		return {address(), 0};
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
		}
	}

	void session_impl::send_udp_packet_listen_encryption(aux::listen_socket_handle const& sock
		, udp::endpoint const& ep
		, sha256_hash const& pk
		, span<char const> p
		, error_code& ec
		, udp_send_flags_t const flags)
	{
		m_raw_send_udp_packet.clear();

#ifdef TORRENT_ENABLE_UDP_COMPRESS
		bool c_result = compress_udp_packet(p, m_raw_send_udp_packet);
		if(!c_result){
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("UDP Compress Error!!!");
			}
#endif
			return;
		}
#else
		m_raw_send_udp_packet.insert(0, p.data(), p.size());
#endif

#ifdef TORRENT_ENABLE_UDP_ENCRYPTION
		m_encrypted_udp_packet.clear();
		std::string err_str;
		bool result = encrypt_udp_packet(pk
			, m_raw_send_udp_packet
			, m_encrypted_udp_packet
			, err_str);

		if (!result)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("UDP encryption error: %s", err_str.c_str());
			}
#endif
			// set error_code
			ec = errors::encrypt_udp_packet;
			return;
		}
		
		// attach self public key to the header of udp packet
		m_encrypted_udp_packet.insert(0
			, m_account_manager->pub_key().bytes.data(), 32);

		send_udp_packet_listen(sock, ep, m_encrypted_udp_packet, ec, flags);

#else
		m_raw_send_udp_packet.insert(0
			, m_account_manager->pub_key().bytes.data(), 32);

		send_udp_packet_listen(sock, ep, m_raw_send_udp_packet, ec, flags);
#endif

/*
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("send UDP encryption packet: %s, raw: %s"
				, aux::to_hex(m_encrypted_udp_packet).c_str()
				, aux::to_hex(m_raw_send_udp_packet).c_str());
		}
#endif
*/
		// send to udp socket
	}

#ifdef TORRENT_ENABLE_UDP_COMPRESS
	bool session_impl::compress_udp_packet(span<char const> p, std::string& out)
	{
		//compress
		size_t input_size = p.size();	
		size_t output_length = snappy_max_compressed_length(input_size);
		char* c_p = (char*)malloc(output_length);
		size_t c_p_size = output_length;	
		snappy_status ss = snappy_compress(p.data(), input_size, c_p, &c_p_size);
		if(ss == SNAPPY_OK) {
			out.insert(0, c_p, c_p_size);
		} else {
			free(c_p);
			return false;
		}
		free(c_p);
		return true;
	}

	bool session_impl::uncompress_udp_packet(const std::string& in, std::string& out)
	{
		//compress
		size_t input_size = in.size();	
		size_t output_length;
		if(snappy_uncompressed_length(in.c_str(), input_size, &output_length) != SNAPPY_OK) {
			return false;
		};
		char* ucd_p = (char*)malloc(output_length);
		snappy_status ss = snappy_uncompress(in.c_str(), input_size, ucd_p, &output_length);
		if(ss == SNAPPY_OK) {
			out.insert(0, ucd_p, output_length);
		} else {
			free(ucd_p);
			return false;
		}
		free(ucd_p);
		return true;
	}
#endif

	bool session_impl::encrypt_udp_packet(sha256_hash const& pk
		, const std::string& in
		, std::string& out
		, std::string& err_str)
	{
		// generate serect key
		dht::public_key dht_pk(pk.data());
		std::array<char, 32> key = m_account_manager->key_exchange(dht_pk);
		std::string keystr;
		keystr.insert(0, key.data(), 32);

/*
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("encrypt exchange key: %s for id: %s"
				, aux::to_hex(keystr).c_str()
				, aux::to_hex(pk).c_str());
		}
#endif
*/

		bool ret;
		time_point const start = clock_type::now();
		ret = aes_encrypt(in, out, keystr, err_str);
		time_point const end = clock_type::now();
/*
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("encrypt time cost:%" PRId64 "us", total_microseconds(end - start));
		}
#endif
*/
		return ret;
	}

	bool session_impl::decrypt_udp_packet(const std::string& in
		, sha256_hash const& pk
		, std::string& out
		, std::string& err_str)
	{
		// generate secret key
		dht::public_key dht_pk(pk.data());
		std::array<char, 32> key = m_account_manager->key_exchange(dht_pk);
		std::string keystr;
		keystr.insert(0, key.data(), 32);
/*
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("decrypt exchange key: %s for id: %s"
				, aux::to_hex(keystr).c_str()
				, aux::to_hex(pk).c_str());
		}
#endif
*/

		bool ret;
		time_point const start = clock_type::now();
		ret = aes_decrypt(in, out, keystr, err_str);
		time_point const end = clock_type::now();
/*
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("decrypt time cost:%" PRId64 "us", total_microseconds(end - start));
		}
#endif
*/

		return ret;
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

				if (buf.size() >= 64) // 32 public key bytes and encrypted data
				{
					sha256_hash pk(buf);
					m_raw_recv_udp_packet.clear();
					m_raw_recv_udp_packet.insert(0
						, buf.subspan(32).data()
						, buf.size() - 32);
					m_decrypted_udp_packet.clear();
/*
#ifndef TORRENT_DISABLE_LOGGING
					if (should_log())
					{
						session_log("recevied UDP decryption packet, raw: %s, id:%s, payload:%s"
							, aux::to_hex(buf).c_str()
							, aux::to_hex(pk).c_str()
							, aux::to_hex(m_raw_recv_udp_packet).c_str());
					}
#endif
*/
#ifdef TORRENT_ENABLE_UDP_ENCRYPTION
					std::string err_str;
					bool result = decrypt_udp_packet(m_raw_recv_udp_packet
						, pk
						, m_decrypted_udp_packet
						, err_str);
					if (!result)
					{
						continue;
					}

#else
					m_decrypted_udp_packet.insert(0 , m_raw_recv_udp_packet.data(), m_raw_recv_udp_packet.size());
#endif

#ifdef TORRENT_ENABLE_UDP_COMPRESS
					m_decrypted_ucd_udp_packet.clear();
					bool c_result = uncompress_udp_packet(m_decrypted_udp_packet, m_decrypted_ucd_udp_packet);
					if(!c_result){
#ifndef TORRENT_DISABLE_LOGGING
						if (should_log())
						{
							session_log("UDP Uncompress Error!!!");
						}
#endif
						continue;
					}

					auto listen_socket = ls.lock();
					if (m_dht && m_decrypted_ucd_udp_packet.size() > 20
						&& listen_socket)
					{
						m_dht->incoming_packet(listen_socket
							, packet.from
							, m_decrypted_ucd_udp_packet
							, pk);
					}
#else
					auto listen_socket = ls.lock();
					if (m_dht && m_decrypted_udp_packet.size() > 20
						&& listen_socket)
					{
						m_dht->incoming_packet(listen_socket
							, packet.from
							, m_decrypted_udp_packet
							, pk);
					}
#endif
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
					return;
				}
				// non-fatal UDP errors get here, we should re-issue the read.
				continue;
			}
		}

		ADD_OUTSTANDING_ASYNC("session_impl::on_udp_packet");
		s->sock.async_read(make_handler([this, socket, ls, ssl](error_code const& e)
			{ this->on_udp_packet(std::move(socket), std::move(ls), ssl, e); }
			, s->udp_handler_storage, *this));
	}

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

	bool session_impl::has_dht() const
	{
		return m_dht != nullptr;
	}

#ifndef TORRENT_DISABLE_LOGGING
    bool session_impl::should_log() const
    {    
        return m_alerts.should_post<log_alert>();
    }    

    bool session_impl::should_log(aux::LOG_LEVEL log_level) const
    {    
        return (log_level <= m_logged) && m_alerts.should_post<log_alert>();
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
			//m_alerts.emplace_alert<session_stats_header_alert>();
		}

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

	// verify that ``addr``s interface allows incoming connections
	bool session_impl::verify_incoming_interface(address const& addr)
	{
		auto const iter = std::find_if(m_listening_sockets.begin(), m_listening_sockets.end()
			, [&addr](std::shared_ptr<listen_socket_t> const& s)
			{ return s->local_endpoint.address() == addr; });
		return iter == m_listening_sockets.end()
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
		for (auto& i : m_listening_sockets)
			i->udp_sock->sock.set_proxy_settings(proxy(), m_alerts);
	}

	void session_impl::update_ip_notifier()
	{
		if (m_settings.get_bool(settings_pack::enable_ip_notifier))
			start_ip_notifier();
		else
			stop_ip_notifier();
	}

	void session_impl::update_log_level()
	{
		m_logged = m_settings.get_int(settings_pack::log_level);
	}

	void session_impl::set_log_level(int logged)
	{
		m_settings.set_int(settings_pack::log_level, logged);
        m_logged = logged;
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

    void session_impl::update_device_id()
    {    
		const char* device_id = m_settings.get_str(settings_pack::device_id).c_str();
#ifndef TORRENT_DISABLE_LOGGING
		session_log("start to update device id: %s", device_id);
#endif
		std::vector<char> device_id_char;
		device_id_char.resize(16);
        span<char const> hex_device_id(device_id, 32);
        libTAU::aux::from_hex(hex_device_id, device_id_char.data());

		std::copy(device_id_char.begin(), device_id_char.end(), std::inserter(m_device_id, m_device_id.begin()));

	}

    void session_impl::update_db_dir()
    {    

#ifdef TORRENT_ANDROID			
        std::string const& kvdb_dir = m_settings.get_str(settings_pack::db_dir)+ "/kvdb";
        std::string const& sqldb_dir = m_settings.get_str(settings_pack::db_dir)+ "/sqldb";
#else
        std::string home_dir = std::filesystem::path(getenv("HOME")).string()+ "/";
        std::string const& kvdb_dir = home_dir + m_settings.get_str(settings_pack::db_dir)+ "/kvdb";
        std::string const& sqldb_dir = home_dir + m_settings.get_str(settings_pack::db_dir)+ "/sqldb";
#endif

		m_bs_nodes_dir = sqldb_dir;

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
			return;
		}

		sqlite3_exec(m_sqldb, "pragma journal_mode = WAL;", NULL, NULL, NULL);
		sqlite3_exec(m_sqldb, "pragma synchronous = normal;", NULL, NULL, NULL);
    }

	void session_impl::update_dht_bootstrap_nodes()
	{

		//std::string const& node_list = m_settings.get_str(settings_pack::dht_bootstrap_nodes);
		std::string const& nodes_from_settings = m_settings.get_str(settings_pack::dht_bootstrap_nodes);

		std::string const nodes_key = "bootstrap_nodes";
		std::string nodes_list;
		leveldb::Status s = m_kvdb->Get(leveldb::ReadOptions(), nodes_key, &nodes_list);
#ifndef TORRENT_DISABLE_LOGGING
		session_log("start to update dht bootstrap nodes default: %s, db: %s",
					 nodes_from_settings.c_str(), nodes_list.c_str());
#endif

		if (!s.ok()){

#ifndef TORRENT_DISABLE_LOGGING
			session_log("start to  put 1st dht bootstrap nodes:%s into kvdb", nodes_from_settings.c_str());
#endif
			s = m_kvdb->Put(leveldb::WriteOptions(), nodes_key, nodes_from_settings);
			nodes_list = nodes_from_settings;
		}

        //TODO: 100% use bs nodes in settings
		nodes_list = nodes_from_settings;

		std::vector<std::tuple<std::string, int, std::string>> nodes;
		parse_comma_separated_string_port_key(nodes_list, nodes);

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

	std::uint16_t session_impl::get_port_from_pubkey(const dht::public_key &pubkey) {
		return aux::generate_port(pubkey.bytes);
	}

	std::uint16_t session_impl::get_port_from_local() {

        return get_port_from_pubkey(m_account_manager->pub_key());
	}

	void session_impl::update_account_seed() {

		std::array<char, 32> seed;

		const char* account_seed = m_settings.get_str(settings_pack::account_seed).c_str();
#ifndef TORRENT_DISABLE_LOGGING
		session_log("start to update account seed :%s", account_seed);
#endif
        span<char const> hexseed(account_seed, 64);
        libTAU::aux::from_hex(hexseed, seed.data());
		//1. update key pair
		m_keypair = dht::ed25519_create_keypair(seed);

		if (m_account_manager)
		{
			m_account_manager->update_key(hexseed);
		}
		else
		{
			m_account_manager
				= std::make_shared<aux::account_manager>(hexseed);
		}

		//2. dht update node id
		if(m_dht)
			m_dht->update_node_id();

		//3. communication update node id
		if(m_communication)
			m_communication->account_changed();

        //4. blockchain update node id
        if(m_blockchain)
            m_blockchain->account_changed();
	}

	void session_impl::new_account_seed(std::string& account_seed) {

		std::array<char, 32> seed;

        //update account seed
		m_settings.set_str(settings_pack::account_seed, account_seed);

#ifndef TORRENT_DISABLE_LOGGING
		session_log("start to update account seed :%s", account_seed.c_str());
#endif
        span<char const> hexseed(account_seed.c_str(), 64);
        libTAU::aux::from_hex(hexseed, seed.data());
		//1. update key pair
		m_keypair = dht::ed25519_create_keypair(seed);

		if (m_account_manager)
		{
			m_account_manager->update_key(hexseed);
		}
		else
		{
			m_account_manager
				= std::make_shared<aux::account_manager>(hexseed);
		}

		//2. dht update node id
		if(m_dht)
			m_dht->update_node_id();

		//3. communication update node id
		if(m_communication)
			m_communication->account_changed();

        //4. blockchain update node id
        if(m_blockchain)
            m_blockchain->account_changed();
	}

	int session_impl::get_listen_port(transport const ssl, aux::listen_socket_handle const& s)
	{
		auto* socket = s.get();
		if (socket->ssl != ssl)
		{
			auto alt_socket = std::find_if(m_listening_sockets.begin(), m_listening_sockets.end()
				, [&](std::shared_ptr<listen_socket_t> const& e)
			{
				return e->ssl == ssl
					&& e->external_address.external_address()
						== socket->external_address.external_address();
			});
			if (alt_socket != m_listening_sockets.end())
				socket = alt_socket->get();
		}
		return socket->udp_external_port();
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

		if (proto == portmap_protocol::udp)
		{
			listen_socket->udp_port_mapping[transport].port = port;
			listen_socket->udp_address_mapping[transport] = external_ip;
		}

		if (!ec && m_alerts.should_post<portmap_alert>())
		{
			m_alerts.emplace_alert<portmap_alert>(mapping, port
				, transport, proto, listen_socket->local_endpoint.address());
		}
	}

    void session_impl::stop_service()
    {
        // TODO: coe to control timer interval when in 'doze' model
    }

    void session_impl::restart_service()
    {
        // TODO: coe to control timer interval when in 'doze' model
    }

    void session_impl::pause_service()
    {
        // TODO: coe to control timer interval when in 'doze' model
		if(m_blockchain)
		{
			m_blockchain->on_pause();
		}
    }

    void session_impl::resume_service()
    {
        // TODO: coe to control timer interval when in 'doze' model
		if(m_blockchain)
		{
			m_blockchain->on_resume();
		}
    }

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
		m_communication = std::make_shared<communication::communication>(m_device_id, *this, m_io_context, m_stats_counters);

#ifndef TORRENT_DISABLE_LOGGING
		session_log("starting Communication");
#endif

		m_communication->start();
		
	}

	void session_impl::start_blockchain()
	{

		stop_blockchain();

		if (m_abort)
		{
#ifndef TORRENT_DISABLE_LOGGING
			session_log("not starting Blockchain, aborting");
#endif
			return;
		}
		// todo: initialize device_id
		m_blockchain = std::make_shared<blockchain::blockchain>(m_io_context, *this, m_stats_counters);

#ifndef TORRENT_DISABLE_LOGGING
		session_log("starting Blockchain");
#endif

		m_blockchain->start();
		
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

		reset_refer_switch();

		// TODO: refactor, move the storage to dht_tracker
		m_dht_storage = m_dht_storage_constructor(m_settings);
		m_items_db = std::make_shared<dht::items_db_sqlite>(
			m_settings, static_cast<dht::dht_observer*>(this));
		m_dht_storage->set_backend(m_items_db);
		m_bs_nodes_storage = std::make_unique<dht::bs_nodes_db_sqlite>(
			m_settings, static_cast<dht::dht_observer*>(this));

		m_dht = std::make_shared<dht::dht_tracker>(
			static_cast<dht::dht_observer*>(this)
			, m_io_context
			, [this](aux::listen_socket_handle const& sock
				, udp::endpoint const& ep
				, sha256_hash const& pk
				, span<char const> p
				, error_code& ec
				, udp_send_flags_t const flags)
				{ send_udp_packet_listen_encryption(sock, ep, pk, p, ec, flags); }
			, m_settings
			, m_stats_counters
			, *m_dht_storage
			, std::move(m_dht_state)
			, m_account_manager
			, *m_bs_nodes_storage
			, m_bs_nodes_dir);

		m_dht->install_bootstrap_nodes();

		for (auto& s : m_listening_sockets)
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

	void session_impl::stop_blockchain()
	{

#ifndef TORRENT_DISABLE_LOGGING
		session_log("about to stop Blockchain, running: %s", m_blockchain ? "true" : "false");
#endif

		if(m_blockchain)
		{
			m_blockchain->stop();
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

		if (m_dht_storage != nullptr) m_dht_storage->close();
		if (m_bs_nodes_storage != nullptr) m_bs_nodes_storage->close();
		m_dht_storage.reset();
		m_items_db.reset();
		m_bs_nodes_storage.reset();
	}

	void session_impl::set_loop_time_interval(int milliseconds)
	{
        /*
		//m_communication
		if(m_communication)
			m_communication->set_loop_time_interval(milliseconds);

		//blockchain
		if(m_blockchain)
			m_blockchain->set_blockchain_loop_interval(milliseconds);
        */
	}

    bool session_impl::publish_data(const aux::bytes& key, const aux::bytes& value)
    {
		if(m_communication) {
            m_communication->publish_data(key, value);
            return true;
        }
		else
			return false;

    }

    bool session_impl::subscribe_from_peer(const dht::public_key& pubkey, const aux::bytes& data)
    {
		if(m_communication) {
            m_communication->subscribe_from_peer(pubkey, data);
            return true;
        }
		else
			return false;

    }

    bool session_impl::send_to_peer(const dht::public_key& pubkey, const aux::bytes& data)
    {
		if(m_communication) {
            //m_communication->send_to_peer(pubkey, data);
            //return true;
            return false;
        }
		else
			return false;

    }

    bool session_impl::pay_attention_to_peer(const dht::public_key& peer)
    {
		if(m_communication) {
            m_communication->pay_attention_to_peer(peer);
            return true;
        }
		else
			return false;

    }

	bool session_impl::add_new_friend(const dht::public_key& pubkey)
	{
		if(m_communication)
			return m_communication->add_new_friend(pubkey);
		else
			return false;
	}

	bool session_impl::delete_friend(const dht::public_key& pubkey)
	{
		if(m_communication)
			return m_communication->delete_friend(pubkey);
		else
			return false;
	}

	void session_impl::get_friend_info(const dht::public_key& pubkey, std::vector<char>* info)
	{
        /*
		if(m_communication)
			*info = m_communication->get_friend_info(pubkey);
        */
	}

	void session_impl::request_friend_info(const dht::public_key& pubkey)
	{
        /*
		if(m_communication)
			m_communication->request_friend_info(pubkey);
        */
	}

	bool session_impl::update_friend_info(const dht::public_key& pubkey, aux::bytes friend_info)
	{
        /*
		if(m_communication)
			return m_communication->update_friend_info(pubkey, friend_info);
		else
			return false;
        */
	}

	void session_impl::unset_chatting_friend()
	{
        /*
		if(m_communication)
			m_communication->unset_chatting_friend();
        */
	}
	
	void session_impl::set_chatting_friend(const dht::public_key& chatting_friend)
	{
        /*
		if(m_communication)
			m_communication->set_chatting_friend(chatting_friend);
        */
	}

	void session_impl::set_active_friends(std::vector<dht::public_key> active_friends)
	{
        /*
		if(m_communication)
			m_communication->set_active_friends(active_friends);
        */
	}

	bool session_impl::add_new_message(const communication::message& msg)
	{
		if(m_communication)
			return m_communication->add_new_message(msg);
		else
			return false;
	}	

	void session_impl::create_chain_id(const aux::bytes &type, std::string community_name, std::vector<char>* id)
	{
		if(m_blockchain)
			*id = m_blockchain->create_chain_id(type, community_name);
	}

	void session_impl::get_all_chains(std::set<std::vector<char>>* cids)
	{
		if(m_blockchain)
			*cids = m_blockchain->get_all_chains();
	}

	bool session_impl::create_new_community(const aux::bytes &chain_id, const std::set<blockchain::account>& accounts) {
		if(m_blockchain) {
			return m_blockchain->createNewCommunity(chain_id, accounts);
		}
		return false; 
	}

	bool session_impl::follow_chain(const aux::bytes &chain_id, const std::set<dht::public_key>& peers) {
		if(m_blockchain)
			return m_blockchain->followChain(chain_id, peers);
		return false;
	}

	bool session_impl::add_new_bootstrap_peers(const aux::bytes &chain_id, const std::set<dht::public_key>& peers) {
		if(m_blockchain)
			return m_blockchain->add_new_bootstrap_peers(chain_id, peers);
		return false;
	}

	bool session_impl::unfollow_chain(const aux::bytes &chain_id) {
		if(m_blockchain)
			return m_blockchain->unfollowChain(chain_id);
		return false;
	}

	bool session_impl::start_chain(const aux::bytes &chain_id) {
		if(m_blockchain)
			return m_blockchain->connect_chain(chain_id);
		return false;
	}

	bool session_impl::submit_transaction(const blockchain::transaction & tx) {
		if(m_blockchain)
			return m_blockchain->submitTransaction(tx);
		return false;
	}

	bool session_impl::get_account_info(const aux::bytes &chain_id, dht::public_key pub_key, blockchain::account * act) {
		if(m_blockchain) {
			*act =  m_blockchain->getAccountInfo(chain_id, pub_key);
			return true;
		}
		return false;
	}

	bool session_impl::get_top_tip_block(const aux::bytes &chain_id, int num, std::vector<blockchain::block> * blks) {
		if(m_blockchain) {
			*blks = m_blockchain->getTopTipBlocks(chain_id, num);
			return true;
		}
		return false;
	}

	bool session_impl::get_access_list(const aux::bytes &chain_id, std::set<dht::public_key>* keys) {
		if(m_blockchain) {
			*keys = m_blockchain->get_access_list(chain_id);
			return true;
		}
		return false;
	}

	bool session_impl::get_ban_list(const aux::bytes &chain_id, std::set<dht::public_key>* keys) {
		if(m_blockchain) {
			*keys = m_blockchain->get_ban_list(chain_id);
			return true;
		}
		return false;
	}

	bool session_impl::get_gossip_list(const aux::bytes &chain_id, std::set<dht::public_key>* keys) {
        /*
		if(m_blockchain) {
			*keys = m_blockchain->get_gossip_peers(chain_id);
			return true;
		}
        */
		return false;
	}

	std::int64_t session_impl::get_median_tx_free(const aux::bytes &chain_id) {
		if(m_blockchain) {
			return m_blockchain->getMedianTxFee(chain_id);
		}
		return -1; //error
	}

	std::int64_t session_impl::get_mining_time(const aux::bytes &chain_id) {
		if(m_blockchain) {
			return m_blockchain->getMiningTime(chain_id);
		}
		return -1; //error
	}

	bool session_impl::send_online_signal(const aux::bytes &chain_id) {
		if(m_blockchain) {
            //m_blockchain->send_online_signal(chain_id);
            //return true;
            return false;
		}
        return false;
	}

	bool session_impl::connect_chain(const aux::bytes &chain_id) {
		if(m_blockchain) {
            m_blockchain->connect_chain(chain_id);
            return true;
		}
        return false;
	}

	void session_impl::set_priority_chain(const aux::bytes &chain_id) {
        /*
		if(m_blockchain) {
			m_blockchain->set_priority_chain(chain_id);
		}
        */
	}

	void session_impl::unset_priority_chain() {
        /*
		if(m_blockchain) {
			m_blockchain->unset_priority_chain();
		}
        */
	}

	blockchain::block session_impl::get_block_by_number(const aux::bytes &chain_id, std::int64_t block_number) {
		if(m_blockchain) {
			return m_blockchain->getBlock(chain_id, block_number);
		}
	}

	blockchain::block session_impl::get_block_by_hash(const aux::bytes &chain_id, const sha1_hash& block_hash) {
		if(m_blockchain) {
			return m_blockchain->getBlock(chain_id, block_hash);
		}
	}

	bool session_impl::is_transaction_in_fee_pool(const aux::bytes &chain_id, const sha1_hash& txid) {
		if(m_blockchain) {
			return m_blockchain->is_transaction_in_fee_pool(chain_id, txid);
		}
	}

	void session_impl::request_chain_state(const aux::bytes &chain_id) {
    /*
		if(m_blockchain) {
			return m_blockchain->request_state(chain_id);
		}
    */
	}

	void session_impl::request_chain_data(const aux::bytes &chain_id, const dht::public_key &peer) {
		if(m_blockchain) {
			return m_blockchain->request_chain_all_data(chain_id, peer);
		}
	}

	void session_impl::put_all_chain_data(const aux::bytes &chain_id) {
		if(m_blockchain) {
			return m_blockchain->put_chain_all_data(chain_id);
		}
	}

	void session_impl::set_dht_state(dht::dht_state&& state)
	{
		m_dht_state = std::move(state);
	}

	void session_impl::set_dht_storage(dht::dht_storage_constructor_type sc)
	{
		m_dht_storage_constructor = std::move(sc);
	}

	void session_impl::add_dht_router(std::tuple<std::string, int, std::string> const& node)
	{
		ADD_OUTSTANDING_ASYNC("session_impl::on_dht_router_name_lookup");
		++m_outstanding_router_lookups;

#ifndef TORRENT_DISABLE_LOGGING
		session_log("add_dht_router lookups: %d" , m_outstanding_router_lookups);
#endif
		m_host_resolver.async_resolve(std::get<0>(node), resolver::abort_on_shutdown
			, std::bind(&session_impl::on_dht_router_name_lookup
				, this, _1, _2, std::get<1>(node), std::get<2>(node)));
	}

	void session_impl::on_dht_router_name_lookup(error_code const& e
		, std::vector<address> const& addresses, int port, std::string pubkey)
	{
		COMPLETE_ASYNC("session_impl::on_dht_router_name_lookup");
		--m_outstanding_router_lookups;

#ifndef TORRENT_DISABLE_LOGGING
		session_log("on_dht_router lookups: %d" , m_outstanding_router_lookups);
#endif
		bool c_enable = m_settings.get_bool(settings_pack::enable_communication);
		bool b_enable = m_settings.get_bool(settings_pack::enable_blockchain);

		if (e)
		{
			if (m_alerts.should_post<dht_error_alert>())
				m_alerts.emplace_alert<dht_error_alert>(
					operation_t::hostname_lookup, e);

			if (m_outstanding_router_lookups == 0) 
			{
				start_dht();
                if(c_enable)
				    start_communication();
                if(b_enable)
				    start_blockchain();
			}
			return;
		}


		for (auto const& addr : addresses)
		{
			// router nodes should be added before the DHT is started (and bootstrapped)
			udp::endpoint ep(addr, std::uint16_t(port));
			sha256_hash nid;

			if (pubkey.size() == 64)
			{
				span<char const> hexseed(pubkey.c_str(), 64);
				aux::from_hex(hexseed, nid.data());
			}
			else
			{
				nid = dht::generate_random_id();
			}

			dht::node_entry ne(nid, ep);

#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("add router node: %s, %s"
					, aux::to_hex(nid).c_str()
					, aux::print_endpoint(ep).c_str());
			}
#endif

			if (m_dht) m_dht->add_router_node(ne);
			m_dht_router_nodes.push_back(ne);
		}

		if (m_outstanding_router_lookups == 0)
		{
			start_dht();
            if(c_enable)
                start_communication();
            if(b_enable)
                start_blockchain();
		}

		m_alerts.emplace_alert<session_start_over_alert>(true);
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
			, i.sig().bytes, i.ts().value
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
				dht::timestamp const ts = i.ts();
				std::string salt = i.salt();
				alerts.emplace_alert<dht_put_alert>(pk.bytes, sig.bytes
					, std::move(salt), ts.value, num);
			}
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
			cb(value, sig.bytes, ts.value, salt);
			i.assign(std::move(value), salt, ts, pk, sig);
		}

		void send_callback(const entry& e
			, std::vector<std::pair<dht::node_entry, bool>> const& nodes)
		{
            //TODO: current just for send api
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

	void session_impl::tau_get_mutable_callback(dht::item const& i, bool auth)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (auth && should_log())
		{
			session_log("get done, data:%s", i.value().to_string(true).c_str());
		}
#endif
	}

	void session_impl::tau_put_mutable_callback(dht::item const& i
		, int num, std::int8_t alpha, std::int8_t invoke_window
		, std::int8_t invoke_limit, std::string salt)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("put done, number:%d, data:%s"
				, num, i.value().to_string(true).c_str());
		}
#endif

		if (!m_dht) return;

		m_dht->get_item(m_account_manager->pub_key()
			, std::bind(&session_impl::tau_get_mutable_callback
			, this, _1, _2)
			, alpha, invoke_window, invoke_limit, salt);
	}

	void session_impl::send(dht::public_key const& to
		, entry const& payload
		, std::int8_t alpha
		, std::int8_t beta
		, std::int8_t invoke_limit
		, std::int8_t hit_limit)
	{
		if (!m_dht) return;

		std::string mutable_item;
		bencode(std::back_inserter(mutable_item), payload);
		hasher h(mutable_item);
		sha1_hash const hash = h.final();
		std::string salt = std::string(hash.data(), 20);

		//m_dht->send(to, payload, alpha, beta, invoke_limit
		//	, hit_limit, std::bind(&send_callback, _1, _2));
		m_dht->put_item(m_account_manager->pub_key()
			, payload
			, std::bind(&session_impl::tau_put_mutable_callback
				, this, _1, _2, alpha, beta, invoke_limit, salt)
			, alpha, beta, invoke_limit, salt);
	}

	void session_impl::dht_live_nodes(sha256_hash const& nid)
	{
		if (!m_dht) return;
		auto nodes = m_dht->live_nodes(nid);
		m_alerts.emplace_alert<dht_live_nodes_alert>(nid, nodes);
	}

	bool session_impl::is_listening() const
	{
		return !m_listening_sockets.empty();
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
		for (auto const& l : m_listening_sockets)
		{
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
		for (auto const& l : m_listening_sockets)
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

	void session_impl::pop_alerts(std::vector<alert*>* alerts)
	{
		m_alerts.get_all(*alerts);
	}

	alert* session_impl::wait_for_alert(time_duration max_wait)
	{
		return m_alerts.wait_for_alert(max_wait);
	}

	std::size_t session_impl::set_alert_queue_size_limit(std::size_t queue_size_limit_)
	{
		m_settings.set_int(settings_pack::alert_queue_size, int(queue_size_limit_));
		return std::size_t(m_alerts.set_alert_queue_size_limit(int(queue_size_limit_)));
	}

	void session_impl::start_ip_notifier()
	{
		if (m_ip_notifier) return;

		m_ip_notifier = create_ip_notifier(m_io_context);
		m_ip_notifier->async_wait([this](error_code const& e)
			{ wrap(&session_impl::on_ip_change, e); });
	}

	void session_impl::start_natpmp()
	{
		for (auto& s : m_listening_sockets)
		{
			start_natpmp(s);
			remap_ports(remap_natpmp, *s);
		}
	}

	void session_impl::start_upnp()
	{
		for (auto const& s : m_listening_sockets)
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
		for (auto& s : m_listening_sockets)
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
		for (auto& s : m_listening_sockets)
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
		for (auto& s : m_listening_sockets)
		{
			s->udp_port_mapping[portmap_transport::natpmp] = listen_port_mapping();
			if (!s->natpmp_mapper) continue;
			s->natpmp_mapper->close();
			s->natpmp_mapper.reset();
		}
	}

	void session_impl::stop_upnp()
	{
		for (auto& s : m_listening_sockets)
		{
			if (!s->upnp_mapper) continue;
			s->udp_port_mapping[portmap_transport::upnp] = listen_port_mapping();
			s->upnp_mapper->close();
			s->upnp_mapper.reset();
		}
	}

	aux::external_ip session_impl::external_address() const
	{
		address ips[2][2];

		// take the first IP we find which matches each category
		for (auto const& i : m_listening_sockets)
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

	bool session_impl::should_log(module_t m, aux::LOG_LEVEL log_level) const
	{
		return (log_level <= m_logged) && (m_alerts.should_post<dht_log_alert>());
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
#endif

	bool session_impl::on_dht_request(string_view query
		, dht::msg const& request, entry& response)
	{
		TORRENT_UNUSED(query);
		TORRENT_UNUSED(request);
		TORRENT_UNUSED(response);
		return false;
	}

	void session_impl::on_dht_item(dht::item& i)
	{
		// dispatch this item to communication and blockchain components.
//		if (m_communication)
//		{
//			m_communication->on_dht_item(i);
//		}
//        if (m_blockchain)
//        {
//            m_blockchain->on_dht_item(i);
//        }
	}

	std::int64_t session_impl::get_time()
	{
		return m_session_time;
	}

	void session_impl::on_dht_relay(dht::public_key const& from, entry const& payload)
	{
        if (m_communication)
        {
            m_communication->on_dht_relay(from, payload);
        }
        if (m_blockchain)
        {
            m_blockchain->on_dht_relay(from, payload);
        }
	}



	sqlite3* session_impl::get_items_database()
	{
		return m_sqldb;
	}

	void session_impl::set_external_address(
		tcp::endpoint const& local_endpoint, address const& ip
		, ip_source_t const source_type, address const& source)
	{
		auto sock = std::find_if(m_listening_sockets.begin(), m_listening_sockets.end()
			, [&](std::shared_ptr<listen_socket_t> const& v)
			{ return v->local_endpoint.address() == local_endpoint.address(); });

		if (sock != m_listening_sockets.end())
			set_external_address(*sock, ip, source_type, source);
	}

	void session_impl::set_external_address(std::shared_ptr<listen_socket_t> const& sock
		, address const& ip, ip_source_t const source_type, address const& source)
	{
		trigger_refer_switch(sock, ip);

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

	void session_impl::update_auto_relay()
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			session_log("update auto relay:%s"
				, m_settings.get_bool(settings_pack::auto_relay) ? "enabled" : "disabled");
		}
#endif

		if (m_settings.get_bool(settings_pack::auto_relay))
		{
			m_refer_switch.set_enabled(true);
			reset_refer_switch();
		}
		else
		{
			m_refer_switch.set_enabled(false);
		}
	}

	void session_impl::reset_refer_switch()
	{
		if (m_refer_switch.is_enabled())
		{
			m_refer_switch.reset();
			m_settings.set_bool(settings_pack::dht_non_referrable, true);
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				session_log("reset refer switch");
			}
#endif
		}
	}

	void session_impl::trigger_refer_switch(std::shared_ptr<listen_socket_t> const& sock
		, address const& ip)
	{
		if (ip.is_unspecified()) return;

		// try to open referrable flag
		if (m_refer_switch.is_enabled()
			&& !m_refer_switch.is_done()
			&& m_settings.get_bool(settings_pack::dht_non_referrable))
		{
			m_refer_switch.on_ip_vote();
			if (m_refer_switch.vote_count() >= 60)
			{
				m_refer_switch.set_done();

#ifndef TORRENT_DISABLE_LOGGING
				if (should_log())
				{
					session_log("refer switch: voted:%s, NAT-PMP:%s, UPNP:%s, now:%s"
						, print_address(sock->external_address.external_address()).c_str()
						, print_address(
							sock->udp_address_mapping[portmap_transport::natpmp]).c_str()
						, print_address(
							sock->udp_address_mapping[portmap_transport::upnp]).c_str()
						, print_address(ip).c_str());
				}
#endif

				udp::endpoint ep = external_udp_endpoint();
				if (ep.port() != 0 && !aux::is_local(ip) && !ip.is_loopback())
				{
					m_settings.set_bool(settings_pack::dht_non_referrable, false);
#ifndef TORRENT_DISABLE_LOGGING
					if (should_log())
					{
						session_log("open refer switch, port:%d", ep.port());
					}
#endif

					// trigger alert
					if (m_alerts.should_post<referred_status_alert>())
						m_alerts.emplace_alert<referred_status_alert>(ep.address()
							, ep.port());
				}
				else
				{
#ifndef TORRENT_DISABLE_LOGGING
					if (should_log())
					{
						session_log("can't open refer switch");
					}
#endif
				}
			}
		}
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
