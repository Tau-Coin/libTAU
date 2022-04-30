/*

Copyright (c) 2003, Magnus Jonsson
Copyright (c) 2003, 2006, 2008-2020, Arvid Norberg
Copyright (c) 2016, 2021, Alden Torres
Copyright (c) 2017, 2020, Steven Siloti
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/config.hpp"
#include "libTAU/session.hpp"
#include "libTAU/extensions.hpp"
#include "libTAU/aux_/session_impl.hpp"
#include "libTAU/aux_/session_call.hpp"
#include "libTAU/extensions.hpp" // for add_peer_flags_t

namespace libTAU {

namespace {

#if defined TORRENT_ASIO_DEBUGGING
	void wait_for_asio_handlers()
	{
		int counter = 0;
		while (aux::log_async())
		{
			std::this_thread::sleep_for(milliseconds(300));
			++counter;
			std::printf("\x1b[2J\x1b[0;0H\x1b[33m==== Waiting to shut down: %d ==== \x1b[0m\n\n"
				, counter);
		}
		aux::async_dec_threads();

		std::fprintf(stderr, "\n\nEXPECTS NO MORE ASYNC OPS\n\n\n");
	}
#endif
} // anonymous namespace

	settings_pack min_memory_usage()
	{
		settings_pack set;

		set.set_int(settings_pack::max_peer_recv_buffer_size, 32 * 1024 + 200);
		set.set_int(settings_pack::disk_io_write_mode, settings_pack::disable_os_cache);
		set.set_int(settings_pack::disk_io_read_mode, settings_pack::disable_os_cache);

		// keep 2 blocks outstanding when hashing
		set.set_int(settings_pack::checking_mem_usage, 2);

		// don't use any extra threads to do SHA-1 hashing
		set.set_int(settings_pack::aio_threads, 1);

		set.set_int(settings_pack::alert_queue_size, 100);

		set.set_int(settings_pack::max_out_request_queue, 300);
		set.set_int(settings_pack::max_allowed_in_request_queue, 100);

		// setting this to a low limit, means more
		// peers are more likely to request from the
		// same piece. Which means fewer partial
		// pieces and fewer entries in the partial
		// piece list
		set.set_int(settings_pack::whole_pieces_threshold, 2);
		set.set_bool(settings_pack::use_parole_mode, false);
		set.set_bool(settings_pack::prioritize_partial_pieces, true);

		// connect to 5 peers per second
		set.set_int(settings_pack::connection_speed, 5);

		// only have 4 files open at a time
		set.set_int(settings_pack::file_pool_size, 4);

		// we want to keep the peer list as small as possible
		set.set_bool(settings_pack::allow_multiple_connections_per_ip, false);
		set.set_int(settings_pack::max_failcount, 2);
		set.set_int(settings_pack::inactivity_timeout, 120);

		// whenever a peer has downloaded one block, write
		// it to disk, and don't read anything from the
		// socket until the disk write is complete
		set.set_int(settings_pack::max_queued_disk_bytes, 1);

		// never keep more than one 16kB block in
		// the send buffer
		set.set_int(settings_pack::send_buffer_watermark, 9);

		set.set_bool(settings_pack::close_redundant_connections, true);

		set.set_int(settings_pack::max_peerlist_size, 500);
		set.set_int(settings_pack::max_paused_peerlist_size, 50);

		// udp trackers are cheaper to talk to
		set.set_bool(settings_pack::prefer_udp_trackers, true);

		set.set_int(settings_pack::max_rejects, 10);

		set.set_int(settings_pack::recv_socket_buffer_size, 16 * 1024);
		set.set_int(settings_pack::send_socket_buffer_size, 16 * 1024);
		return set;
	}

	settings_pack high_performance_seed()
	{
		settings_pack set;
		// don't throttle TCP, assume there is
		// plenty of bandwidth
		set.set_int(settings_pack::mixed_mode_algorithm, settings_pack::prefer_tcp);

		set.set_int(settings_pack::max_out_request_queue, 1500);
		set.set_int(settings_pack::max_allowed_in_request_queue, 2000);

		set.set_int(settings_pack::max_peer_recv_buffer_size, 5 * 1024 * 1024);

		// we will probably see a high rate of alerts, make it less
		// likely to loose alerts
		set.set_int(settings_pack::alert_queue_size, 10000);

		// allow 500 files open at a time
		set.set_int(settings_pack::file_pool_size, 500);

		// don't update access time for each read/write
		set.set_bool(settings_pack::no_atime_storage, true);

		// as a seed box, we must accept multiple peers behind
		// the same NAT
//		set.set_bool(settings_pack::allow_multiple_connections_per_ip, true);

		// connect to 50 peers per second
		set.set_int(settings_pack::connection_speed, 500);

		// allow 8000 peer connections
		set.set_int(settings_pack::connections_limit, 8000);

		// allow lots of peers to try to connect simultaneously
		set.set_int(settings_pack::listen_queue_size, 3000);

		// unchoke all peers
		set.set_int(settings_pack::unchoke_slots_limit, -1);

		set.set_int(settings_pack::read_cache_line_size, 32);
		set.set_int(settings_pack::write_cache_line_size, 256);

		// the max number of bytes pending write before we throttle
		// download rate
		set.set_int(settings_pack::max_queued_disk_bytes, 7 * 1024 * 1024);

		// prevent fast pieces to interfere with suggested pieces
		// since we unchoke everyone, we don't need fast pieces anyway
		set.set_int(settings_pack::allowed_fast_set_size, 0);

		// suggest pieces in the read cache for higher cache hit rate
		set.set_int(settings_pack::suggest_mode, settings_pack::suggest_read_cache);

		set.set_bool(settings_pack::close_redundant_connections, true);

		set.set_int(settings_pack::max_rejects, 10);

		set.set_int(settings_pack::send_not_sent_low_watermark, 524288);

		// don't let connections linger for too long
		set.set_int(settings_pack::request_timeout, 10);
		set.set_int(settings_pack::peer_timeout, 20);
		set.set_int(settings_pack::inactivity_timeout, 20);

		set.set_int(settings_pack::active_limit, 20000);
		set.set_int(settings_pack::active_tracker_limit, 2000);
		set.set_int(settings_pack::active_dht_limit, 600);
		set.set_int(settings_pack::active_seeds, 2000);

		set.set_int(settings_pack::choking_algorithm, settings_pack::fixed_slots_choker);

		// of 500 ms, and a send rate of 4 MB/s, the upper
		// limit should be 2 MB
		set.set_int(settings_pack::send_buffer_watermark, 3 * 1024 * 1024);

		// put 1.5 seconds worth of data in the send buffer
		// this gives the disk I/O more heads-up on disk
		// reads, and can maximize throughput
		set.set_int(settings_pack::send_buffer_watermark_factor, 150);

		// always stuff at least 1 MiB down each peer
		// pipe, to quickly ramp up send rates
		set.set_int(settings_pack::send_buffer_low_watermark, 1 * 1024 * 1024);

		// don't retry peers if they fail once. Let them
		// connect to us if they want to
		set.set_int(settings_pack::max_failcount, 1);

		// number of disk threads for low level file operations
		set.set_int(settings_pack::aio_threads, 8);

		set.set_int(settings_pack::checking_mem_usage, 2048);

		return set;
	}

	void session::start(session_flags_t const flags, session_params&& params, io_context* ios)
	{
		bool const internal_executor = ios == nullptr;

		if (internal_executor)
		{
			// the user did not provide an executor, we have to use our own
			m_io_service = std::make_shared<io_context>(1);
			ios = m_io_service.get();
		}

		// TODO: start() should just use flags out of the session_params object,
		m_impl = std::make_shared<aux::session_impl>(std::ref(*ios)
			, std::move(params.settings)
			, flags);
		*static_cast<session_handle*>(this) = session_handle(m_impl);

		m_impl->set_dht_state(std::move(params.dht_state));

		TORRENT_ASSERT(params.dht_storage_constructor);
		m_impl->set_dht_storage(std::move(params.dht_storage_constructor));

		if (!params.ip_filter.empty())
		{
			std::shared_ptr<ip_filter> copy = std::make_shared<ip_filter>(std::move(params.ip_filter));
			m_impl->set_ip_filter(std::move(copy));
		}

		m_impl->start_session();

		if (internal_executor)
		{
			// start a thread for the message pump
			auto s = m_io_service;
			m_thread = std::make_shared<std::thread>(
				[=] { s->run(); });
		}
	}

	session::session(session&&) = default;

	session::session(session_params const& params)
	{
		start(params.flags, session_params(params), nullptr);
	}

	session::session(session_params&& params)
	{
		start(params.flags, std::move(params), nullptr);
	}

#if TORRENT_ABI_VERSION < 4
	session::session(session_params const& params, session_flags_t const flags)
	{
		start(flags, session_params(params), nullptr);
	}

	session::session(session_params&& params, session_flags_t const flags)
	{
		start(flags, std::move(params), nullptr);
	}
#endif

	session::session()
	{
		session_params params;
		start(params.flags, std::move(params), nullptr);
	}

	session::session(session_params&& params, io_context& ios)
	{
		start(params.flags, std::move(params), &ios);
	}

	session::session(session_params const& params, io_context& ios)
	{
		start(params.flags, session_params(params), &ios);
	}

#if TORRENT_ABI_VERSION < 4
	session::session(session_params&& params, io_context& ios, session_flags_t const flags)
	{
		start(flags, std::move(params), &ios);
	}

	session::session(session_params const& params, io_context& ios, session_flags_t const flags)
	{
		start(flags, session_params(params), &ios);
	}
#endif

	session& session::operator=(session&&) & = default;

	session::~session()
	{
		if (!m_impl) return;
        //TAU useless call
		//aux::dump_call_profile();

		// capture the shared_ptr in the dispatched function
		// to keep the session_impl alive
		// m_impl->call_abort();

		if (m_thread && m_thread.use_count() == 1)
		{
#if defined TORRENT_ASIO_DEBUGGING
			wait_for_asio_handlers();
#endif
			m_thread->join();
		}

		std::cout << "Session Impl Abort Over" << std::endl;
	}

    bool session::stop()
    {
        //stop session_impl;
        m_impl->call_abort();
        return true;
    }

	session_proxy session::abort()
	{
		// stop calling the alert notify function now, to avoid it thinking the
		// session is still alive
		m_impl->alerts().set_notify_function({});
		return session_proxy(m_io_service, m_thread, m_impl);
	}

	session_proxy::session_proxy() = default;
	session_proxy::session_proxy(std::shared_ptr<io_context> ios
		, std::shared_ptr<std::thread> t
		, std::shared_ptr<aux::session_impl> impl)
		: m_io_service(std::move(ios))
		, m_thread(std::move(t))
		, m_impl(std::move(impl))
	{}
	session_proxy::session_proxy(session_proxy const&) = default;
	session_proxy& session_proxy::operator=(session_proxy const&) & = default;
	session_proxy::session_proxy(session_proxy&&) noexcept = default;
	session_proxy& session_proxy::operator=(session_proxy&&) & noexcept = default;
	session_proxy::~session_proxy()
	{
		if (m_thread && m_thread.use_count() == 1)
		{
#if defined TORRENT_ASIO_DEBUGGING
			wait_for_asio_handlers();
#endif
			m_thread->join();
		}
	}
}
