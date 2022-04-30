/*

Copyright (c) 2003-2004, 2006-2007, 2009-2010, 2013-2020, Arvid Norberg
Copyright (c) 2015, Steven Siloti
Copyright (c) 2016, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_SESSION_HPP_INCLUDED
#define TORRENT_SESSION_HPP_INCLUDED

#include <thread>

#include "libTAU/config.hpp"
#include "libTAU/io_context.hpp"
#include "libTAU/settings_pack.hpp"
#include "libTAU/session_handle.hpp"
#include "libTAU/kademlia/dht_storage.hpp"
#include "libTAU/session_params.hpp"
#include "libTAU/session_types.hpp" // for session_flags_t

namespace libTAU {

	struct plugin;
	struct session_params;

	// The default values of the session settings are set for a regular
	// bittorrent client running on a desktop system. There are functions that
	// can set the session settings to pre set settings for other environments.
	// These can be used for the basis, and should be tweaked to fit your needs
	// better.
	//
	// ``min_memory_usage`` returns settings that will use the minimal amount of
	// RAM, at the potential expense of upload and download performance. It
	// adjusts the socket buffer sizes, disables the disk cache, lowers the send
	// buffer watermarks so that each connection only has at most one block in
	// use at any one time. It lowers the outstanding blocks send to the disk
	// I/O thread so that connections only have one block waiting to be flushed
	// to disk at any given time. It lowers the max number of peers in the peer
	// list for torrents. It performs multiple smaller reads when it hashes
	// pieces, instead of reading it all into memory before hashing.
	//
	// This configuration is intended to be the starting point for embedded
	// devices. It will significantly reduce memory usage.
	//
	// ``high_performance_seed`` returns settings optimized for a seed box,
	// serving many peers and that doesn't do any downloading. It has a 128 MB
	// disk cache and has a limit of 400 files in its file pool. It support fast
	// upload rates by allowing large send buffers.
	TORRENT_EXPORT settings_pack min_memory_usage();
	TORRENT_EXPORT settings_pack high_performance_seed();

namespace aux {

	struct session_impl;
}

	struct counters;
	struct settings_interface;

	// this is a holder for the internal session implementation object. Once the
	// session destruction is explicitly initiated, this holder is used to
	// synchronize the completion of the shutdown. The lifetime of this object
	// may outlive session, causing the session destructor to not block. The
	// session_proxy destructor will block however, until the underlying session
	// is done shutting down.
	struct TORRENT_EXPORT session_proxy
	{
		friend struct session;
		// default constructor, does not refer to any session
		// implementation object.
		session_proxy();
		~session_proxy();
		session_proxy(session_proxy const&);
		session_proxy& operator=(session_proxy const&) &;
		session_proxy(session_proxy&&) noexcept;
		session_proxy& operator=(session_proxy&&) & noexcept;
	private:
		session_proxy(
			std::shared_ptr<io_context> ios
			, std::shared_ptr<std::thread> t
			, std::shared_ptr<aux::session_impl> impl);

		std::shared_ptr<io_context> m_io_service;
		std::shared_ptr<std::thread> m_thread;
		std::shared_ptr<aux::session_impl> m_impl;
	};

	// The session holds all state that spans multiple torrents. Among other
	// things it runs the network loop and manages all torrents. Once it's
	// created, the session object will spawn the main thread that will do all
	// the work. The main thread will be idle as long it doesn't have any
	// torrents to participate in.
	//
	// You have some control over session configuration through the
	// ``session_handle::apply_settings()`` member function. To change one or more
	// configuration options, create a settings_pack. object and fill it with
	// the settings to be set and pass it in to ``session::apply_settings()``.
	//
	// see apply_settings().
	struct TORRENT_EXPORT session : session_handle
	{
		// Constructs the session objects which acts as the container of torrents.
		// In order to avoid a race condition between starting the session and
		// configuring it, you can pass in a session_params object. Its settings
		// will take effect before the session starts up.
		explicit session(session_params const& params);
		explicit session(session_params&& params);

#if TORRENT_ABI_VERSION < 4
		TORRENT_DEPRECATED session(session_params const& params, session_flags_t flags);
		TORRENT_DEPRECATED session(session_params&& params, session_flags_t flags);
#endif
		session();

		// Overload of the constructor that takes an external io_context to run
		// the session object on. This is primarily useful for tests that may want
		// to run multiple sessions on a single io_context, or low resource
		// systems where additional threads are expensive and sharing an
		// io_context with other events is fine.
		//
		// .. warning::
		// 	The session object does not cleanly terminate with an external
		// 	``io_context``. The ``io_context::run()`` call *must* have returned
		// 	before it's safe to destruct the session. Which means you *MUST*
		// 	call session::abort() and save the session_proxy first, then
		// 	destruct the session object, then sync with the io_context, then
		// 	destruct the session_proxy object.
		session(session_params&& params, io_context& ios);
		session(session_params const& params, io_context& ios);
#if TORRENT_ABI_VERSION < 4
		TORRENT_DEPRECATED session(session_params&& params, io_context& ios, session_flags_t);
		TORRENT_DEPRECATED session(session_params const& params, io_context& ios, session_flags_t);
#endif

		// hidden
		session(session&&);
		session& operator=(session&&) &;

		// hidden
		session(session const&) = delete;
		session& operator=(session const&) = delete;

		// The destructor of session will notify all trackers that our torrents
		// have been shut down. If some trackers are down, they will time out.
		// All this before the destructor of session returns. So, it's advised
		// that any kind of interface (such as windows) are closed before
		// destructing the session object. Because it can take a few second for
		// it to finish. The timeout can be set with apply_settings().
		~session();

        bool stop();

		// In case you want to destruct the session asynchronously, you can
		// request a session destruction proxy. If you don't do this, the
		// destructor of the session object will block while the trackers are
		// contacted. If you keep one ``session_proxy`` to the session when
		// destructing it, the destructor will not block, but start to close down
		// the session, the destructor of the proxy will then synchronize the
		// threads. So, the destruction of the session is performed from the
		// ``session`` destructor call until the ``session_proxy`` destructor
		// call. The ``session_proxy`` does not have any operations on it (since
		// the session is being closed down, no operations are allowed on it).
		// The only valid operation is calling the destructor::
		//
		// 	struct session_proxy {};
		session_proxy abort();

	private:

		void start(session_flags_t, session_params&& params, io_context* ios);

		void start(session_params const& params, io_context* ios) = delete;

		// data shared between the main thread
		// and the working thread
		std::shared_ptr<io_context> m_io_service;
		std::shared_ptr<std::thread> m_thread;
		std::shared_ptr<aux::session_impl> m_impl;
	};

}

#endif // TORRENT_SESSION_HPP_INCLUDED
