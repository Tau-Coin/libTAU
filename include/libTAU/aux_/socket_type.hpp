/*

Copyright (c) 2007, 2009-2010, 2012-2013, 2019-2020, Arvid Norberg
Copyright (c) 2016, 2021, Alden Torres
Copyright (c) 2020, Paul-Louis Ageneau
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_SOCKET_TYPE
#define TORRENT_SOCKET_TYPE

#include "libTAU/assert.hpp"
#include "libTAU/aux_/polymorphic_socket.hpp"
#include "libTAU/aux_/rtc_stream.hpp"
#include "libTAU/aux_/utp_stream.hpp"
#include "libTAU/config.hpp"
#include "libTAU/i2p_stream.hpp"
#include "libTAU/io_context.hpp"
#include "libTAU/socket.hpp"
#include "libTAU/socket_type.hpp"
#include "libTAU/socks5_stream.hpp"

#if TORRENT_USE_SSL
#include "libTAU/aux_/ssl_stream.hpp"
#endif

#include "libTAU/aux_/debug.hpp"

namespace libTAU::aux {

	using socket_type = polymorphic_socket<
		tcp::socket
		, socks5_stream
		, utp_stream
#if TORRENT_USE_I2P
		, i2p_stream
#endif
#if TORRENT_USE_RTC
		, rtc_stream
#endif
#if TORRENT_USE_SSL
		, ssl_stream<tcp::socket>
		, ssl_stream<socks5_stream>
		, ssl_stream<utp_stream>
#endif
	>;

	// returns true if this socket is an SSL socket
	bool is_ssl(socket_type const& s);

	// returns true if this is a uTP socket
	bool is_utp(socket_type const& s);

	socket_type_t socket_type_idx(socket_type const& s);

	char const* socket_type_name(socket_type const& s);

	// this is only relevant for uTP connections
	void set_close_reason(socket_type& s, close_reason_t code);
	close_reason_t get_close_reason(socket_type const& s);

#if TORRENT_USE_I2P
	// returns true if this is an i2p socket
	bool is_i2p(socket_type const& s);
#endif

#if TORRENT_USE_RTC
	// returns true if this is a WebRTC socket
	bool is_rtc(socket_type const& s);
#endif

	// assuming the socket_type s is an ssl socket, make sure it
	// verifies the hostname in its SSL handshake
	void setup_ssl_hostname(socket_type& s, std::string const& hostname, error_code& ec);

	// properly shuts down SSL sockets. holder keeps s alive
	void async_shutdown(socket_type& s, std::shared_ptr<void> holder);
}

#endif
