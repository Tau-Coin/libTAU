/*

Copyright (c) 2003, Daniel Wallin
Copyright (c) 2004, Magnus Jonsson
Copyright (c) 2009-2021, Arvid Norberg
Copyright (c) 2014-2018, Steven Siloti
Copyright (c) 2015, Thomas
Copyright (c) 2015-2018, 2020-2021, Alden Torres
Copyright (c) 2016, Pavel Pimenov
Copyright (c) 2017, Andrei Kurushin
Copyright (c) 2017, Antoine Dahan
Copyright (c) 2019, Amir Abrams
Copyright (c) 2020, Fonic
Copyright (c) 2020, Viktor Elofsson
Copyright (c) 2020, Paul-Louis Ageneau
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <string>
#include <cstdio> // for snprintf
#include <cinttypes> // for PRId64 et.al.
#include <utility>

#include "libTAU/config.hpp"
#include "libTAU/alert.hpp"
#include "libTAU/alert_types.hpp"
#include "libTAU/aux_/socket_io.hpp"
#include "libTAU/error_code.hpp"
#include "libTAU/performance_counters.hpp"
#include "libTAU/aux_/stack_allocator.hpp"
#include "libTAU/hex.hpp" // to_hex
#include "libTAU/session_stats.hpp"
#include "libTAU/socket_type.hpp"
#include "libTAU/aux_/ip_helpers.hpp" // for is_v4
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"
#include "libTAU/communication/message.hpp"

#if TORRENT_ABI_VERSION == 1
#include "libTAU/write_resume_data.hpp"
#endif

#include "libTAU/aux_/escape_string.hpp" // for convert_from_native

namespace libTAU {

	alert::alert() : m_timestamp(clock_type::now()) {}
	alert::~alert() = default;
	time_point alert::timestamp() const { return m_timestamp; }

namespace {

#ifndef TORRENT_DISABLE_ALERT_MSG
	char const* const nat_type_str[] = {"NAT-PMP", "UPnP"};

	char const* const protocol_str[] = {"none", "TCP", "UDP"};
#endif

#if TORRENT_ABI_VERSION == 1
	int sock_type_idx(socket_type_t type)
	{
		// these numbers are the deprecated enum values in
		// listen_succeeded_alert and listen_failed_alert
		static aux::array<int, 10, socket_type_t> const mapping{{
			0, // tcp
			4, // socks5,
			0, // http,
			2, // utp,
			3, // i2p,
			0, // rtc,
			1, // tcp_ssl,
			4, // socks5_ssl,
			1, // http_ssl,
			5  // utp_ssl,
		}};
		return mapping[type];
	}

	int to_op_t(operation_t op)
	{
		using o = operation_t;
		using lfo = listen_failed_alert::op_t;

		// we have to use deprecated enum values here. suppress the warnings
#include "libTAU/aux_/disable_deprecation_warnings_push.hpp"
		switch (op)
		{
			case o::bittorrent: return -1;
			case o::iocontrol: return -1;
			case o::getpeername: return -1;
			case o::getname: return lfo::get_socket_name;
			case o::alloc_recvbuf: return -1;
			case o::alloc_sndbuf: return -1;
			case o::file_write: return -1;
			case o::file_read: return -1;
			case o::file: return -1;
			case o::sock_write: return -1;
			case o::sock_read: return -1;
			case o::sock_open: return lfo::open;
			case o::sock_bind: return lfo::bind;
			case o::available: return -1;
			case o::encryption: return -1;
			case o::connect: return -1;
			case o::ssl_handshake: return -1;
			case o::get_interface: return -1;
			case o::unknown: return -1;
			case o::sock_listen: return lfo::listen;
			case o::sock_bind_to_device: return lfo::bind_to_device;
			case o::sock_accept: return lfo::accept;
			case o::parse_address: return lfo::parse_addr;
			case o::enum_if: return lfo::enum_if;
			case o::file_stat: return -1;
			case o::file_copy: return -1;
			case o::file_fallocate: return -1;
			case o::file_hard_link: return -1;
			case o::file_remove: return -1;
			case o::file_rename: return -1;
			case o::file_open: return -1;
			case o::mkdir: return -1;
			case o::check_resume: return -1;
			case o::exception: return -1;
			case o::alloc_cache_piece: return -1;
			case o::partfile_move: return -1;
			case o::partfile_read: return -1;
			case o::partfile_write: return -1;
			case o::hostname_lookup: return -1;
			case o::symlink: return -1;
			case o::handshake: return -1;
			case o::sock_option: return -1;
			case o::enum_route: return -1;
			case o::file_seek: return -1;
			case o::timer: return -1;
			case o::file_mmap: return -1;
			case o::file_truncate: return -1;
		}
		return -1;
	}
#include "libTAU/aux_/disable_warnings_pop.hpp"

#endif // TORRENT_ABI_VERSION

} // anonymous namespace

	listen_failed_alert::listen_failed_alert(
		aux::stack_allocator& alloc
		, string_view iface
		, libTAU::address const& listen_addr
		, int listen_port
		, operation_t const op_
		, error_code const& ec
		, libTAU::socket_type_t t)
		: error(ec)
		, op(op_)
		, socket_type(t)
		, address(listen_addr)
		, port(listen_port)
		, m_alloc(alloc)
		, m_interface_idx(alloc.copy_string(iface))
#if TORRENT_ABI_VERSION == 1
		, operation(to_op_t(op_))
		, endpoint(listen_addr, std::uint16_t(listen_port))
		, sock_type(static_cast<socket_type_t>(sock_type_idx(t)))
#endif
	{}

	listen_failed_alert::listen_failed_alert(
		aux::stack_allocator& alloc
		, string_view iface
		, tcp::endpoint const& ep
		, operation_t const op_
		, error_code const& ec
		, libTAU::socket_type_t t)
		: listen_failed_alert(alloc
			, iface
			, ep.address()
			, ep.port()
			, op_
			, ec
			, t)
	{}

	listen_failed_alert::listen_failed_alert(
		aux::stack_allocator& alloc
		, string_view iface
		, udp::endpoint const& ep
		, operation_t const op_
		, error_code const& ec
		, libTAU::socket_type_t t)
		: listen_failed_alert(alloc
			, iface
			, ep.address()
			, ep.port()
			, op_
			, ec
			, t)
	{}

	listen_failed_alert::listen_failed_alert(
		aux::stack_allocator& alloc
		, string_view iface
		, operation_t const op_
		, error_code const& ec
		, libTAU::socket_type_t t)
		: listen_failed_alert(alloc
			, iface
			, libTAU::address()
			, 0
			, op_
			, ec
			, t)
	{}

	char const* listen_failed_alert::listen_interface() const
	{
		return m_alloc.get().ptr(m_interface_idx);
	}

	std::string listen_failed_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char ret[300];
		std::snprintf(ret, sizeof(ret), "listening on %s (device: %s) failed: [%s] [%s] %s"
			, print_endpoint(address, port).c_str()
			, listen_interface()
			, operation_name(op)
			, socket_type_name(socket_type)
			, convert_from_native(error.message()).c_str());
		return ret;
#endif
	}

	udp_error_alert::udp_error_alert(
		aux::stack_allocator&
		, udp::endpoint const& ep
		, operation_t op
		, error_code const& ec)
		: endpoint(ep)
		, operation(op)
		, error(ec)
	{}

	std::string udp_error_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		return "UDP error: " + convert_from_native(error.message())
			+ " from: " + endpoint.address().to_string()
			+ " op: " + operation_name(operation);
#endif
	}

	external_ip_alert::external_ip_alert(aux::stack_allocator&
		, address const& ip)
		: external_address(ip)
	{}

	std::string external_ip_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		return "external IP received: " + external_address.to_string();
#endif
	}

	listen_succeeded_alert::listen_succeeded_alert(aux::stack_allocator&
		, libTAU::address const& listen_addr
		, int listen_port
		, libTAU::socket_type_t t)
		: address(listen_addr)
		, port(listen_port)
		, socket_type(t)
#if TORRENT_ABI_VERSION == 1
		, endpoint(listen_addr, std::uint16_t(listen_port))
		, sock_type(static_cast<socket_type_t>(sock_type_idx(t)))
#endif
	{}

	listen_succeeded_alert::listen_succeeded_alert(aux::stack_allocator& alloc
		, tcp::endpoint const& ep
		, libTAU::socket_type_t t)
		: listen_succeeded_alert(alloc
			, ep.address()
			, ep.port()
			, t)
	{}

	listen_succeeded_alert::listen_succeeded_alert(aux::stack_allocator& alloc
		, udp::endpoint const& ep
		, libTAU::socket_type_t t)
		: listen_succeeded_alert(alloc
			, ep.address()
			, ep.port()
			, t)
	{}

	std::string listen_succeeded_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char ret[200];
		std::snprintf(ret, sizeof(ret), "libTAU successfully listening on [%s] %s"
			, socket_type_name(socket_type), print_endpoint(address, port).c_str());
		return ret;
#endif
	}

	portmap_error_alert::portmap_error_alert(aux::stack_allocator&
		, port_mapping_t const i, portmap_transport const t, error_code const& e
		, address const& local)
		: mapping(i)
		, map_transport(t)
		, local_address(local)
		, error(e)
#if TORRENT_ABI_VERSION == 1
		, map_type(static_cast<int>(t))
		, msg(convert_from_native(error.message()))
#endif
	{}

	std::string portmap_error_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		return std::string("could not map port using ")
			+ nat_type_str[static_cast<int>(map_transport)]
			+ "[" + local_address.to_string() + "]: "
			+ convert_from_native(error.message());
#endif
	}

	portmap_alert::portmap_alert(aux::stack_allocator&, port_mapping_t const i
		, int const port, portmap_transport const t, portmap_protocol const proto
		, address const& local)
		: mapping(i)
		, external_port(port)
		, map_protocol(proto)
		, map_transport(t)
		, local_address(local)
#if TORRENT_ABI_VERSION == 1
		, protocol(static_cast<int>(proto))
		, map_type(static_cast<int>(t))
#endif
	{}

	std::string portmap_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char ret[200];
		std::snprintf(ret, sizeof(ret), "successfully mapped port using %s. local: %s external port: %s/%d"
			, nat_type_str[static_cast<int>(map_transport)]
			, local_address.to_string().c_str()
			, protocol_str[static_cast<int>(map_protocol)], external_port);
		return ret;
#endif
	}

	portmap_log_alert::portmap_log_alert(aux::stack_allocator& alloc
		, portmap_transport const t, const char* m, address const& local)
		: map_transport(t)
		, local_address(local)
		, m_alloc(alloc)
		, m_log_idx(alloc.copy_string(m))
#if TORRENT_ABI_VERSION == 1
		, map_type(static_cast<int>(t))
		, msg(m)
#endif
	{}

	char const* portmap_log_alert::log_message() const
	{
		return m_alloc.get().ptr(m_log_idx);
	}

	std::string portmap_log_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char ret[1024];
		std::snprintf(ret, sizeof(ret), "%s [%s]: %s"
			, nat_type_str[static_cast<int>(map_transport)]
			, local_address.to_string().c_str()
			, log_message());
		return ret;
#endif
	}

	dht_announce_alert::dht_announce_alert(aux::stack_allocator&
		, address const& i, int p
		, sha256_hash const& ih)
		: ip(i)
		, port(p)
		, info_hash(ih)
	{}

	std::string dht_announce_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[200];
		std::snprintf(msg, sizeof(msg), "incoming dht announce: %s:%d (%s)"
			, ip.to_string().c_str(), port, aux::to_hex(info_hash).c_str());
		return msg;
#endif
	}

	dht_get_peers_alert::dht_get_peers_alert(aux::stack_allocator&
		, sha256_hash const& ih)
		: info_hash(ih)
	{}

	std::string dht_get_peers_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[200];
		std::snprintf(msg, sizeof(msg), "incoming dht get_peers: %s", aux::to_hex(info_hash).c_str());
		return msg;
#endif
	}

#if TORRENT_ABI_VERSION <= 2
namespace {

		std::array<int, stats_alert::num_channels> stat_to_array(aux::stat const& s)
		{
			std::array<int, stats_alert::num_channels> arr{};

			arr[stats_alert::upload_payload] = s[aux::stat::upload_payload].counter();
			arr[stats_alert::upload_protocol] = s[aux::stat::upload_protocol].counter();
			arr[stats_alert::download_payload] = s[aux::stat::download_payload].counter();
			arr[stats_alert::download_protocol] = s[aux::stat::download_protocol].counter();
			arr[stats_alert::upload_ip_protocol] = s[aux::stat::upload_ip_protocol].counter();
			arr[stats_alert::download_ip_protocol] = s[aux::stat::download_ip_protocol].counter();

#if TORRENT_ABI_VERSION == 1
			arr[stats_alert::upload_dht_protocol] = 0;
			arr[stats_alert::upload_tracker_protocol] = 0;
			arr[stats_alert::download_dht_protocol] = 0;
			arr[stats_alert::download_tracker_protocol] = 0;
#else
			arr[stats_alert::deprecated1] = 0;
			arr[stats_alert::deprecated2] = 0;
			arr[stats_alert::deprecated3] = 0;
			arr[stats_alert::deprecated4] = 0;
#endif
			return arr;
		}
	}
#endif // TORRENT_ABI_VERSION


	dht_bootstrap_alert::dht_bootstrap_alert(aux::stack_allocator&)
	{}

	std::string dht_bootstrap_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		return "DHT bootstrap complete";
#endif
	}

	session_start_over_alert::session_start_over_alert( aux::stack_allocator&
		, bool start_over)
		: session_start_over(start_over)
	{}

	std::string session_start_over_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[100];
		std::snprintf(msg, sizeof(msg), " Session Start Over");
		return msg;
#endif
	}

	incoming_connection_alert::incoming_connection_alert(aux::stack_allocator&
		, socket_type_t t, tcp::endpoint const& i)
		: socket_type(t)
		, endpoint(i)
#if TORRENT_ABI_VERSION == 1
		, ip(i)
#endif
	{}

	std::string incoming_connection_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[600];
		std::snprintf(msg, sizeof(msg), "incoming connection from %s (%s)"
			, print_endpoint(endpoint).c_str(), socket_type_name(socket_type));
		return msg;
#endif
	}

	session_stop_over_alert::session_stop_over_alert(aux::stack_allocator&
		, bool over): session_stop_over(over)
	{}

	std::string session_stop_over_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[100];
		std::snprintf(msg, sizeof(msg), " Session Stop Over");
		return msg;
#endif
	}

	char const* operation_name(operation_t const op)
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		TORRENT_UNUSED(op);
		return "";
#else
		static char const* const names[] = {
			"unknown",
			"bittorrent",
			"iocontrol",
			"getpeername",
			"getname",
			"alloc_recvbuf",
			"alloc_sndbuf",
			"file_write",
			"file_read",
			"file",
			"sock_write",
			"sock_read",
			"sock_open",
			"sock_bind",
			"available",
			"encryption",
			"connect",
			"ssl_handshake",
			"get_interface",
			"sock_listen",
			"sock_bind_to_device",
			"sock_accept",
			"parse_address",
			"enum_if",
			"file_stat",
			"file_copy",
			"file_fallocate",
			"file_hard_link",
			"file_remove",
			"file_rename",
			"file_open",
			"mkdir",
			"check_resume",
			"exception",
			"alloc_cache_piece",
			"partfile_move",
			"partfile_read",
			"partfile_write",
			"hostname_lookup",
			"symlink",
			"handshake",
			"sock_option",
			"enum_route",
			"file_seek",
			"timer",
			"file_mmap",
			"file_truncate",
		};

		int const idx = static_cast<int>(op);
		if (idx < 0 || idx >= int(sizeof(names) / sizeof(names[0])))
			return "unknown operation";

		return names[idx];
#endif
	}

#if TORRENT_ABI_VERSION == 1
	char const* operation_name(int const op)
	{
		return operation_name(static_cast<operation_t>(op));
	}
#endif

	dht_error_alert::dht_error_alert(aux::stack_allocator&
		, operation_t const op_
		, error_code const& ec)
		: error(ec)
		, op(op_)
#if TORRENT_ABI_VERSION == 1
		, operation(op_ == operation_t::hostname_lookup
			? op_t::hostname_lookup : op_t::unknown)
#endif
	{}

	std::string dht_error_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[600];
		std::snprintf(msg, sizeof(msg), "DHT error [%s] (%d) %s"
			, operation_name(op)
			, error.value()
			, convert_from_native(error.message()).c_str());
		return msg;
#endif
	}

	dht_immutable_item_alert::dht_immutable_item_alert(aux::stack_allocator&
		, sha256_hash const& t, entry i)
		: target(t), item(std::move(i))
	{}

	std::string dht_immutable_item_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[1050];
		std::snprintf(msg, sizeof(msg), "DHT immutable item %s [ %s ]"
			, aux::to_hex(target).c_str()
			, item.to_string().c_str());
		return msg;
#endif
	}

	// TODO: 2 the salt here is allocated on the heap. It would be nice to
	// allocate in the stack_allocator
	dht_mutable_item_alert::dht_mutable_item_alert(aux::stack_allocator&
		, std::array<char, 32> const& k
		, std::array<char, 64> const& sig
		, std::int64_t timestamp
		, string_view s
		, entry i
		, bool a)
		: key(k), signature(sig), ts(timestamp), salt(s), item(std::move(i)), authoritative(a)
	{}

	std::string dht_mutable_item_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[1050];
		std::snprintf(msg, sizeof(msg), "DHT mutable item (key=%s salt=%s timestamp=%" PRId64 " %s) [ %s ]"
			, aux::to_hex(key).c_str()
			, salt.c_str()
			, ts
			, authoritative ? "auth" : "non-auth"
			, item.to_string().c_str());
		return msg;
#endif
	}

	dht_put_alert::dht_put_alert(aux::stack_allocator&, sha256_hash const& t, int n)
		: target(t)
		, public_key()
		, signature()
		, ts(0)
		, num_success(n)
	{}

	dht_put_alert::dht_put_alert(aux::stack_allocator&
		, std::array<char, 32> const& key
		, std::array<char, 64> const& sig
		, std::string s
		, std::int64_t timestamp
		, int n)
		: target(nullptr)
		, public_key(key)
		, signature(sig)
		, salt(std::move(s))
		, ts(timestamp)
		, num_success(n)
	{}

	std::string dht_put_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[1050];
		if (target.is_all_zeros())
		{
			std::snprintf(msg, sizeof(msg), "DHT put complete (success=%d key=%s sig=%s salt=%s timestamp=%" PRId64 ")"
				, num_success
				, aux::to_hex(public_key).c_str()
				, aux::to_hex(signature).c_str()
				, salt.c_str()
				, ts);
			return msg;
		}

		std::snprintf(msg, sizeof(msg), "DHT put complete (success=%d hash=%s)"
			, num_success
			, aux::to_hex(target).c_str());
		return msg;
#endif
	}

	dht_outgoing_get_peers_alert::dht_outgoing_get_peers_alert(aux::stack_allocator&
		, sha256_hash const& ih, sha256_hash const& obfih
		, udp::endpoint ep)
		: info_hash(ih)
		, obfuscated_info_hash(obfih)
		, endpoint(std::move(ep))
#if TORRENT_ABI_VERSION == 1
		, ip(endpoint)
#endif
	{}

	std::string dht_outgoing_get_peers_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[600];
		char obf[70];
		obf[0] = '\0';
		if (obfuscated_info_hash != info_hash)
		{
			std::snprintf(obf, sizeof(obf), " [obfuscated: %s]"
			, aux::to_hex(obfuscated_info_hash).c_str());
		}
		std::snprintf(msg, sizeof(msg), "outgoing dht get_peers : %s%s -> %s"
			, aux::to_hex(info_hash).c_str()
			, obf
			, print_endpoint(endpoint).c_str());
		return msg;
#endif
	}

	log_alert::log_alert(aux::stack_allocator& alloc, char const* log)
		: m_alloc(alloc)
		, m_str_idx(alloc.copy_string(log))
	{}
	log_alert::log_alert(aux::stack_allocator& alloc, char const* fmt, va_list v)
		: m_alloc(alloc)
		, m_str_idx(alloc.format_string(fmt, v))
	{}

	char const* log_alert::log_message() const
	{
		return m_alloc.get().ptr(m_str_idx);
	}

#if TORRENT_ABI_VERSION == 1
	char const* log_alert::msg() const
	{
		return log_message();
	}
#endif

	std::string log_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		return log_message();
#endif
	}

#if TORRENT_ABI_VERSION == 1
namespace {

	aux::array<std::int64_t, counters::num_counters> counters_to_array(counters const& cnt)
	{
		aux::array<std::int64_t, counters::num_counters> arr;

		for (int i = 0; i < counters::num_counters; ++i)
			arr[i] = cnt[i];

		return arr;
	}
}
#else
namespace {
	template <typename T, typename U>
	T* align_pointer(U* ptr)
	{
		return reinterpret_cast<T*>((reinterpret_cast<std::uintptr_t>(ptr) + alignof(T) - 1)
			& ~(alignof(T) - 1));
	}
}
#endif

#if TORRENT_ABI_VERSION == 1
	session_stats_alert::session_stats_alert(aux::stack_allocator&, struct counters const& cnt)
		: values(counters_to_array(cnt))
	{}
#else
	session_stats_alert::session_stats_alert(aux::stack_allocator& alloc, struct counters const& cnt)
		: m_alloc(alloc)
		, m_counters_idx(alloc.allocate(sizeof(std::int64_t)
			* counters::num_counters + sizeof(std::int64_t) - 1))
	{
		std::int64_t* ptr = align_pointer<std::int64_t>(alloc.ptr(m_counters_idx));
		for (int i = 0; i < counters::num_counters; ++i, ++ptr)
			*ptr = cnt[i];
	}
#endif

	std::string session_stats_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[50];
		auto cnt = counters();
		std::snprintf(msg, sizeof(msg), "session stats (%d values): " , int(cnt.size()));
		std::string ret = msg;
		bool first = true;
		for (auto v : cnt)
		{
			std::snprintf(msg, sizeof(msg), first ? "%" PRId64 : ", %" PRId64, v);
			first = false;
			ret += msg;
		}
		return ret;
#endif
	}

	span<std::int64_t const> session_stats_alert::counters() const
	{
#if TORRENT_ABI_VERSION == 1
		return values;
#else
		return { align_pointer<std::int64_t const>(m_alloc.get().ptr(m_counters_idx))
			, counters::num_counters };
#endif
	}

	dht_stats_alert::dht_stats_alert(aux::stack_allocator&
		, std::vector<dht_routing_bucket> table
		, std::vector<dht_lookup> requests
			, sha256_hash id, udp::endpoint ep)
		: alert()
		, active_requests(std::move(requests))
		, routing_table(std::move(table))
		, nid(id)
		, local_endpoint(ep)
	{}

	std::string dht_stats_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char buf[2048];
		std::snprintf(buf, sizeof(buf), "DHT stats: (%s) reqs: %d buckets: %d"
			, aux::to_hex(nid).c_str()
			, int(active_requests.size())
			, int(routing_table.size()));
		return buf;
#endif
	}

	dht_log_alert::dht_log_alert(aux::stack_allocator& alloc
		, dht_log_alert::dht_module_t m, const char* fmt, va_list v)
		: module(m)
		, m_alloc(alloc)
		, m_msg_idx(alloc.format_string(fmt, v))
	{}

	char const* dht_log_alert::log_message() const
	{
		return m_alloc.get().ptr(m_msg_idx);
	}

	std::string dht_log_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		static char const* const dht_modules[] =
		{
			"tracker",
			"node",
			"routing_table",
			"rpc_manager",
			"traversal",
			"incoming_table",
			"items_db",
			"bs_nodes_db"
		};

		char ret[900];
		std::snprintf(ret, sizeof(ret), "DHT %s: %s", dht_modules[module]
			, log_message());
		return ret;
#endif
	}

	dht_pkt_alert::dht_pkt_alert(aux::stack_allocator& alloc
		, span<char const> buf, dht_pkt_alert::direction_t d
		, udp::endpoint const& ep)
		: direction(d)
		, node(ep)
		, m_alloc(alloc)
		, m_msg_idx(alloc.copy_buffer(buf))
		, m_size(aux::numeric_cast<int>(buf.size()))
#if TORRENT_ABI_VERSION == 1
		, dir(d)
#endif
	{}

	span<char const> dht_pkt_alert::pkt_buf() const
	{
		return {m_alloc.get().ptr(m_msg_idx), m_size};
	}

	std::string dht_pkt_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		bdecode_node print;
		error_code ec;

		// ignore errors here. This is best-effort. It may be a broken encoding
		// but at least we'll print the valid parts
		span<char const> pkt = pkt_buf();
		bdecode(pkt.data(), pkt.data() + int(pkt.size()), print, ec, nullptr, 100, 100);

		std::string msg = print_entry(print, true);

		static char const* const prefix[2] = {"<==", "==>"};
		char buf[1024];
		std::snprintf(buf, sizeof(buf), "%s [%s] %s", prefix[direction]
			, print_endpoint(node).c_str(), msg.c_str());

		return buf;
#endif
	}

	dht_get_peers_reply_alert::dht_get_peers_reply_alert(aux::stack_allocator& alloc
		, sha1_hash const& ih
		, std::vector<tcp::endpoint> const& peers)
		: info_hash(ih)
		, m_alloc(alloc)
	{
		for (auto const& endp : peers)
		{
			if (aux::is_v4(endp))
				m_v4_num_peers++;
			else
				m_v6_num_peers++;
		}

		m_v4_peers_idx = alloc.allocate(m_v4_num_peers * 6);
		m_v6_peers_idx = alloc.allocate(m_v6_num_peers * 18);

		char* v4_ptr = alloc.ptr(m_v4_peers_idx);
		char* v6_ptr = alloc.ptr(m_v6_peers_idx);
		for (auto const& endp : peers)
		{
			if (aux::is_v4(endp))
				aux::write_endpoint(endp, v4_ptr);
			else
				aux::write_endpoint(endp, v6_ptr);
		}
	}

	std::string dht_get_peers_reply_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[200];
		std::snprintf(msg, sizeof(msg), "incoming dht get_peers reply: %s, peers %d"
			, aux::to_hex(info_hash).c_str(), num_peers());
		return msg;
#endif
	}

	int dht_get_peers_reply_alert::num_peers() const
	{
		return m_v4_num_peers + m_v6_num_peers;
	}

#if TORRENT_ABI_VERSION == 1
	void dht_get_peers_reply_alert::peers(std::vector<tcp::endpoint> &v) const
	{
		std::vector<tcp::endpoint> p(peers());
		v.reserve(p.size());
		std::copy(p.begin(), p.end(), std::back_inserter(v));
	}
#endif
	std::vector<tcp::endpoint> dht_get_peers_reply_alert::peers() const
	{
		aux::vector<tcp::endpoint> peers;
		peers.reserve(num_peers());

		char const* v4_ptr = m_alloc.get().ptr(m_v4_peers_idx);
		for (int i = 0; i < m_v4_num_peers; i++)
			peers.push_back(aux::read_v4_endpoint<tcp::endpoint>(v4_ptr));
		char const* v6_ptr = m_alloc.get().ptr(m_v6_peers_idx);
		for (int i = 0; i < m_v6_num_peers; i++)
			peers.push_back(aux::read_v6_endpoint<tcp::endpoint>(v6_ptr));

		return std::move(peers);
	}

	dht_direct_response_alert::dht_direct_response_alert(
		aux::stack_allocator& alloc, client_data_t userdata_
		, udp::endpoint const& addr_, bdecode_node const& response)
		: userdata(userdata_), endpoint(addr_)
		, m_alloc(alloc)
		, m_response_idx(alloc.copy_buffer(response.data_section()))
		, m_response_size(int(response.data_section().size()))
#if TORRENT_ABI_VERSION == 1
		, addr(addr_)
#endif
	{}

	dht_direct_response_alert::dht_direct_response_alert(
		aux::stack_allocator& alloc
		, client_data_t userdata_
		, udp::endpoint const& addr_)
		: userdata(userdata_), endpoint(addr_)
		, m_alloc(alloc)
		, m_response_size(0)
#if TORRENT_ABI_VERSION == 1
		, addr(addr_)
#endif
	{}

	std::string dht_direct_response_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[1050];
		std::snprintf(msg, sizeof(msg), "DHT direct response (address=%s) [ %s ]"
			, endpoint.address().to_string().c_str()
			, m_response_size ? std::string(m_alloc.get().ptr(m_response_idx)
				, aux::numeric_cast<std::size_t>(m_response_size)).c_str() : "");
		return msg;
#endif
	}

	bdecode_node dht_direct_response_alert::response() const
	{
		if (m_response_size == 0) return bdecode_node();
		char const* start = m_alloc.get().ptr(m_response_idx);
		char const* end = start + m_response_size;
		error_code ec;
		bdecode_node ret;
		bdecode(start, end, ret, ec);
		TORRENT_ASSERT(!ec);
		return ret;
	}

	session_error_alert::session_error_alert(aux::stack_allocator& alloc
		, error_code e, string_view error_str)
		: error(e)
		, m_alloc(alloc)
		, m_msg_idx(alloc.copy_buffer(error_str))
	{}

	std::string session_error_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char buf[400];
		if (error)
		{
			std::snprintf(buf, sizeof(buf), "session error: (%d %s) %s"
				, error.value(), convert_from_native(error.message()).c_str()
				, m_alloc.get().ptr(m_msg_idx));
		}
		else
		{
			std::snprintf(buf, sizeof(buf), "session error: %s"
				, m_alloc.get().ptr(m_msg_idx));
		}
		return buf;
#endif
	}

namespace {

	using nodes_slot = std::tuple<int, aux::allocation_slot, int, aux::allocation_slot>;

	nodes_slot write_nodes(aux::stack_allocator& alloc
		, std::vector<std::pair<sha256_hash, udp::endpoint>> const& nodes)
	{
		int v4_num_nodes = 0;
		int v6_num_nodes = 0;

		for (auto const& n : nodes)
		{
			if (aux::is_v4(n.second))
				v4_num_nodes++;
			else
				v6_num_nodes++;
		}

		aux::allocation_slot const v4_nodes_idx = alloc.allocate(v4_num_nodes * (32 + 6));
		aux::allocation_slot const v6_nodes_idx = alloc.allocate(v6_num_nodes * (32 + 18));

		char* v4_ptr = alloc.ptr(v4_nodes_idx);
		char* v6_ptr = alloc.ptr(v6_nodes_idx);
		for (auto const& n : nodes)
		{
			udp::endpoint const& endp = n.second;
			if (aux::is_v4(endp))
			{
				aux::write_string(n.first.to_string(), v4_ptr);
				aux::write_endpoint(endp, v4_ptr);
			}
			else
			{
				aux::write_string(n.first.to_string(), v6_ptr);
				aux::write_endpoint(endp, v6_ptr);
			}
		}

		return nodes_slot{v4_num_nodes, v4_nodes_idx, v6_num_nodes, v6_nodes_idx};
	}

	std::vector<std::pair<sha256_hash, udp::endpoint>> read_nodes(
		aux::stack_allocator const& alloc
		, int const v4_num_nodes, aux::allocation_slot const v4_nodes_idx
		, int const v6_num_nodes, aux::allocation_slot const v6_nodes_idx)
	{
		aux::vector<std::pair<sha256_hash, udp::endpoint>> nodes;
		nodes.reserve(v4_num_nodes + v6_num_nodes);

		char const* v4_ptr = alloc.ptr(v4_nodes_idx);
		for (int i = 0; i < v4_num_nodes; i++)
		{
			sha256_hash ih;
			std::memcpy(ih.data(), v4_ptr, 32);
			v4_ptr += 32;
			nodes.emplace_back(ih, aux::read_v4_endpoint<udp::endpoint>(v4_ptr));
		}
		char const* v6_ptr = alloc.ptr(v6_nodes_idx);
		for (int i = 0; i < v6_num_nodes; i++)
		{
			sha256_hash ih;
			std::memcpy(ih.data(), v6_ptr, 32);
			v6_ptr += 32;
			nodes.emplace_back(ih, aux::read_v6_endpoint<udp::endpoint>(v6_ptr));
		}

		return std::move(nodes);
	}
	}

	dht_live_nodes_alert::dht_live_nodes_alert(aux::stack_allocator& alloc
		, sha256_hash const& nid
		, std::vector<std::pair<sha256_hash, udp::endpoint>> const& nodes)
		: node_id(nid)
		, m_alloc(alloc)
	{
		std::tie(m_v4_num_nodes, m_v4_nodes_idx, m_v6_num_nodes, m_v6_nodes_idx)
			= write_nodes(alloc, nodes);
	}

	std::string dht_live_nodes_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[200];
		std::snprintf(msg, sizeof(msg), "dht live nodes for id: %s, nodes %d"
			, aux::to_hex(node_id).c_str(), num_nodes());
		return msg;
#endif
	}

	int dht_live_nodes_alert::num_nodes() const
	{
		return m_v4_num_nodes + m_v6_num_nodes;
	}

	std::vector<std::pair<sha256_hash, udp::endpoint>> dht_live_nodes_alert::nodes() const
	{
		return read_nodes(m_alloc.get()
			, m_v4_num_nodes, m_v4_nodes_idx
			, m_v6_num_nodes, m_v6_nodes_idx);
	}

	session_stats_header_alert::session_stats_header_alert(aux::stack_allocator&)
	{}

	std::string session_stats_header_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		std::string stats_header = "session stats header: ";
		std::vector<stats_metric> stats = session_stats_metrics();
		std::sort(stats.begin(), stats.end()
			, [] (stats_metric const& lhs, stats_metric const& rhs)
			{ return lhs.value_index < rhs.value_index; });
		bool first = true;
		for (auto const& s : stats)
		{
			if (!first) stats_header += ", ";
			stats_header += s.name;
			first = false;
		}

		return stats_header;
#endif
	}

	dht_sample_infohashes_alert::dht_sample_infohashes_alert(aux::stack_allocator& alloc
		, sha256_hash const& nid
		, udp::endpoint const& endp
		, time_duration _interval
		, int _num
		, std::vector<sha256_hash> const& samples
		, std::vector<std::pair<sha256_hash, udp::endpoint>> const& nodes)
		: node_id(nid)
		, endpoint(endp)
		, interval(_interval)
		, num_infohashes(_num)
		, m_alloc(alloc)
		, m_num_samples(aux::numeric_cast<int>(samples.size()))
	{
		m_samples_idx = alloc.allocate(m_num_samples * 32);

		char *ptr = alloc.ptr(m_samples_idx);
		std::memcpy(ptr, samples.data(), samples.size() * 32);

		std::tie(m_v4_num_nodes, m_v4_nodes_idx, m_v6_num_nodes, m_v6_nodes_idx)
			= write_nodes(alloc, nodes);
	}

	std::string dht_sample_infohashes_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[200];
		std::snprintf(msg, sizeof(msg)
			, "incoming dht sample_infohashes reply from: %s, samples %d"
			, print_endpoint(endpoint).c_str(), m_num_samples);
		return msg;
#endif
	}

	int dht_sample_infohashes_alert::num_samples() const
	{
		return m_num_samples;
	}

	std::vector<sha256_hash> dht_sample_infohashes_alert::samples() const
	{
		aux::vector<sha256_hash> samples;
		samples.resize(m_num_samples);

		char const* ptr = m_alloc.get().ptr(m_samples_idx);
		std::memcpy(samples.data(), ptr, samples.size() * 32);

		return std::move(samples);
	}

	int dht_sample_infohashes_alert::num_nodes() const
	{
		return m_v4_num_nodes + m_v6_num_nodes;
	}

	std::vector<std::pair<sha256_hash, udp::endpoint>> dht_sample_infohashes_alert::nodes() const
	{
		return read_nodes(m_alloc.get()
			, m_v4_num_nodes, m_v4_nodes_idx
			, m_v6_num_nodes, m_v6_nodes_idx);
	}

	alerts_dropped_alert::alerts_dropped_alert(aux::stack_allocator&
		, std::bitset<abi_alert_count> const& dropped)
		: dropped_alerts(dropped)
	{}

	char const* alert_name(int const alert_type)
	{
		static std::array<char const*, num_alert_types> const names = {{
		"udp_error", "external_ip", "listen_failed",
		"listen_succeeded", "portmap_error", "portmap",
		"portmap_log", "dht_announce", "dht_get_peers", 
		"dht_bootstrap", "session_start_over", "incoming_connection",
		"session_stop_over", "session_stats", "dht_error", 
		"dht_immutable_item", "dht_mutable_item", "dht_put", 
		"dht_outgoing_get_peers", "log", "dht_stats", 
		"dht_log", "dht_pkt", "dht_get_peers_reply", 
		"dht_direct_response", "session_error", "dht_live_nodes",
		"session_stats_header", "dht_sample_infohashes", "alerts_dropped", 
		"socks5", "communication_new_device_id", "communication_new_message",
		"communication_confirmation_root", "communication_syncing_message",
		"communication_friend_info", "communication_log",
		"communication_last_seen", "blockchain_log_alert",
		"blockchain_new_tip_block_alert", "blockchain_new_tail_block_alert",
		"blockchain_new_consensus_point_block_alert","blockchain_rollback_block_alert",
		"blockchain_fork_point_block_alert","blockchain_top_three_votes_alert",
		"blockchain_new_transaction_alert", "blockchain_state_alert",
		"blockchain_syncing_block_alert", "blockchain_syncing_head_block_alert",
		"blockchain_tx_confirmation_alert"
		}};

		TORRENT_ASSERT(alert_type >= 0);
		TORRENT_ASSERT(alert_type < num_alert_types);
		return names[std::size_t(alert_type)];
	}

	std::string alerts_dropped_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		std::string ret = "dropped alerts: ";

		TORRENT_ASSERT(int(dropped_alerts.size()) >= num_alert_types);
		for (int idx = 0; idx < num_alert_types; ++idx)
		{
			if (!dropped_alerts.test(std::size_t(idx))) continue;
			ret += alert_name(idx);
			ret += ' ';
		}

		return ret;
#endif
	}

	socks5_alert::socks5_alert(aux::stack_allocator&
		, tcp::endpoint const& ep, operation_t operation, error_code const& ec)
		: error(ec)
		, op(operation)
		, ip(ep)
	{}

	std::string socks5_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char buf[512];
		std::snprintf(buf, sizeof(buf), "SOCKS5 error. op: %s ec: %s ep: %s"
			, operation_name(op), error.message().c_str(), print_endpoint(ip).c_str());
		return buf;
#endif
	}

    communication_new_device_id_alert::communication_new_device_id_alert(aux::stack_allocator&
            , aux::bytes t)
            : device_id(std::move(t))
    {}

    std::string communication_new_device_id_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        char msg[256];
        std::snprintf(msg, sizeof(msg), "device id %s"
                , aux::toHex(device_id).c_str());
        return msg;
#endif
    }

    communication_new_message_alert::communication_new_message_alert(aux::stack_allocator&
            , communication::message e)
            : msg(std::move(e))
    {}

    std::string communication_new_message_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        char buffer[256];
        std::snprintf(buffer, sizeof(buffer), "new message hash: %s"
                , aux::toHex(msg.sha1().to_string()).c_str());
        return buffer;
#endif
    }

    communication_confirmation_root_alert::communication_confirmation_root_alert(aux::stack_allocator&
            , dht::public_key p, std::vector<sha1_hash> s, std::int64_t t)
            : peer(p), confirmation_roots(std::move(s)), time(t)
    {}

    std::string communication_confirmation_root_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        char msg[256];
        std::snprintf(msg, sizeof(msg), "peer[%s] confirmation root size %zu, time:%" PRId64 "", aux::toHex(peer.bytes).c_str()
                , confirmation_roots.size(), time);
        return msg;
#endif
    }

    communication_syncing_message_alert::communication_syncing_message_alert(aux::stack_allocator&
            , dht::public_key p, sha1_hash s, std::int64_t t)
            : peer(p), syncing_msg_hash(s), time(t)
    {}

    std::string communication_syncing_message_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        char msg[256];
        std::snprintf(msg, sizeof(msg), "peer[%s] sync message hash %s, time:%" PRId64 "", aux::toHex(peer.bytes).c_str()
                , aux::toHex(syncing_msg_hash.to_string()).c_str(), time);

        return msg;
#endif
    }

    communication_friend_info_alert::communication_friend_info_alert(aux::stack_allocator&
            , dht::public_key p, aux::bytes t)
            : peer(p), friend_info(std::move(t))
    {}

    std::string communication_friend_info_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        char msg[1050];
        std::snprintf(msg, sizeof(msg), "peer[%s] friend info %s", aux::toHex(peer.bytes).c_str()
                , aux::toHex(friend_info).c_str());
        return msg;
#endif
    }

    communication_log_alert::communication_log_alert(aux::stack_allocator& alloc, char const* log)
            : m_alloc(alloc)
            , m_str_idx(alloc.copy_string(log))
    {}
    communication_log_alert::communication_log_alert(aux::stack_allocator& alloc, char const* fmt, va_list v)
            : m_alloc(alloc)
            , m_str_idx(alloc.format_string(fmt, v))
    {}

    char const* communication_log_alert::log_message() const
    {
        return m_alloc.get().ptr(m_str_idx);
    }

#if TORRENT_ABI_VERSION == 1
    char const* communication_log_alert::msg() const
    {
        return log_message();
    }
#endif

    std::string communication_log_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return log_message();
#endif
    }

    communication_last_seen_alert::communication_last_seen_alert(aux::stack_allocator&
            , dht::public_key p, int64_t t)
            : peer(p), last_seen(t)
    {}

    std::string communication_last_seen_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        char msg[256];
        std::snprintf(msg, sizeof(msg), "peer[%s] last seen time %" PRId64 "", aux::toHex(peer.bytes).c_str(), last_seen);
        return msg;
#endif
    }

	blockchain_log_alert::blockchain_log_alert(aux::stack_allocator& alloc, char const* log)
			: m_alloc(alloc)
			, m_str_idx(alloc.copy_string(log))
	{}
	blockchain_log_alert::blockchain_log_alert(aux::stack_allocator& alloc, char const* fmt, va_list v)
			: m_alloc(alloc)
			, m_str_idx(alloc.format_string(fmt, v))
	{}

	char const* blockchain_log_alert::log_message() const
	{
		return m_alloc.get().ptr(m_str_idx);
	}

#if TORRENT_ABI_VERSION == 1
	char const* blockchain_log_alert::msg() const
	{
		return log_message();
	}
#endif

	std::string blockchain_log_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		return log_message();
#endif
	}

	blockchain_new_head_block_alert::blockchain_new_head_block_alert(aux::stack_allocator&
			, blockchain::block blk)
			: blk(std::move(blk))
	{}

	std::string blockchain_new_head_block_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		return "new head block:" + blk.to_string();
#endif
	}

	blockchain_new_tail_block_alert::blockchain_new_tail_block_alert(aux::stack_allocator&
			, blockchain::block blk)
			: blk(std::move(blk))
	{}

	std::string blockchain_new_tail_block_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
        return "new tail block:" + blk.to_string();
#endif
	}

    blockchain_new_consensus_point_block_alert::blockchain_new_consensus_point_block_alert(aux::stack_allocator&
            , blockchain::block blk)
            : blk(std::move(blk))
    {}

    std::string blockchain_new_consensus_point_block_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return "new consensus point block:" + blk.to_string();
#endif
    }

	blockchain_rollback_block_alert::blockchain_rollback_block_alert(aux::stack_allocator&
			, blockchain::block blk)
			: blk(std::move(blk))
	{}

	std::string blockchain_rollback_block_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
        return "rollback block:" + blk.to_string();
#endif
	}

	blockchain_fork_point_block_alert::blockchain_fork_point_block_alert(aux::stack_allocator&
			, blockchain::block blk)
			: blk(std::move(blk))
	{}

	std::string blockchain_fork_point_block_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
        return "fork point block:" + blk.to_string();
#endif
	}

	blockchain_top_three_votes_alert::blockchain_top_three_votes_alert(aux::stack_allocator&
			, aux::bytes id, std::vector<blockchain::vote> vs)
			: chain_id(std::move(id)), votes(std::move(vs))
	{}

	std::string blockchain_top_three_votes_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char msg[256];
		std::snprintf(msg, sizeof(msg), "chain[%s] votes size %zu", aux::toHex(chain_id).c_str(), votes.size());
		return msg;
#endif
	}

    blockchain_new_transaction_alert::blockchain_new_transaction_alert(aux::stack_allocator&
			, blockchain::transaction t)
			: tx(std::move(t))
	{}

	std::string blockchain_new_transaction_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char buffer[256];
		std::snprintf(buffer, sizeof(buffer), "new tx hash: %s"
				, aux::toHex(tx.sha1().to_string()).c_str());
		return buffer;
#endif
	}

    blockchain_state_alert::blockchain_state_alert(aux::stack_allocator&
            , aux::bytes id, blockchain::account t)
            : chain_id(std::move(id)), act(t)
    {}

    std::string blockchain_state_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return "Alert: chain:" + aux::toHex(chain_id) + " post state:" + act.to_string();
#endif
    }

    blockchain_syncing_block_alert::blockchain_syncing_block_alert(aux::stack_allocator&
            , dht::public_key p, blockchain::block blk)
            : peer(p), blk(std::move(blk))
    {}

    std::string blockchain_syncing_block_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return "Alert: peer:" + aux::toHex(peer.bytes) + " syncing block:" + blk.to_string();
#endif
    }

    blockchain_syncing_head_block_alert::blockchain_syncing_head_block_alert(aux::stack_allocator&
            , dht::public_key p, blockchain::block blk)
            : peer(p), blk(std::move(blk))
    {}

    std::string blockchain_syncing_head_block_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return "Alert: peer:" + aux::toHex(peer.bytes) + " syncing head block:" + blk.to_string();
#endif
    }

    blockchain_tx_confirmation_alert::blockchain_tx_confirmation_alert(aux::stack_allocator&
            , aux::bytes id, dht::public_key p, sha1_hash h)
            : chain_id(std::move(id)), peer(p), hash(h)
    {}



    std::string blockchain_tx_confirmation_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return "Alert: chain:" + aux::toHex(chain_id) + " peer:" + aux::toHex(peer.bytes) + " tx confirmation hash:" + aux::toHex(hash.to_string());
#endif
    }

	referred_status_alert::referred_status_alert(aux::stack_allocator&
		, address const& ip, int port)
		: external_address(ip), external_port(port)
	{}

	std::string referred_status_alert::message() const
	{
#ifdef TORRENT_DISABLE_ALERT_MSG
		return {};
#else
		char ret[200];
		std::snprintf(ret, sizeof(ret), "libTAU successfully referred on %s"
			, print_endpoint(external_address, external_port).c_str());
		return ret;
#endif
	}

    communication_message_arrived_alert::communication_message_arrived_alert(aux::stack_allocator&
            , dht::public_key p, sha1_hash s, std::int64_t t)
            : peer(p), msg_arrived_hash(s), time(t)
    {}

    std::string communication_message_arrived_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        char msg[256];
        std::snprintf(msg, sizeof(msg), "peer[%s] arrived message hash %s, time:%" PRId64 "", aux::toHex(peer.bytes).c_str()
                , aux::toHex(msg_arrived_hash.to_string()).c_str(), time);

        return msg;
#endif
    }

    blockchain_tx_sent_alert::blockchain_tx_sent_alert(aux::stack_allocator&
            , dht::public_key p, sha1_hash s, std::int64_t t)
            : peer(p), tx_sent_hash(s), time(t)
    {}

    std::string blockchain_tx_sent_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        char msg[256];
        std::snprintf(msg, sizeof(msg), "peer[%s] sent tx hash %s, time:%" PRId64 "", aux::toHex(peer.bytes).c_str()
                , aux::toHex(tx_sent_hash.to_string()).c_str(), time);

        return msg;
#endif
    }

    blockchain_tx_arrived_alert::blockchain_tx_arrived_alert(aux::stack_allocator&
            , aux::bytes id, sha1_hash s, std::int64_t t)
            : chain_id(std::move(id)), tx_arrived_hash(s), time(t)
    {}

    std::string blockchain_tx_arrived_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        char msg[256];
        std::snprintf(msg, sizeof(msg), "ALERT: chain[%s] arrived tx hash %s, time:%" PRId64 "",
                      aux::toHex(chain_id).c_str(), aux::toHex(tx_arrived_hash.to_string()).c_str(), time);

        return msg;
#endif
    }

    communication_user_info_alert::communication_user_info_alert(aux::stack_allocator&
            , dht::public_key p, aux::bytes k, aux::bytes v)
            : peer(p), key(std::move(k)), user_info(std::move(v))
    {}

    std::string communication_user_info_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return "Alert: peer:" + aux::toHex(peer.bytes) + " key: " + aux::toHex(key) + " user info: " + aux::toHex(user_info);
#endif
    }

    communication_user_event_alert::communication_user_event_alert(aux::stack_allocator&
            , dht::public_key p, aux::bytes t)
            : peer(p), user_event(std::move(t))
    {}

    std::string communication_user_event_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return "Alert: peer:" + aux::toHex(peer.bytes) + " user event: " + aux::toHex(user_event);
#endif
    }

    blockchain_state_array_alert::blockchain_state_array_alert(aux::stack_allocator&
            , aux::bytes id, std::vector<libTAU::blockchain::account> acts)
            : chain_id(std::move(id)), accounts(std::move(acts))
    {}

    std::string blockchain_state_array_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return "Alert: chain:" + aux::toHex(chain_id) + " post state array";
#endif
    }

    blockchain_fail_to_get_chain_data_alert::blockchain_fail_to_get_chain_data_alert(aux::stack_allocator&
            , aux::bytes id)
            : chain_id(std::move(id))
    {}

    std::string blockchain_fail_to_get_chain_data_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return "Alert: chain:" + aux::toHex(chain_id) + " fail to get chain data";
#endif
    }

    blockchain_online_peer_alert::blockchain_online_peer_alert(aux::stack_allocator&
            , aux::bytes id, dht::public_key p, std::int64_t t)
            : chain_id(std::move(id)), peer(p), time(t)
    {}

    std::string blockchain_online_peer_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        char msg[256];
        std::snprintf(msg, sizeof(msg), "chain[%s] online peer[%s] time:%" PRId64 "",
                      aux::toHex(chain_id).c_str(), aux::toHex(peer.bytes).c_str(), time);

        return msg;
#endif
    }

    communication_peer_attention_alert::communication_peer_attention_alert(aux::stack_allocator&
            , dht::public_key p, std::int64_t t): peer(p), time(t)
    {}

    std::string communication_peer_attention_alert::message() const
    {
#ifdef TORRENT_DISABLE_ALERT_MSG
        return {};
#else
        return "Alert: attention peer:" + aux::toHex(peer.bytes);
#endif
    }


} // namespace libTAU
