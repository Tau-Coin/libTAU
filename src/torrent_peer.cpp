/*

Copyright (c) 2014-2017, 2019-2020, Arvid Norberg
Copyright (c) 2016-2017, 2020-2021, Alden Torres
Copyright (c) 2018, Steven Siloti
Copyright (c) 2020, Paul-Louis Ageneau
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/aux_/torrent_peer.hpp"
#include "libTAU/assert.hpp"
#include "libTAU/aux_/string_util.hpp"
#include "libTAU/aux_/crc32c.hpp"
#include "libTAU/aux_/ip_voter.hpp"
#include "libTAU/aux_/io_bytes.hpp" // for write_uint16
#include "libTAU/aux_/ip_helpers.hpp"

namespace libTAU::aux {

	namespace {

		void apply_mask(std::uint8_t* b, std::uint8_t const* mask, int size)
		{
			for (int i = 0; i < size; ++i)
			{
				*b &= *mask;
				++b;
				++mask;
			}
		}
	}

	// 1. if the IP addresses are identical, hash the ports in 16 bit network-order
	//    binary representation, ordered lowest first.
	// 2. if the IPs are in the same /24, hash the IPs ordered, lowest first.
	// 3. if the IPs are in the ame /16, mask the IPs by 0xffffff55, hash them
	//    ordered, lowest first.
	// 4. if IPs are not in the same /16, mask the IPs by 0xffff5555, hash them
	//    ordered, lowest first.
	//
	// * for IPv6 peers, just use the first 64 bits and widen the masks.
	//   like this: 0xffff5555 -> 0xffffffff55555555
	//   the lower 64 bits are always unmasked
	//
	// * for IPv6 addresses, compare /32 and /48 instead of /16 and /24
	//
	// * the two IP addresses that are used to calculate the rank must
	//   always be of the same address family
	//
	// * all IP addresses are in network byte order when hashed
	std::uint32_t peer_priority(tcp::endpoint e1, tcp::endpoint e2)
	{
		TORRENT_ASSERT(aux::is_v4(e1) == aux::is_v4(e2));

		using std::swap;

		std::uint32_t ret;
		if (e1.address() == e2.address())
		{
			if (e1.port() > e2.port())
				swap(e1, e2);
			std::uint32_t p;
			auto* ptr = reinterpret_cast<char*>(&p);
			aux::write_uint16(e1.port(), ptr);
			aux::write_uint16(e2.port(), ptr);
			ret = aux::crc32c_32(p);
		}
		else if (aux::is_v6(e1))
		{
			static const std::uint8_t v6mask[][8] = {
				{ 0xff, 0xff, 0xff, 0xff, 0x55, 0x55, 0x55, 0x55 },
				{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x55, 0x55 },
				{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
			};

			if (e1 > e2) swap(e1, e2);
			address_v6::bytes_type b1 = e1.address().to_v6().to_bytes();
			address_v6::bytes_type b2 = e2.address().to_v6().to_bytes();
			int const mask = std::memcmp(b1.data(), b2.data(), 4) ? 0
				: std::memcmp(b1.data(), b2.data(), 6) ? 1 : 2;
			apply_mask(b1.data(), v6mask[mask], 8);
			apply_mask(b2.data(), v6mask[mask], 8);
			std::uint64_t addrbuf[4];
			std::memcpy(&addrbuf[0], b1.data(), 16);
			std::memcpy(&addrbuf[2], b2.data(), 16);
			ret = aux::crc32c(addrbuf, 4);
		}
		else
		{
			static const std::uint8_t v4mask[][4] = {
				{ 0xff, 0xff, 0x55, 0x55 },
				{ 0xff, 0xff, 0xff, 0x55 },
				{ 0xff, 0xff, 0xff, 0xff }
			};

			if (e1 > e2) swap(e1, e2);
			address_v4::bytes_type b1 = e1.address().to_v4().to_bytes();
			address_v4::bytes_type b2 = e2.address().to_v4().to_bytes();
			int mask = std::memcmp(&b1[0], &b2[0], 2) ? 0
				: std::memcmp(&b1[0], &b2[0], 3) ? 1 : 2;
			apply_mask(&b1[0], v4mask[mask], 4);
			apply_mask(&b2[0], v4mask[mask], 4);
			std::uint64_t addrbuf;
			std::memcpy(&addrbuf, &b1[0], 4);
			std::memcpy(reinterpret_cast<char*>(&addrbuf) + 4, &b2[0], 4);
			ret = aux::crc32c(&addrbuf, 1);
		}

		return ret;
	}

	torrent_peer::torrent_peer(std::uint16_t port_, bool conn
		, peer_source_flags_t const src)
		: connection(nullptr)
		, port(port_)
		, failcount(0)
		, connectable(conn)
		, optimistically_unchoked(false)
		, seed(false)
		, maybe_upload_only(false)
		, fast_reconnects(0)
		, trust_points(0)
		, source(static_cast<std::uint8_t>(src))
#if !defined TORRENT_DISABLE_ENCRYPTION
		// assume no support in order to
		// prefer opening non-encrypted
		// connections. If it fails, we'll
		// retry with encryption
		, pe_support(false)
#endif
		, is_v6_addr(false)
		, on_parole(false)
		, banned(false)
		, supports_utp(true) // assume peers support utp
		, confirmed_supports_utp(false)
		, supports_holepunch(false)
		, web_seed(false)
		, protocol_v2(false)
	{}

	std::uint32_t torrent_peer::rank(aux::external_ip const& external, int external_port) const
	{
		TORRENT_ASSERT(in_use);
		//TODO: how do we deal with our external address changing?
		if (peer_rank == 0)
			peer_rank = peer_priority(
				tcp::endpoint(external.external_address(this->address()), std::uint16_t(external_port))
				, tcp::endpoint(this->address(), this->port));
		return peer_rank;
	}

#ifndef TORRENT_DISABLE_LOGGING
	std::string torrent_peer::to_string() const
	{
		TORRENT_ASSERT(in_use);
		return address().to_string();
	}
#endif

	std::int64_t torrent_peer::total_download() const
	{
		return 1024;
	}

	std::int64_t torrent_peer::total_upload() const
	{
		return 1024;
	}

	ipv4_peer::ipv4_peer(tcp::endpoint const& ep, bool c
		, peer_source_flags_t const src)
		: torrent_peer(ep.port(), c, src)
		, addr(ep.address().to_v4())
	{
		is_v6_addr = false;
	}

	ipv4_peer::ipv4_peer(ipv4_peer const&) = default;
	ipv4_peer& ipv4_peer::operator=(ipv4_peer const& p) & = default;

	ipv6_peer::ipv6_peer(tcp::endpoint const& ep, bool c
		, peer_source_flags_t const src)
		: torrent_peer(ep.port(), c, src)
		, addr(ep.address().to_v6().to_bytes())
	{
		is_v6_addr = true;
	}

	ipv6_peer::ipv6_peer(ipv6_peer const&) = default;

	libTAU::address torrent_peer::address() const
	{
		if (is_v6_addr)
			return libTAU::address_v6(
				static_cast<ipv6_peer const*>(this)->addr);
		else
			return static_cast<ipv4_peer const*>(this)->addr;
	}

}
