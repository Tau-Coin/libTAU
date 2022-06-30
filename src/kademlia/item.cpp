/*

Copyright (c) 2013-2020, Arvid Norberg
Copyright (c) 2015-2016, Steven Siloti
Copyright (c) 2016-2017, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <libTAU/hasher.hpp>
#include <libTAU/kademlia/item.hpp>
#include <libTAU/bencode.hpp>
#include <libTAU/kademlia/ed25519.hpp>
#include <libTAU/aux_/numeric_cast.hpp>

#include <cstdio> // for snprintf
#include <cinttypes> // for PRId64 et.al.
#include <algorithm> // for copy

#if TORRENT_USE_ASSERTS
#include "libTAU/bdecode.hpp"
#endif

namespace libTAU { namespace dht {

namespace {

	int canonical_string(span<char const> v
		, timestamp const ts
		, span<char const> salt
		, span<char> out)
	{
		// v must be valid bencoding!
#if TORRENT_USE_ASSERTS
		bdecode_node e;
		error_code ec;
		TORRENT_ASSERT(bdecode(v.data(), v.data() + v.size(), e, ec) == 0);
#endif
		char* ptr = out.data();

		auto left = out.size() - (ptr - out.data());
		if (!salt.empty())
		{
			ptr += std::snprintf(ptr, static_cast<std::size_t>(left), "4:salt%d:", int(salt.size()));
			left = out.size() - (ptr - out.data());
			std::copy(salt.begin(), salt.begin() + std::min(salt.size(), left), ptr);
			ptr += std::min(salt.size(), left);
			left = out.size() - (ptr - out.data());
		}
		ptr += std::snprintf(ptr, static_cast<std::size_t>(left), "3:tsi%" PRId64 "e1:v", ts.value);
		left = out.size() - (ptr - out.data());
		std::copy(v.begin(), v.begin() + std::min(v.size(), left), ptr);
		ptr += std::min(v.size(), left);
		TORRENT_ASSERT((ptr - out.data()) <= int(out.size()));
		return int(ptr - out.data());
	}
}

// calculate the target hash for an immutable item.
sha256_hash item_target_id(span<char const> v)
{
	return hasher256(v).final();
}

// calculate the target hash for a mutable item.
sha256_hash item_target_id(span<char const> salt
	, public_key const& pk)
{
	/*
	hasher256 h(pk.bytes);
	if (!salt.empty()) h.update(salt);
	return h.final();
	 */

	// libtau concatenate salt and public key as mutable item target.
	// <mutable item target> = concat<first 128 bits of sender(public key),
	//		first 128 bits of receiver(salt)>
	sha256_hash target;

	// copy first 96 bits(12 bytes) of sender (public key)
	std::memcpy(&target[0], pk.bytes.begin(), 12);

	// copy first 160 bits(20 bytes) of receiver(salt)
	if (salt.size() > 0)
	{
		if (salt.size() >= 20)
		{
			std::memcpy(&target[12], salt.data(), 20);
		}
		else
		{
			std::memcpy(&target[12], salt.data(), salt.size());
		}
	}

	return target;
}

// calculate the target hash for a mutable item.
sha256_hash item_target_id(public_key const& pk)
{
	sha256_hash target;
	std::memcpy(&target[0], pk.bytes.begin(), 32);

	return target;
}

bool verify_mutable_item(
	span<char const> v
	, span<char const> salt
	, timestamp const ts
	, public_key const& pk
	, signature const& sig)
{
	char str[1200];
	int len = canonical_string(v, ts, salt, str);

	return ed25519_verify(sig, {str, len}, pk);
}

// given the bencoded buffer ``v``, the salt (which is optional and may have
// a length of zero to be omitted), timestamp ``ts``, public key (32
// bytes ed25519 key) ``pk`` and a secret/private key ``sk`` (64 bytes ed25519
// key) a signature ``sig`` is produced. The ``sig`` pointer must point to
// at least 64 bytes of available space. This space is where the signature is
// written.
signature sign_mutable_item(
	span<char const> v
	, span<char const> salt
	, timestamp const ts
	, public_key const& pk
	, secret_key const& sk)
{
	char str[1200];
	int const len = canonical_string(v, ts, salt, str);

	return ed25519_sign({str, len}, pk, sk);
}

item::item(public_key const& pk, span<char const> salt)
	: m_salt(salt.data(), static_cast<std::size_t>(salt.size()))
	, m_pk(pk)
	, m_mutable(true)
{}

item::item(entry v)
	: m_value(std::move(v))
{}

item::item(bdecode_node const& v)
{
	// TODO: implement ctor for entry from bdecode_node?
	m_value = v;
}

item::item(entry v, span<char const> salt
	, timestamp const ts, public_key const& pk, secret_key const& sk)
{
	assign(std::move(v), salt, ts, pk, sk);
}

void item::assign(entry v)
{
	m_mutable = false;
	m_value = std::move(v);
}

void item::assign(entry v, span<char const> salt
	, timestamp const ts, public_key const& pk, secret_key const& sk)
{
	std::array<char, 1000> buffer;
	int const bsize = bencode(buffer.begin(), v);
	TORRENT_ASSERT(bsize <= 1000);
	m_sig = sign_mutable_item(span<char const>(buffer).first(bsize)
		, salt, ts, pk, sk);
	m_salt.assign(salt.data(), static_cast<std::size_t>(salt.size()));
	m_pk = pk;
	m_timestamp = ts;
	m_mutable = true;
	m_value = std::move(v);
}

void item::assign(bdecode_node const& v)
{
	m_mutable = false;
	m_value = v;
}

bool item::assign(bdecode_node const& v, span<char const> salt
	, timestamp const ts, public_key const& pk, signature const& sig)
{
	TORRENT_ASSERT(v.data_section().size() <= 1000);
	if (!verify_mutable_item(v.data_section(), salt, ts, pk, sig))
		return false;
	m_pk = pk;
	m_sig = sig;
	if (!salt.empty())
		m_salt.assign(salt.data(), static_cast<std::size_t>(salt.size()));
	else
		m_salt.clear();
	m_timestamp = ts;
	m_mutable = true;

	m_value = v;
	return true;
}

void item::assign(entry v, span<char const> salt
	, timestamp const ts
	, public_key const& pk, signature const& sig)
{

	m_pk = pk;
	m_sig = sig;
	m_salt.assign(salt.data(), static_cast<std::size_t>(salt.size()));
	m_timestamp = ts;
	m_mutable = true;
	m_value = std::move(v);
}

} } // namespace libTAU::dht
