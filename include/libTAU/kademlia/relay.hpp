/*

Copyright (c) 2015, Thomas Yuan
Copyright (c) 2016-2020, Arvid Norberg
Copyright (c) 2016, 2018, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_DHT_RELAY_HPP
#define TORRENT_DHT_RELAY_HPP

#include <libTAU/kademlia/traversal_algorithm.hpp>
#include <libTAU/kademlia/node_entry.hpp>
#include <libTAU/kademlia/node_id.hpp>
#include <libTAU/kademlia/observer.hpp>
#include <libTAU/kademlia/item.hpp>

#include <libTAU/sha1_hash.hpp>
#include <libTAU/span.hpp>

#include <vector>

namespace libTAU {
namespace dht {

struct msg;
class node;

struct relay_hmac
{
	relay_hmac() = default;
	explicit relay_hmac(char const* b)
	{ std::copy(b, b + len, bytes.begin()); }

	bool operator==(relay_hmac const& rhs) const
	{ return bytes == rhs.bytes; }

	static constexpr int len = 4;
	std::array<char, len> bytes;
};

TORRENT_EXTRA_EXPORT relay_hmac gen_relay_hmac(span<char const> payload
		, span<char const> aux_nodes);

TORRENT_EXTRA_EXPORT bool verify_relay_hmac(relay_hmac const& hmac
		, span<char const> payload
		, span<char const> aux_nodes);

struct relay: traversal_algorithm
{
	using completed_callback
		= std::function<void(entry const&, std::vector<std::pair<node_entry, bool>> const&)>;

	relay(node& node
		, node_id const& to
		, entry payload
		, entry aux_nodes
		, relay_hmac const& hmac
		, completed_callback callback);

	char const* name() const override;
	void start() override;
	bool is_done() const override;

	void set_hit_limit(int hit_limit) { m_hit_limit = hit_limit; }

	void on_put_success(node_id const& nid, udp::endpoint const& ep, bool hit);

	std::string& encrypted_payload() { return m_encrypted_payload; }

protected:

	void done() override;
	bool invoke(observer_ptr o) override;

	observer_ptr new_observer(udp::endpoint const& ep
		, node_id const& id) override;

	completed_callback m_completed_callback;
	std::vector<std::pair<node_entry, bool>> m_success_nodes;

	entry m_payload;
	std::string m_encrypted_payload;
	node_id m_to;
	entry m_aux_nodes;
	relay_hmac m_hmac;

	int m_hits = 0;
	int m_hit_limit = 0;
	bool m_done = false;
};

struct relay_observer : traversal_observer
{
	relay_observer(
		std::shared_ptr<traversal_algorithm> algorithm
		, udp::endpoint const& ep, node_id const& id)
		: traversal_observer(std::move(algorithm), ep, id)
	{
	}

	void reply(msg const&, node_id const&) override;
};

} // namespace dht
} // namespace libTAU

#endif // TORRENT_DHT_RELAY_HPP
