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

#include <vector>

namespace libTAU {
namespace dht {

struct msg;
class node;

struct relay: traversal_algorithm
{
	using completed_callback = std::function<void(entry const&, int)>;

	relay(node& node, node_id const& to, completed_callback callback);

	char const* name() const override;
	void start() override;

	void set_payload(entry payload) { m_payload = std::move(payload); }

	void add_relays_nodes(std::vector<node_entry> const& nodes);

protected:

	void done() override;
	bool invoke(observer_ptr o) override;

	observer_ptr new_observer(udp::endpoint const& ep
		, node_id const& id) override;

	completed_callback m_completed_callback;
	entry m_payload;
	node_id m_to;
	std::vector<node_entry> m_relay_nodes;
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

	void reply(msg const&) override;
};

} // namespace dht
} // namespace libTAU

#endif // TORRENT_DHT_RELAY_HPP
