/*

Copyright (c) 2015, Thomas Yuan
Copyright (c) 2016-2020, Arvid Norberg
Copyright (c) 2016, 2018, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_PUT_DATA_HPP
#define TORRENT_PUT_DATA_HPP

#include <libTAU/kademlia/traversal_algorithm.hpp>
#include <libTAU/kademlia/node_id.hpp>
#include <libTAU/kademlia/observer.hpp>
#include <libTAU/kademlia/item.hpp>

#include <vector>

namespace libTAU {
namespace dht {

struct msg;
class node;

struct put_data: traversal_algorithm
{
	using put_callback = std::function<void(item const&, int)>;
	using nodes_callback = std::function<void(std::vector<std::pair<node_entry, bool>> const&)>;

	put_data(node& node, node_id const& target
		, public_key const& to
		, put_callback callback
		, nodes_callback ncallback = nodes_callback());

	char const* name() const override;
	void start() override;
	bool is_done() const override;

	void set_data(item&& data) { m_data = std::move(data); }
	void set_data(item const& data) = delete;

	void set_cache(bool cache) { m_cache = cache; }

	void set_hit_limit(int hit_limit) { m_hit_limit = hit_limit; };

	void on_put_success(node_id const& nid, udp::endpoint const& ep, bool hit);

protected:

	void done() override;
	bool invoke(observer_ptr o) override;

	observer_ptr new_observer(udp::endpoint const& ep
		, node_id const& id) override;

	put_callback m_put_callback;
	nodes_callback m_nodes_callback;
	std::vector<std::pair<node_entry, bool>> m_success_nodes;
	item m_data;
	public_key m_to;
	bool m_cache = true;
	int m_hits = 0;
	int m_hit_limit = 0;
	bool m_done = false;
};

struct put_data_observer : traversal_observer
{
	put_data_observer(
		std::shared_ptr<traversal_algorithm> algorithm
		, udp::endpoint const& ep, node_id const& id)
		: traversal_observer(std::move(algorithm), ep, id)
	{
	}

	void reply(msg const&, node_id const&) override;
};

} // namespace dht
} // namespace libTAU

#endif // TORRENT_PUT_DATA_HPP
