/*

Copyright (c) 2013, Steven Siloti
Copyright (c) 2013-2020, Arvid Norberg
Copyright (c) 2015, Thomas Yuan
Copyright (c) 2016, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTORRENT_GET_ITEM_HPP
#define LIBTORRENT_GET_ITEM_HPP

#include <libTAU/kademlia/find_data.hpp>
#include <libTAU/kademlia/item.hpp>

#include <memory>

namespace libTAU {
namespace dht {

class get_item : public find_data
{
public:

	// when getting enough items satisfied with the specified timestamp,
	// done this traversal algorithm.
	static constexpr int got_items_max_count = 1;

	using data_callback = std::function<void(item const&, bool)>;

	void got_data(bdecode_node const& v,
		public_key const& pk,
		timestamp ts,
		signature const& sig);

	// for immutable items
	get_item(node& dht_node
		, node_id const& target
		, data_callback dcallback
		, nodes_callback ncallback);

	// for mutable items
	get_item(node& dht_node
		, public_key const& pk
		, span<char const> salt
		, data_callback dcallback
		, nodes_callback ncallback);

	char const* name() const override;

	virtual void start();

	bool is_done() const override;

	void set_timestamp(std::int64_t timestamp) { m_timestamp = timestamp; }

protected:
	observer_ptr new_observer(udp::endpoint const& ep
		, node_id const& id) override;
	bool invoke(observer_ptr o) override;
	void done() override;

	data_callback m_data_callback;
	item m_data;
	bool m_immutable;
	public_key m_pk;

	std::int64_t m_timestamp = -1;
	int m_got_items_count = 0;
};

class get_item_observer : public find_data_observer
{
public:
	get_item_observer(
		std::shared_ptr<traversal_algorithm> algorithm
		, udp::endpoint const& ep, node_id const& id)
		: find_data_observer(std::move(algorithm), ep, id)
	{}

	void reply(msg const&, node_id const&) override;
};

} // namespace dht
} // namespace libTAU

#endif // LIBTORRENT_GET_ITEM_HPP
