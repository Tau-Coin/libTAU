/*

Copyright (c) 2006, Daniel Wallin
Copyright (c) 2013, 2017-2020, Arvid Norberg
Copyright (c) 2016, Pavel Pimenov
Copyright (c) 2016, 2018, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTORRENT_GET_PEERS_HPP
#define LIBTORRENT_GET_PEERS_HPP

#include <libTAU/kademlia/find_data.hpp>

namespace libTAU {
namespace dht {

struct get_peers : find_data
{
	using data_callback = std::function<void(std::vector<tcp::endpoint> const&)>;

	void got_peers(std::vector<tcp::endpoint> const& peers);

	get_peers(node& dht_node, node_id const& target
		, data_callback dcallback
		, nodes_callback ncallback
		, bool noseeds);

	char const* name() const override;

protected:
	bool invoke(observer_ptr o) override;
	observer_ptr new_observer(udp::endpoint const& ep
		, node_id const& id) override;

	data_callback m_data_callback;
	bool m_noseeds;
};

struct get_peers_observer : find_data_observer
{
	get_peers_observer(
		std::shared_ptr<traversal_algorithm> algorithm
		, udp::endpoint const& ep, node_id const& id)
		: find_data_observer(std::move(algorithm), ep, id)
	{}

	void reply(msg const&, node_id const&) override;
#ifndef TORRENT_DISABLE_LOGGING
private:
	void log_peers(msg const& m, bdecode_node const& r, int size, node_id const& from) const;
#endif
};

} // namespace dht
} // namespace libTAU

#endif // LIBTORRENT_GET_PEERS_HPP
