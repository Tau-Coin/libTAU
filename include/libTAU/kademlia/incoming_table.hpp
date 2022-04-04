/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_DHT_INCOMING_TABLE_HPP
#define TORRENT_DHT_INCOMING_TABLE_HPP

#include <algorithm>
#include <map>

#include <libTAU/kademlia/routing_table.hpp>
#include <libTAU/kademlia/node_entry.hpp>
#include <libTAU/kademlia/node_id.hpp>
#include <libTAU/kademlia/dht_observer.hpp>

#include "libTAU/time.hpp"
#include "libTAU/aux_/time.hpp" // for time_now

namespace libTAU {

namespace aux {
	struct session_settings;
}

namespace dht {

struct settings;
struct dht_logger;

class TORRENT_EXTRA_EXPORT incoming_table
{

public:

	incoming_table(node_id const& id, udp proto
		, aux::session_settings const& settings
		, routing_table& table
		, dht_logger* log);

	incoming_table(incoming_table const&) = delete;
	incoming_table& operator=(incoming_table const&) = delete;

	bool incoming_endpoint(node_id const& id, udp::endpoint const& ep, bool non_referrable);

    // this function is called every time the node sees
    // a sign of a node being alive. This node will either
    // be inserted into incoming table or routing table
	bool node_seen(node_id const& id, udp::endpoint const& ep, int rtt, bool non_referrable);

	// return a pointer the node_entry with the given node id.
	node_entry* find_node(node_id const& nid);

	void tick();

	void update_node_id(node_id const& id) { m_id = id; }

	int size() const { return m_nr_table.size(); }

private:

	bool add_node(node_id const& id, udp::endpoint const& ep);

	void remove_node(node_id const& id);

	int endpoint_max_count() const;

	int refresh_time() const;

	int endpoint_lifetime() const;

#ifndef TORRENT_DISABLE_LOGGING
	dht_logger* m_log;
#endif
	aux::session_settings const& m_settings;
	routing_table& m_table;
	node_id m_id;

	// non-referrable table
	std::map<node_id, node_entry> m_nr_table;

	udp m_protocol; // protocol this table is for

	time_point m_last_refresh;
};

} // namespace dht
} // namespace libTAU

#endif // TORRENT_DHT_INCOMING_TABLE_HPP
