/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BOOTSTRAP_NODES_LEARNER_HPP
#define LIBTAU_BOOTSTRAP_NODES_LEARNER_HPP

#include <libTAU/socket.hpp>
#include <libTAU/time.hpp>

#include <libTAU/kademlia/node_id.hpp>
#include <libTAU/kademlia/bs_nodes_storage.hpp>

namespace libTAU {
struct entry;
namespace aux {
	struct session_settings;
}
}

namespace libTAU {
namespace dht {

struct settings;
struct dht_logger;

class routing_table;

class TORRENT_EXTRA_EXPORT bs_nodes_learner
{
public:

	bs_nodes_learner(node_id const& our_id
		, aux::session_settings const& settings
		, routing_table& table
		, bs_nodes_storage_interface& bs_nodes_storage
		, dht_logger* log);

	void get_bootstrap_nodes(std::vector<bs_node_entry>& nodes, int count = 4);

	void add_bootstrap_nodes(std::vector<bs_node_entry> const& nodes);

	void tick();

private:

#ifndef TORRENT_DISABLE_LOGGING
	dht_logger* m_log;
#endif

	aux::session_settings const& m_settings;
	routing_table& m_table;
	node_id m_our_id;
	bs_nodes_storage_interface& m_bs_nodes_storage;

	// bootstrap nodes storage size
	std::size_t m_storage_size = 0;

	// bootstrap nodes storage iterator
	std::size_t m_storage_iterator = 0;

	time_point m_last_refresh;
};

} // namespace dht
} // namespace libTAU

#endif // LIBTAU_BOOTSTRAP_NODES_LEARNER_HPP
