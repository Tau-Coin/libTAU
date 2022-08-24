/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BOOTSTRAP_NODES_STORAGE_HPP
#define LIBTAU_BOOTSTRAP_NODES_STORAGE_HPP

#include <functional>

#include <libTAU/kademlia/dht_observer.hpp>
#include <libTAU/kademlia/node_id.hpp>
#include <libTAU/kademlia/types.hpp>
#include <libTAU/kademlia/node_entry.hpp>

#include <libTAU/aux_/common.h> // for utcTime()

#include <libTAU/socket.hpp>
#include <libTAU/address.hpp>
#include <libTAU/span.hpp>
#include <libTAU/string_view.hpp>

namespace libTAU {
namespace dht {

	// This structure hold the basic info of bootstrap node
	struct TORRENT_EXPORT bs_node_entry
	{
		bs_node_entry(node_id const& nid, udp::endpoint const& ep)
		{
			m_nid = nid;
			m_ep = ep;
			m_ts.value = libTAU::aux::utcTime();
		}

		bs_node_entry(node_id const& nid, udp::endpoint const& ep, timestamp const& ts)
		{
			m_nid = nid;
			m_ep = ep;
			m_ts = ts;
		}

		// bootstrap node id
		node_id m_nid;

		// ip + port
		udp::endpoint m_ep;

		// sampling timestamp
		timestamp m_ts;
	};

	struct TORRENT_EXPORT bs_nodes_storage_interface
	{
		// Store bootstrap nodes
		virtual bool put(std::vector<bs_node_entry> const& nodes) = 0;

		// Get bootstrap by timestamp priority.
		virtual bool get(std::vector<bs_node_entry>& nodes
			, int offset, int count) const = 0;

		virtual std::size_t size() = 0;

		// This function is called periodically (non-constant frequency).
		//
		// For implementers:
		// Use this functions for expire bootstrap nodes or any other
		// storage cleanup.
		virtual std::size_t tick() = 0;

		// close storage
		virtual void close() = 0;

		// hidden
		virtual ~bs_nodes_storage_interface() {}
	};

} // namespace dht
} // namespace libTAU

#endif //LIBTAU_BOOTSTRAP_NODES_STORAGE_HPP
