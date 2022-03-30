/*

Copyright (c) 2006-2017, 2019-2020, Arvid Norberg
Copyright (c) 2015, Thomas Yuan
Copyright (c) 2016-2017, Steven Siloti
Copyright (c) 2016, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef RPC_MANAGER_HPP
#define RPC_MANAGER_HPP

#include <unordered_map>
#include <cstdint>

#include <libTAU/socket.hpp>
#include <libTAU/time.hpp>
#include <libTAU/kademlia/node_id.hpp>
#include <libTAU/kademlia/observer.hpp>
#include <libTAU/aux_/listen_socket_handle.hpp>
#include <libTAU/aux_/pool.hpp>

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
struct socket_manager;

struct TORRENT_EXTRA_EXPORT null_observer : observer
{
	null_observer(std::shared_ptr<traversal_algorithm> a
		, udp::endpoint const& ep, node_id const& id)
		: observer(std::move(a), ep, id) {}
	void reply(msg const&, node_id const&) override { flags |= flag_done; }
};

class routing_table;
class incoming_table;

class TORRENT_EXTRA_EXPORT rpc_manager
{
public:

	rpc_manager(node_id const& our_id
		, aux::session_settings const& settings
		, routing_table& table
		, incoming_table& incoming_table
		, aux::listen_socket_handle sock
		, socket_manager* sock_man
		, dht_logger* log);
	~rpc_manager();

	void unreachable(udp::endpoint const& ep);

	// returns true if the node needs a refresh
	// if so, id is assigned the node id to refresh
	bool incoming(msg const&, node_id const& nid);
	time_duration tick();

	bool invoke(entry& e, udp::endpoint const& target
		, observer_ptr o, bool discard_response = false);

#if TORRENT_USE_ASSERTS
	size_t allocation_size() const;
#endif
#if TORRENT_USE_INVARIANT_CHECKS
	void check_invariant() const;
#endif

	template <typename T, typename... Args>
	std::shared_ptr<T> allocate_observer(Args&&... args)
	{
		void* ptr = allocate_observer();
		if (ptr == nullptr) return std::shared_ptr<T>();

		auto deleter = [this](observer* o)
		{
			TORRENT_ASSERT(o->m_in_use);
			o->~observer();
			free_observer(o);
		};
		return std::shared_ptr<T>(new (ptr) T(std::forward<Args>(args)...), deleter);
	}

	int num_allocated_observers() const { return m_allocated_observers; }

	int num_invoked_requests() const { return m_invoked_requests; }

	void update_node_id(node_id const& id) { m_our_id = id; }

private:

	void* allocate_observer();
	void free_observer(void* ptr);

	mutable lt::aux::pool m_pool_allocator;

	std::unordered_multimap<std::uint16_t, observer_ptr> m_transactions;

	aux::listen_socket_handle m_sock;
	socket_manager* m_sock_man;
#ifndef TORRENT_DISABLE_LOGGING
	dht_logger* m_log;
#endif
	aux::session_settings const& m_settings;
	routing_table& m_table;
	incoming_table& m_incoming_table;
	node_id m_our_id;
	std::uint32_t m_allocated_observers:31;
	std::int64_t m_invoked_requests;
	std::uint32_t m_destructing:1;
};

} // namespace dht
} // namespace libTAU

#endif
