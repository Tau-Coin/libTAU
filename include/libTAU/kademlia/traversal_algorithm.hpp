/*

Copyright (c) 2006, Daniel Wallin
Copyright (c) 2006, 2008-2010, 2013-2020, Arvid Norberg
Copyright (c) 2015, Steven Siloti
Copyright (c) 2016, Alden Torres
Copyright (c) 2016-2017, Pavel Pimenov
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TRAVERSAL_ALGORITHM_050324_HPP
#define TRAVERSAL_ALGORITHM_050324_HPP

#include <vector>
#include <set>
#include <memory>

#include <libTAU/fwd.hpp>
#include <libTAU/kademlia/node_id.hpp>
#include <libTAU/kademlia/routing_table.hpp>
#include <libTAU/kademlia/observer.hpp>
#include <libTAU/address.hpp>
#include <libTAU/flags.hpp>
#include <libTAU/bdecode.hpp>

namespace libTAU {

namespace dht {

class node;
struct node_endpoint;

using traversal_flags_t = libTAU::flags::bitfield_flag<std::uint8_t, struct traversal_flags_tag>;

// this class may not be instantiated as a stack object
struct TORRENT_EXTRA_EXPORT traversal_algorithm
	: std::enable_shared_from_this<traversal_algorithm>
{
	void traverse(node_id const& id, udp::endpoint const& addr);
	void finished(observer_ptr o);

	static inline constexpr traversal_flags_t prevent_request = 0_bit;
	static inline constexpr traversal_flags_t short_timeout = 1_bit;

	void failed(observer_ptr o, traversal_flags_t flags = {});
	virtual ~traversal_algorithm();
	void status(dht_lookup& l);

	virtual char const* name() const;
	virtual void start();

	// added by libTAU
	virtual bool is_done() const;

	node_id const& target() const { return m_target; }

	void resort_result(observer*);
	void add_entry(node_id const& id, udp::endpoint const& addr, observer_flags_t flags);

	traversal_algorithm(node& dht_node, node_id const& target);
	traversal_algorithm(traversal_algorithm const&) = delete;
	traversal_algorithm& operator=(traversal_algorithm const&) = delete;
	int invoke_count() const { TORRENT_ASSERT(m_invoke_count >= 0); return m_invoke_count; }
	int branch_factor() const { TORRENT_ASSERT(m_branch_factor >= 0); return m_branch_factor; }

	void set_invoke_window(std::int8_t invoke_window) { m_invoke_window = invoke_window; }
	void set_invoke_limit(std::int8_t invoke_limit) { m_invoke_limit = invoke_limit; }

	node& get_node() const { return m_node; }

	// Set specified endpoints which traversal algorithm
	// will communicate with instead of depth traversal.
	// Make sure this method must be called before start method.
	void set_direct_endpoints(std::vector<node_entry> const& eps);

	// Discard corresponding responses and rpc manager don't store these requests.
	void set_discard_response(bool discard_response);

	void set_fixed_distance(int distance) { m_fixed_distance = distance; }

#ifndef TORRENT_DISABLE_LOGGING
	std::uint32_t id() const { return m_id; }
#endif

protected:

	std::shared_ptr<traversal_algorithm> self()
	{ return shared_from_this(); }

	std::uint32_t get_high_priority_node(std::uint32_t max);

	// returns true if we're done
	bool add_requests();

	void add_router_entries();
	void init();

	virtual void done();
	// should construct an algorithm dependent
	// observer in ptr.
	virtual observer_ptr new_observer(udp::endpoint const& ep
		, node_id const& id);

	virtual bool invoke(observer_ptr) { return false; }

	int num_responses() const { return m_responses; }
	int num_timeouts() const { return m_timeouts; }

	// the min distance of the endpoint which is allowed into m_results.
	int allow_distance() const;

	int invoke_window() const { return m_invoke_window; }

	int invoke_limit() const { return m_invoke_limit; }

	node& m_node;

	// this vector is sorted by node-id distance from our node id. Closer nodes
	// are earlier in the vector. However, not the entire vector is necessarily
	// sorted, the tail of the vector may contain nodes out-of-order. This is
	// used when bootstrapping. The ``m_sorted_results`` member indicates how
	// many of the first elements are sorted.
	std::vector<observer_ptr> m_results;

	// This flag indicates whether traversal algorithm
	// will communicate with the specified nodes instead of depth traversal.
	// The default value "false" means getting or putting mutable items.
	bool m_direct_invoking = false;

	// This flag indicates traversal algorithm directly invokes all requests
	// and discard corresponding responses.
	bool m_discard_response = false;

	int m_fixed_distance = -1;

	int num_sorted_results() const { return m_sorted_results; }

private:

	node_id const m_target;
	std::int8_t m_invoke_count = 0;
	std::int8_t m_branch_factor = 3;
	std::int8_t m_invoke_window = 3;
	// limit the total invoked requests.
	std::int8_t m_invoke_limit = 0;
	std::int8_t m_invoke_failed = 0;
	// the number of elements at the beginning of m_results that are sorted by
	// node_id.
	std::int8_t m_sorted_results = 0;
	std::int16_t m_responses = 0;
	std::int16_t m_timeouts = 0;

	// set to true when done() is called, and will prevent adding new results, as
	// they would never be serviced and the whole traversal algorithm would stall
	// and leak
	bool m_done = false;

#ifndef TORRENT_DISABLE_LOGGING
	// this is a unique ID for this specific traversal_algorithm instance,
	// just used for logging
	std::uint32_t m_id;
#endif

	// the IP addresses of the nodes in m_results
	std::set<std::uint32_t> m_peer4_prefixes;
	std::set<std::uint64_t> m_peer6_prefixes;
#ifndef TORRENT_DISABLE_LOGGING
	void log_timeout(observer_ptr const& o, char const* prefix) const;
#endif
};

void look_for_nodes(char const* nodes_key, udp const& protocol
	, bdecode_node const& r, std::function<void(node_endpoint const&)> f);

struct traversal_observer : observer
{
	traversal_observer(
		std::shared_ptr<traversal_algorithm> algorithm
		, udp::endpoint const& ep, node_id const& id)
		: observer(std::move(algorithm), ep, id)
	{}

	// parses out "nodes" and keeps traversing
	void reply(msg const&, node_id const&) override;
};

} // namespace dht
} // namespace libTAU

#endif // TRAVERSAL_ALGORITHM_050324_HPP
