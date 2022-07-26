/*

Copyright (c) 2006, Daniel Wallin
Copyright (c) 2006-2017, 2019-2020, Arvid Norberg
Copyright (c) 2015-2016, Steven Siloti
Copyright (c) 2016-2017, Pavel Pimenov
Copyright (c) 2016-2018, 2021, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <libTAU/kademlia/traversal_algorithm.hpp>
#include <libTAU/kademlia/rpc_manager.hpp>
#include <libTAU/kademlia/node.hpp>
#include <libTAU/kademlia/dht_observer.hpp> // for dht_logger
#include <libTAU/kademlia/dht_settings.hpp>
#include <libTAU/kademlia/io.hpp>
#include <libTAU/aux_/socket_io.hpp> // for read_*_endpoint
#include <libTAU/aux_/random.hpp>
#include <libTAU/alert_types.hpp> // for dht_lookup
#include <libTAU/aux_/time.hpp>

#ifndef TORRENT_DISABLE_LOGGING
#include <libTAU/hex.hpp> // to_hex
#endif

using namespace std::placeholders;

namespace libTAU::dht {

#if TORRENT_USE_ASSERTS
template <class It, class Cmp>
bool is_sorted(It b, It e, Cmp cmp)
{
	if (b == e) return true;

	typename std::iterator_traits<It>::value_type v = *b;
	++b;
	while (b != e)
	{
		if (cmp(*b, v)) return false;
		v = *b;
		++b;
	}
	return true;
}
#endif

observer_ptr traversal_algorithm::new_observer(udp::endpoint const& ep
	, node_id const& id)
{
	auto o = m_node.m_rpc.allocate_observer<null_observer>(self(), ep, id);
#if TORRENT_USE_ASSERTS
	if (o) o->m_in_constructor = false;
#endif
	return o;
}

traversal_algorithm::traversal_algorithm(node& dht_node, node_id const& target)
	: m_node(dht_node)
	, m_target(target)
{

	m_branch_factor = aux::numeric_cast<std::int8_t>(m_node.branch_factor());
	m_invoke_window = aux::numeric_cast<std::int8_t>(m_node.invoke_window());
	m_invoke_limit = aux::numeric_cast<std::int8_t>(m_node.invoke_limit());
#ifndef TORRENT_DISABLE_LOGGING
	m_id = m_node.search_id();
	dht_observer* logger = get_node().observer();
	if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
	{
		logger->log(dht_logger::traversal, "[%u] NEW target: %s k: %d"
			, m_id, aux::to_hex(target).c_str(), m_node.m_table.bucket_size());
	}
#endif
}

void traversal_algorithm::resort_result(observer* o)
{
	// find the given observer, remove it and insert it in its sorted location
	auto it = std::find_if(m_results.begin(), m_results.end()
		, [=](observer_ptr const& ptr) { return ptr.get() == o; });

	if (it == m_results.end()) return;

	if (it - m_results.begin() < m_sorted_results)
		--m_sorted_results;

	observer_ptr ptr = std::move(*it);
	m_results.erase(it);

	TORRENT_ASSERT(std::size_t(m_sorted_results) <= m_results.size());
	auto end = m_results.begin() + m_sorted_results;

	TORRENT_ASSERT(libTAU::dht::is_sorted(m_results.begin(), end
		, [this](observer_ptr const& lhs, observer_ptr const& rhs)
		{ return compare_ref(lhs->id(), rhs->id(), m_target); }));

	auto iter = std::lower_bound(m_results.begin(), end, ptr
		, [this](observer_ptr const& lhs, observer_ptr const& rhs)
		{ return compare_ref(lhs->id(), rhs->id(), m_target); });

	m_results.insert(iter, ptr);
	++m_sorted_results;
}

void traversal_algorithm::add_entry(node_id const& id
	, udp::endpoint const& addr, observer_flags_t const flags)
{
	if (m_done) return;

	TORRENT_ASSERT(m_node.m_rpc.allocation_size() >= sizeof(find_data_observer));
	auto o = new_observer(addr, id);
	if (!o)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (get_node().observer() != nullptr)
		{
			get_node().observer()->log(dht_logger::traversal, "[%u] failed to allocate memory or observer. aborting!"
				, m_id);
		}
#endif
		done();
		return;
	}

	o->flags |= flags;

	if (id.is_all_zeros())
	{
		o->set_id(generate_random_id());
		o->flags |= observer::flag_no_id;

		m_results.push_back(o);

#ifndef TORRENT_DISABLE_LOGGING
		dht_observer* logger = get_node().observer();
		if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
		{
			logger->log(dht_logger::traversal
				, "[%u] ADD (no-id) id: %s addr: %s distance: %d invoke-count: %d type: %s"
				, m_id, aux::to_hex(id).c_str(), aux::print_endpoint(addr).c_str()
				, distance_exp(m_target, id), m_invoke_count, name());
		}
#endif
	}
	else
	{
		TORRENT_ASSERT(std::size_t(m_sorted_results) <= m_results.size());
		auto end = m_results.begin() + m_sorted_results;

		TORRENT_ASSERT(libTAU::dht::is_sorted(m_results.begin(), end
				, [this](observer_ptr const& lhs, observer_ptr const& rhs)
				{ return compare_ref(lhs->id(), rhs->id(), m_target); }));

		auto iter = std::lower_bound(m_results.begin(), end, o
			, [this](observer_ptr const& lhs, observer_ptr const& rhs)
			{ return compare_ref(lhs->id(), rhs->id(), m_target); });

		if (iter == end || (*iter)->id() != id)
		{
			// this IP restriction does not apply to the nodes we loaded from out
			// node cache
			if (m_node.settings().get_bool(settings_pack::dht_restrict_search_ips)
				&& !(flags & observer::flag_initial))
			{
				if (o->target_addr().is_v6())
				{
					address_v6::bytes_type addr_bytes = o->target_addr().to_v6().to_bytes();
					auto prefix_it = addr_bytes.cbegin();
					std::uint64_t const prefix6 = aux::read_uint64(prefix_it);

					if (m_peer6_prefixes.insert(prefix6).second)
						goto add_result;
				}
				else
				{
					// mask the lower octet
					std::uint32_t const prefix4
						= o->target_addr().to_v4().to_uint() & 0xffffff00;

					if (m_peer4_prefixes.insert(prefix4).second)
						goto add_result;
				}

				// we already have a node in this search with an IP very
				// close to this one. We know that it's not the same, because
				// it claims a different node-ID. Ignore this to avoid attacks
#ifndef TORRENT_DISABLE_LOGGING
				dht_observer* logger = get_node().observer();
				if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
				{
					logger->log(dht_logger::traversal
						, "[%u] traversal DUPLICATE node. id: %s addr: %s type: %s"
						, m_id, aux::to_hex(o->id()).c_str(), aux::print_address(o->target_addr()).c_str(), name());
				}
#endif
				return;
			}

	add_result:

			TORRENT_ASSERT((o->flags & observer::flag_no_id)
				|| std::none_of(m_results.begin(), end
					, [&id](observer_ptr const& ob) { return ob->id() == id; }));

#ifndef TORRENT_DISABLE_LOGGING
			dht_observer* logger = get_node().observer();
			if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
			{
				logger->log(dht_logger::traversal
					, "[%u] ADD id: %s addr: %s distance: %d invoke-count: %d type: %s"
					, m_id, aux::to_hex(id).c_str(), aux::print_endpoint(addr).c_str()
					, distance_exp(m_target, id), m_invoke_count, name());
			}
#endif
			m_results.insert(iter, o);
			++m_sorted_results;
		}
	}

	TORRENT_ASSERT(std::size_t(m_sorted_results) <= m_results.size());
	TORRENT_ASSERT(libTAU::dht::is_sorted(m_results.begin()
		, m_results.begin() + m_sorted_results
		, [this](observer_ptr const& lhs, observer_ptr const& rhs)
		{ return compare_ref(lhs->id(), rhs->id(), m_target); }));

	if (m_results.size() > 100)
	{
		std::for_each(m_results.begin() + 100, m_results.end()
			, [this](std::shared_ptr<observer> const& ptr)
		{
			if ((ptr->flags & (observer::flag_queried | observer::flag_failed | observer::flag_alive))
				== observer::flag_queried)
			{
				// set the done flag on any outstanding queries to prevent them from
				// calling finished() or failed()
				ptr->flags |= observer::flag_done;
				TORRENT_ASSERT(m_invoke_count > 0);
			}

#if TORRENT_USE_ASSERTS
			ptr->m_was_abandoned = true;
#endif
		});
		m_results.resize(100);
		m_sorted_results = std::min(std::int8_t(100), m_sorted_results);
	}
}

void traversal_algorithm::set_direct_endpoints(std::vector<node_entry> const& eps)
{
	for (auto const& e : eps)
	{
		add_entry(e.id, e.ep(), observer::flag_initial);
	}

	m_direct_invoking = true;
}

void traversal_algorithm::set_discard_response(bool discard_response)
{
	m_discard_response = discard_response;
}

void traversal_algorithm::start()
{
	// in case the routing table is empty, use the
	// router nodes in the table
	// TODO: remove this logic when blockchain can provide more alive nodes.
	if (m_results.size() < invoke_window()) add_router_entries();
	init();
	bool const is_done = add_requests();
	if (is_done) done();
}

char const* traversal_algorithm::name() const
{
	return "traversal_algorithm";
}

bool traversal_algorithm::is_done() const
{
	return false;
}

void traversal_algorithm::traverse(node_id const& id, udp::endpoint const& addr)
{
	if (m_done) return;

	// TODO: exclude ourself from invoking list.
	// This is temporay solution and it may exclude ourself on another device.
	if (m_node.nid() == id) return;

#ifndef TORRENT_DISABLE_LOGGING
	dht_observer* logger = get_node().observer();
	if (logger != nullptr
		&& logger->should_log(dht_logger::traversal, aux::LOG_WARNING) && id.is_all_zeros())
	{
		logger->log(dht_logger::traversal
			, "[%u] WARNING node returned a list which included a node with id 0"
			, m_id);
	}
#endif

	node_entry *existing;
	std::tie(existing, std::ignore, std::ignore) = m_node.m_table.find_node(addr);

#ifndef TORRENT_DISABLE_LOGGING
	if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
	{
		if (existing != nullptr)
		{
			logger->log(dht_logger::traversal
				, "[%u] NODE id: %s addr: %s distance: %d allow-invoke: %s type: %s"
				, m_id, aux::to_hex(id).c_str(), aux::print_endpoint(addr).c_str()
				, distance_exp(m_target, id)
				, existing->allow_invoke() ? "true" : "false", name());
		}
		else
		{
			logger->log(dht_logger::traversal
				, "[%u] NODE id: %s addr: %s not found, type: %s"
				, m_id, aux::to_hex(id).c_str(), aux::print_endpoint(addr).c_str()
				, name());
		}
	}
#endif

	// only accept other nodes when target nodes are not specified.
	// When one endpoint aren't accepted by routing table, give it
	// invoking chance if its distance is enough small.
	if (!m_direct_invoking && (existing == nullptr
				|| (existing != nullptr && existing->allow_invoke() && !existing->pinged()))
		&& distance_exp(m_target, id) <= allow_distance())
	{
		add_entry(id, addr, {});
	}

	// let the routing table know this node may exist
	m_node.m_table.heard_about(id, addr);
}

void traversal_algorithm::finished(observer_ptr o)
{
#if TORRENT_USE_ASSERTS
	auto i = std::find(m_results.begin(), m_results.end(), o);
	TORRENT_ASSERT(i != m_results.end() || m_results.size() == 100);
#endif

	// if this flag is set, it means we increased the
	// branch factor for it, and we should restore it
	if (o->flags & observer::flag_short_timeout)
	{
		TORRENT_ASSERT(m_branch_factor > 0);
		//--m_branch_factor;
	}

	TORRENT_ASSERT(o->flags & observer::flag_queried);
	o->flags |= observer::flag_alive;

	++m_responses;
	bool const is_done = add_requests();
	if (is_done) done();
}

// prevent request means that the total number of requests has
// overflown. This query failed because it was the oldest one.
// So, if this is true, don't make another request
void traversal_algorithm::failed(observer_ptr o, traversal_flags_t const flags)
{
	// don't tell the routing table about
	// node ids that we just generated ourself
	if (!(o->flags & observer::flag_no_id))
		m_node.m_table.node_failed(o->id(), o->target_ep());

	if (m_results.empty())
	{
		// Anyway, set observer timeout flag
		if (flags & short_timeout)
		{
			o->flags |= observer::flag_short_timeout;
		}
		else
		{
			o->flags |= observer::flag_failed;

			node_entry *existing;
			std::tie(existing, std::ignore, std::ignore) = m_node.m_table.find_node(o->target_ep());
			if (existing != nullptr)
			{
				existing->invoke_failed();
			}
		}

		return;
	}

	bool decrement_branch_factor = false;

	TORRENT_ASSERT(o->flags & observer::flag_queried);
	if (flags & short_timeout)
	{
		// short timeout means that it has been more than
		// two seconds since we sent the request, and that
		// we'll most likely not get a response. But, in case
		// we do get a late response, keep the handler
		// around for some more, but open up the slot
		// by increasing the branch factor
		if (!(o->flags & observer::flag_short_timeout)
			&& m_branch_factor < std::numeric_limits<std::int8_t>::max())
		{
			//++m_branch_factor;
			o->flags |= observer::flag_short_timeout;
		}
#ifndef TORRENT_DISABLE_LOGGING
		log_timeout(o, "1ST_");
#endif
	}
	else
	{
		o->flags |= observer::flag_failed;
		// if this flag is set, it means we increased the
		// branch factor for it, and we should restore it
		decrement_branch_factor = bool(o->flags & observer::flag_short_timeout);

#ifndef TORRENT_DISABLE_LOGGING
		log_timeout(o,"");
#endif

		++m_timeouts;
		TORRENT_ASSERT(m_invoke_count > 0);

		node_entry *existing;
		std::tie(existing, std::ignore, std::ignore) = m_node.m_table.find_node(o->target_ep());
		if (existing != nullptr)
		{
			existing->invoke_failed();
		}
	}

	// this is another reason to decrement the branch factor, to prevent another
	// request from filling this slot. Only ever decrement once per response though
	decrement_branch_factor |= bool(flags & prevent_request);

	if (decrement_branch_factor)
	{
		TORRENT_ASSERT(m_branch_factor > 0);
		//--m_branch_factor;
		//if (m_branch_factor <= 0) m_branch_factor = 1;
	}

	bool const is_done = add_requests();
	if (is_done) done();
}

#ifndef TORRENT_DISABLE_LOGGING
void traversal_algorithm::log_timeout(observer_ptr const& o, char const* prefix) const
{
	dht_observer * logger = get_node().observer();
	if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_WARNING))
	{
		logger->log(dht_logger::traversal
			, "[%u] %sTIMEOUT id: %s distance: %d addr: %s branch-factor: %d "
			"invoke-count: %d type: %s"
			, m_id, prefix, aux::to_hex(o->id()).c_str(), distance_exp(m_target, o->id())
			, aux::print_address(o->target_addr()).c_str(), m_branch_factor
			, m_invoke_count, name());
	}

}
#endif

void traversal_algorithm::done()
{
	TORRENT_ASSERT(m_done == false);
	m_done = true;
#ifndef TORRENT_DISABLE_LOGGING
	int results_target = m_node.m_table.bucket_size();
	int closest_target = 256;
#endif

	for (auto const& o : m_results)
	{
		if ((o->flags & (observer::flag_queried | observer::flag_failed)) == observer::flag_queried)
		{
			// set the done flag on any outstanding queries to prevent them from
			// calling finished() or failed() after we've already declared the traversal
			// done
			o->flags |= observer::flag_done;
		}

#ifndef TORRENT_DISABLE_LOGGING
		dht_observer* logger = get_node().observer();
		if (results_target > 0 && (o->flags & observer::flag_alive)
			&& logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
		{
			TORRENT_ASSERT(o->flags & observer::flag_queried);
			logger->log(dht_logger::traversal
				, "[%u] id: %s distance: %d addr: %s"
				, m_id, aux::to_hex(o->id()).c_str(), closest_target
				, aux::print_endpoint(o->target_ep()).c_str());

			--results_target;
			int const dist = distance_exp(m_target, o->id());
			if (dist < closest_target) closest_target = dist;
		}
#endif
	}

#ifndef TORRENT_DISABLE_LOGGING
	if (get_node().observer() != nullptr)
	{
		get_node().observer()->log(dht_logger::traversal
			, "[%u] COMPLETED distance: %d type: %s"
			, m_id, closest_target, name());
	}
#endif

	// delete all our references to the observer objects so
	// they will in turn release the traversal algorithm
	m_results.clear();
	m_sorted_results = 0;
	m_invoke_count = 0;
	m_invoke_failed = 0;
}

int traversal_algorithm::allow_distance() const
{
	if (m_fixed_distance >= 0)
	{
		return m_fixed_distance;
	}

	int index = int(m_results.size()) >= m_invoke_limit ?
			m_invoke_limit - 1 : int(m_results.size()) - 1;
	observer* o = (m_results.begin() + index)->get();

	return distance_exp(m_target, o->id());
}

/*
bool traversal_algorithm::add_requests()
{
	if (m_done) return true;

	// Once invoke all requests if discarding response and invoking directly.
	if (m_discard_response && m_direct_invoking)
	{
		for (auto i = m_results.begin(), end(m_results.end()); i != end; ++i)
		{
			observer* o = i->get();
			o->flags |= observer::flag_queried;
			if (invoke(*i))
			{
				TORRENT_ASSERT(m_invoke_count < std::numeric_limits<std::int8_t>::max());
				++m_invoke_count;
			}
			else
			{
				o->flags |= observer::flag_failed;
			}
		}

		return true;
	}

	// this only counts outstanding requests at the top of the
	// target list. This is <= m_invoke count. m_invoke_count
	// is the total number of outstanding requests, including
	// old ones that may be waiting on nodes much farther behind
	// the current point we've reached in the search.
	int outstanding = 0;

	int has_invoked = 0;

	// if the first 'invoke_limit' nodes are all invoked, just return true;
	int j = 0;

	if (m_invoke_count < m_invoke_limit)
	{
		for (auto i = m_results.begin(), end(m_results.end());
			i != end && j < m_invoke_limit;
			++i)
		{
			j++;

			observer* o = i->get();
			if (o->flags & observer::flag_alive)
			{
				TORRENT_ASSERT(o->flags & observer::flag_queried);
				has_invoked++;
				continue;
			}
			if (o->flags & observer::flag_queried)
			{
				// if it's queried, not alive and not failed, it
				// must be currently in flight
				if (!(o->flags & observer::flag_failed))
					++outstanding;

				has_invoked++;
				continue;
			}
		}

		if (outstanding == 0
			&& (has_invoked >= m_invoke_limit || has_invoked == int(m_results.size())))
		{
			return true;
		}
		else if (outstanding != 0
			&& (has_invoked >= m_invoke_limit || has_invoked == int(m_results.size())))
		{
			return false;
		}
	}

	// this only counts invoking requests for once calling this function.
	int invokes = 0;

	std::uint32_t random_max = int(m_results.size()) >= m_invoke_limit ?
			std::uint32_t(m_invoke_limit) - 1 : std::uint32_t(m_results.size()) - 1;

	// Find the first node that hasn't already been queried.
	// and make sure that the 'm_branch_factor' top nodes
	// stay queried at all times (obviously ignoring failed nodes)
	// and without surpassing the 'result_target' nodes (i.e. k=8)
	// this is a slight variation of the original paper which instead
	// limits the number of outstanding requests, this limits the
	// number of good outstanding requests. It will use more traffic,
	// but is intended to speed up lookups
	while (invokes < m_branch_factor
		&& m_invoke_count < m_invoke_limit
		&& m_invoke_count < (aux::numeric_cast<std::int16_t>(m_results.size()))
		&& m_responses + m_timeouts + outstanding + m_invoke_failed
			< (aux::numeric_cast<std::int16_t>(m_results.size()))
	)
	{
		// generate random
		std::uint32_t const r = aux::random(random_max);
		observer* o = (m_results.begin() + r)->get();

		if (o->flags & observer::flag_alive)
		{
			TORRENT_ASSERT(o->flags & observer::flag_queried);
			continue;
		}

		if (o->flags & observer::flag_queried)
		{
			continue;
		}

#ifndef TORRENT_DISABLE_LOGGING
		dht_observer* logger = get_node().observer();
		if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
		{
			logger->log(dht_logger::traversal
				, "[%u] INVOKE node-index: %d top-invoke-count: %d "
				"invoke-count: %d branch-factor: %d invoke-limit: %d "
				"distance: %d id: %s addr: %s type: %s"
				, m_id, r, outstanding, int(m_invoke_count)
				, int(m_branch_factor), int(m_invoke_limit)
				, distance_exp(m_target, o->id()), aux::to_hex(o->id()).c_str()
				, aux::print_address(o->target_addr()).c_str(), name());
		}
#endif

		o->flags |= observer::flag_queried;
		if (invoke(*(m_results.begin() + r)))
		{
			TORRENT_ASSERT(m_invoke_count < std::numeric_limits<std::int8_t>::max());
			++outstanding;
			++invokes;
		}
		else
		{
			o->flags |= observer::flag_failed;
			++m_invoke_failed;

			if (!(o->flags & observer::flag_no_id))
				m_node.m_table.node_failed(o->id(), o->target_ep());
		}

		++m_invoke_count;
	}

	// 1. m_responses + m_timeouts + m_invoke_failed >= m_invoke_limit
	//     we have invoked enough requests and all requests were all processed.
	// 2. m_timeouts == m_invoke_count
	//     all the requests were timeout.
	// 3. m_responses + m_timeouts + m_invoke_failed = m_results.size()
	//     the total size of m_results is less than m_invoke_limit
	//     and all requests were all processed.
	// 4. if invoke count is 0, it means we didn't even find any
	//     working nodes, we still have to terminate though.
	return (outstanding == 0 && (m_responses + m_timeouts + m_invoke_failed >= m_invoke_limit))
			|| (outstanding == 0 && m_invoke_count != 0 && m_timeouts == m_invoke_count)
			|| (outstanding == 0 && m_invoke_count != 0
					&& (m_responses + m_timeouts + m_invoke_failed
							== aux::numeric_cast<std::int16_t>(m_results.size())))
			|| m_invoke_count == 0;
}
*/

bool traversal_algorithm::add_requests()
{
	if (m_done || m_results.empty() || is_done()) return true;

	// Once invoke all requests if discarding response and invoking directly.
	if (m_discard_response && m_direct_invoking)
	{
		for (auto i = m_results.begin(), end(m_results.end()); i != end; ++i)
		{
			observer* o = i->get();
			o->flags |= observer::flag_queried;
			if (invoke(*i))
			{
				TORRENT_ASSERT(m_invoke_count < std::numeric_limits<std::int8_t>::max());
				++m_invoke_count;
			}
			else
			{
				o->flags |= observer::flag_failed;
			}
		}

		return true;
	}

	// the following logic is based on 'alpha == 1'.
	TORRENT_ASSERT(m_branch_factor == 1);

	// this only counts outstanding requests at the top of the
	// invoke window. Because in the condition of 'alpha == 1',
	// the outstanding requests can only happen in invoke window.
	int outstanding = 0;

	// invoke count in invoke window.
	int invoke_count_in_window = 0;
	int j = 0;

	// traverse the invoke window and statistic the oustanding and the invoked nodes.
	for (auto i = m_results.begin(), end(m_results.end());
		i != end && j < m_invoke_window;
		++i)
	{
		j++;

		observer* o = i->get();
		if (o->flags & observer::flag_alive)
		{
			TORRENT_ASSERT(o->flags & observer::flag_queried);
			invoke_count_in_window++;
			continue;
		}

		if (o->flags & observer::flag_queried)
		{
			// if it's queried, not alive and not failed, it
			// must be currently in flight
			if (!(o->flags & observer::flag_failed))
				++outstanding;

			invoke_count_in_window++;
			continue;
		}
	}

	// 1. 'invoke_count_in_window == m_invoke_window':
	//		the nodes in invoke window all have been invoked.
	// 2. 'invoke_count_in_window == m_results.size()':
	//		m_results.size() <= m_invoke_window and all
	//		the nodes have been invoked.
	// 3. 'm_invoke_count >= m_invoke_limit':
	//		m_invoke_window >= m_invoke_limit
	if (invoke_count_in_window == m_invoke_window
		|| invoke_count_in_window == int(m_results.size())
		|| m_invoke_count >= m_invoke_limit)
	{
		return outstanding == 0;
	}

	// here, randomly select a node and invoke.
	std::uint32_t random_max = int(m_results.size()) >= m_invoke_window ?
		std::uint32_t(m_invoke_window) - 1 : std::uint32_t(m_results.size()) - 1;

	// Find the first node in invoke window that hasn't already been queried.
	while (m_invoke_count < m_invoke_limit
		&& invoke_count_in_window < m_invoke_window
		&& invoke_count_in_window < aux::numeric_cast<std::int16_t>(m_results.size())
	)
	{
		// try to get invoking node with high priority
		std::uint32_t r = get_high_priority_node(random_max);

		if (r > random_max)
		{
			// generate random
			r = aux::random(random_max);
		}

		observer* o = (m_results.begin() + r)->get();

		if (o->flags & observer::flag_alive)
		{
			TORRENT_ASSERT(o->flags & observer::flag_queried);
			continue;
		}

		if (o->flags & observer::flag_queried)
		{
			continue;
		}

#ifndef TORRENT_DISABLE_LOGGING
		dht_observer* logger = get_node().observer();
		if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
		{
			logger->log(dht_logger::traversal
				, "[%u] INVOKE node-index: %d outstanding: %d "
				"invoke-count: %d invoke-window: %d invoke-limit: %d "
				"distance: %d id: %s addr: %s type: %s"
				, m_id, r, outstanding, int(m_invoke_count)
				, int(m_invoke_window), int(m_invoke_limit)
				, distance_exp(m_target, o->id()), aux::to_hex(o->id()).c_str()
				, aux::print_address(o->target_addr()).c_str(), name());
		}
#endif

		o->flags |= observer::flag_queried;
		++m_invoke_count;
		++invoke_count_in_window;

		if (invoke(*(m_results.begin() + r)))
		{
			TORRENT_ASSERT(m_invoke_count < std::numeric_limits<std::int8_t>::max());
			++outstanding;
			break; // alpha == 1, so just invoke once
		}
		else
		{
			o->flags |= observer::flag_failed;
			++m_invoke_failed;

			if (!(o->flags & observer::flag_no_id))
				m_node.m_table.node_failed(o->id(), o->target_ep());

			continue; // select next random node
		}
	}

	// 1. 'invoke_count_in_window == m_invoke_window':
	//      the nodes in invoke window all have been invoked.
	// 2. 'invoke_count_in_window == m_results.size()':
	//      m_results.size() <= m_invoke_window and all
	//      the nodes have been invoked.
	// 3. 'm_invoke_count >= m_invoke_limit':
	//      m_invoke_window >= m_invoke_limit
	if (invoke_count_in_window == m_invoke_window
		|| invoke_count_in_window == int(m_results.size())
		|| m_invoke_count >= m_invoke_limit)
	{
		return outstanding == 0;
	}

	return false;
}

std::uint32_t traversal_algorithm::get_high_priority_node(std::uint32_t max)
{
	std::uint32_t ret = max + 1;
	std::uint32_t j = 0;

	// traverse the invoke window and get the node with high priority.
	for (auto i = m_results.begin(), end(m_results.end());
		i != end && j <= max;
		++i, ++j)
	{
		observer* o = i->get();
		if (o->flags & observer::flag_alive
			|| o->flags & observer::flag_queried
			|| o->flags & observer::flag_failed
			|| o->flags & observer::flag_done)
		{
			continue;
		}

		if (o->flags & observer::flag_high_priority)
		{
			ret = j;
			break;
		}
	}

	return ret;
}

void traversal_algorithm::add_router_entries()
{
#ifndef TORRENT_DISABLE_LOGGING
	dht_observer* logger = get_node().observer();
	if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
	{
		logger->log(dht_logger::traversal
			, "[%u] using router nodes to initiate traversal algorithm %d routers"
			, m_id, int(std::distance(m_node.m_table.begin(), m_node.m_table.end())));
	}
#endif
	for (auto const& n : m_node.m_table)
		add_entry(n.id, n.ep(), observer::flag_initial);
}

void traversal_algorithm::init()
{
	m_node.add_traversal_algorithm(this);
}

traversal_algorithm::~traversal_algorithm()
{
	m_node.remove_traversal_algorithm(this);
}

void traversal_algorithm::status(dht_lookup& l)
{
	l.timeouts = m_timeouts;
	l.responses = m_responses;
	l.outstanding_requests = m_invoke_count;
	l.branch_factor = m_branch_factor;
	l.type = name();
	l.nodes_left = 0;
	l.first_timeout = 0;
	// temp removed
	//l.target = m_target;

	int last_sent = INT_MAX;
	time_point const now = aux::time_now();
	for (auto const& r : m_results)
	{
		observer const& o = *r;
		if (o.flags & observer::flag_queried)
		{
			last_sent = std::min(last_sent, int(total_seconds(now - o.sent())));
			if (o.has_short_timeout()) ++l.first_timeout;
			continue;
		}
		++l.nodes_left;
	}
	l.last_sent = last_sent;
}

void look_for_nodes(char const* nodes_key, udp const& protocol, bdecode_node const& r, std::function<void(const node_endpoint&)> f)
{
	bdecode_node const n = r.dict_find_string(nodes_key);
	if (n)
	{
		char const* nodes = n.string_ptr();
		char const* end = nodes + n.string_length();
		int const protocol_size = int(aux::address_size(protocol));

		while (end - nodes >= 32 + protocol_size + 2)
		{
			f(read_node_endpoint(protocol, nodes));
		}
	}
}

void traversal_observer::reply(msg const& m, node_id const& from)
{
	bdecode_node const r = m.message.dict_find_dict("r");
	if (!r)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (get_observer() != nullptr)
		{
			get_observer()->log(dht_logger::traversal
				, "[%u] missing response dict"
				, algorithm()->id());
		}
#endif
		return;
	}

#ifndef TORRENT_DISABLE_LOGGING
	dht_observer* logger = get_observer();
	if (logger != nullptr && logger->should_log(dht_logger::traversal, aux::LOG_INFO))
	{
        // Because node id has 32 bytes, and corresponding hex string
        // length is 64. So here allocate 64 + 1 bytes.
		char hex_id[65];
		aux::to_hex({from.data(), 32}, hex_id);
		logger->log(dht_logger::traversal
			, "[%u] RESPONSE id: %s invoke-count: %d addr: %s type: %s"
			, algorithm()->id(), hex_id, algorithm()->invoke_count()
			, aux::print_endpoint(target_ep()).c_str(), algorithm()->name());
	}
#endif

	look_for_nodes(algorithm()->get_node().protocol_nodes_key(), algorithm()->get_node().protocol(), r,
		[this](node_endpoint const& nep) { algorithm()->traverse(nep.id, nep.ep); });

	// in case we didn't know the id of this peer when we sent the message to
	// it. For instance if it's a bootstrap node.
	set_id(from);
}

} // namespace libTAU::dht
