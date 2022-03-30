/*

Copyright (c) 2006, 2008-2009, 2013-2016, 2019-2020, Arvid Norberg
Copyright (c) 2015, Steven Siloti
Copyright (c) 2016, 2021, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef KADEMLIA_NODE_ENTRY_HPP
#define KADEMLIA_NODE_ENTRY_HPP

#include "libTAU/kademlia/node_id.hpp"
#include "libTAU/socket.hpp"
#include "libTAU/address.hpp"
#include "libTAU/aux_/union_endpoint.hpp"
#include "libTAU/time.hpp" // for time_point
#include "libTAU/aux_/time.hpp" // for time_now

namespace libTAU::dht {

struct TORRENT_EXPORT node_entry
{
	node_entry(node_id const& id_, udp::endpoint const& ep, int roundtriptime = 0xffff
		, bool pinged = false, bool non_referrable_ = false);
	explicit node_entry(udp::endpoint const& ep);
	node_entry() = default;
	void update_rtt(int new_rtt);

	bool pinged() const { return timeout_count != 0xff; }
	void set_pinged() { if (timeout_count == 0xff) timeout_count = 0; }
	void timed_out() { if (pinged() && timeout_count < 0xfe) ++timeout_count; }
	int fail_count() const { return pinged() ? timeout_count : 0; }
	void reset_fail_count() { if (pinged()) timeout_count = 0; }
	udp::endpoint ep() const { return endpoint; }
	bool confirmed() const { return timeout_count == 0; }
	address addr() const { return endpoint.address(); }
	int port() const { return endpoint.port; }

	// compares which node_entry is "better". Smaller is better
	bool operator<(node_entry const& rhs) const
	{
		return std::make_tuple(!verified, rtt) < std::make_tuple(!rhs.verified, rhs.rtt);
	}

	void invoke_failed()
	{
		invoke_fail_count++;
		last_invoke_failed = aux::time_now();
	}

	void update_endpoint(udp::endpoint const& ep) { endpoint = ep; }

	bool allow_invoke() const
	{
		return invoke_fail_count < 10
			|| last_invoke_failed + minutes(5) < aux::time_now();
	}

	void reset_invoke_failed()
	{
		invoke_fail_count = 0;
		last_invoke_failed = min_time();
	}

	void reset()
	{
#ifndef TORRENT_DISABLE_LOGGING
		first_seen = aux::time_now();
#endif

		last_queried = min_time();
		last_seen = min_time();
		rtt = 0xffff;
		timeout_count = 0xff;
		verified = false;
		last_invoke_failed = min_time();
		invoke_fail_count = 0;
		non_referrable = false;
	}

#ifndef TORRENT_DISABLE_LOGGING
	time_point first_seen = aux::time_now();
#endif

	// the time we last received a response for a request to this peer
	time_point last_queried = min_time();

	// this field is designed for non-referrable endpoint.
	// the time we last received a response for a request to this peer
	// or the time we last received a request from this peer
	time_point last_seen = min_time();

	node_id id{nullptr};

	aux::union_endpoint endpoint;

	// the average RTT of this node
	std::uint16_t rtt = 0xffff;

	// the number of times this node has failed to
	// respond in a row
	// 0xff is a special value to indicate we have not pinged this node yet
	std::uint8_t timeout_count = 0xff;

	bool verified = false;

	time_point last_invoke_failed = min_time();

	int invoke_fail_count = 0;

	bool non_referrable = false;
};

} // namespace libTAU::dht

#endif
