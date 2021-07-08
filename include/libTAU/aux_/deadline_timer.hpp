/*

Copyright (c) 2009, 2015, 2017-2020, Arvid Norberg
Copyright (c) 2016, 2021, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_DEADLINE_TIMER_HPP_INCLUDED
#define TORRENT_DEADLINE_TIMER_HPP_INCLUDED

#include "libTAU/config.hpp"

#if defined TORRENT_BUILD_SIMULATOR
#include "simulator/simulator.hpp"
#else
#include "libTAU/aux_/disable_warnings_push.hpp"
#include <boost/asio/high_resolution_timer.hpp>
#include "libTAU/aux_/disable_warnings_pop.hpp"
#endif // SIMULATOR

namespace libTAU::aux {

#if defined TORRENT_BUILD_SIMULATOR
	using deadline_timer = sim::asio::high_resolution_timer;
#else
	using deadline_timer = boost::asio::high_resolution_timer;
#endif
}

#endif // TORRENT_DEADLINE_TIMER_HPP_INCLUDED
