/*

Copyright (c) 2009, 2017, 2019-2020, Arvid Norberg
Copyright (c) 2016, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_ERROR_HPP_INCLUDED
#define TORRENT_ERROR_HPP_INCLUDED

#include "libTAU/config.hpp"

#include "libTAU/aux_/disable_warnings_push.hpp"
#if defined TORRENT_WINDOWS || defined TORRENT_CYGWIN
// asio assumes that the windows error codes are defined already
#include <winsock2.h>
#endif

#include <boost/asio/error.hpp>
#include "libTAU/aux_/disable_warnings_pop.hpp"

namespace libTAU {

	namespace error = boost::asio::error;
}

#endif
