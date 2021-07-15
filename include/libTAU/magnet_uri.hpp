/*

Copyright (c) 2007-2009, 2012-2013, 2016-2020, Arvid Norberg
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_MAGNET_URI_HPP_INCLUDED
#define TORRENT_MAGNET_URI_HPP_INCLUDED

#include <string>
#include "libTAU/config.hpp"
#include "libTAU/torrent_handle.hpp"
#include "libTAU/add_torrent_params.hpp"
#include "libTAU/string_view.hpp"

namespace libTAU {

	struct torrent_handle;
	struct session;

	// Generates a magnet URI from the specified torrent. If the torrent
	// handle is invalid, an empty string is returned.
	//
	// For more information about magnet links, see magnet-links_.
	//
	TORRENT_EXPORT std::string make_magnet_uri(torrent_handle const& handle);
	TORRENT_EXPORT std::string make_magnet_uri(torrent_info const& info);

#if TORRENT_ABI_VERSION == 1
#ifndef BOOST_NO_EXCEPTIONS
	// deprecated in 0.14
	TORRENT_DEPRECATED_EXPORT
	torrent_handle add_magnet_uri(session& ses, std::string const& uri
		, std::string const& save_path
		, storage_mode_t storage_mode = storage_mode_sparse
		, bool paused = false
		, void* userdata = nullptr);

	// deprecated in 0.16. Instead, pass in the magnet link as add_torrent_params::url
	TORRENT_DEPRECATED_EXPORT
	torrent_handle add_magnet_uri(session& ses, std::string const& uri
		, add_torrent_params const& p);
#endif

	// deprecated in 0.16. Instead, pass in the magnet link as add_torrent_params::url
	TORRENT_DEPRECATED_EXPORT
	torrent_handle add_magnet_uri(session& ses, std::string const& uri
		, add_torrent_params const& p, error_code& ec);
#endif // TORRENT_ABI_VERSION


	// This function parses out information from the magnet link and populates the
	// add_torrent_params object. The overload that does not take an
	// ``error_code`` reference will throw a system_error on error
	// The overload taking an ``add_torrent_params`` reference will fill in the
	// fields specified in the magnet URI.
	TORRENT_EXPORT add_torrent_params parse_magnet_uri(string_view uri, error_code& ec);
	TORRENT_EXPORT add_torrent_params parse_magnet_uri(string_view uri);
	TORRENT_EXPORT void parse_magnet_uri(string_view uri, add_torrent_params& p, error_code& ec);
}

#endif