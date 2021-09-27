/*

Copyright (c) 2015, Steven Siloti
Copyright (c) 2016-2018, Alden Torres
Copyright (c) 2019-2020, Arvid Norberg
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_SESSION_PARAMS_HPP_INCLUDED
#define TORRENT_SESSION_PARAMS_HPP_INCLUDED

#include <functional>
#include <memory>
#include <vector>

#include "libTAU/config.hpp"
#include "libTAU/aux_/export.hpp"
#include "libTAU/settings_pack.hpp"
#include "libTAU/io_context.hpp"
#include "libTAU/kademlia/dht_state.hpp"
#include "libTAU/session_types.hpp"
#include "libTAU/kademlia/dht_storage.hpp"
#include "libTAU/ip_filter.hpp"
#include "libTAU/session_types.hpp" // for session_flags_t

#if TORRENT_ABI_VERSION <= 2
#include "libTAU/kademlia/dht_settings.hpp"
#endif

namespace libTAU {

struct plugin;
struct counters;

// The session_params is a parameters pack for configuring the session
// before it's started.
struct TORRENT_EXPORT session_params
{
	// This constructor can be used to start with the default plugins
	// (ut_metadata, ut_pex and smart_ban). Pass a settings_pack to set the
	// initial settings when the session starts.
	session_params(settings_pack&& sp); // NOLINT
	session_params(settings_pack const& sp); // NOLINT
	session_params();

	// hidden
	~session_params();

	// This constructor helps to configure the set of initial plugins
	// to be added to the session before it's started.
	session_params(settings_pack&& sp
		, std::vector<std::shared_ptr<plugin>> exts);
	session_params(settings_pack const& sp
		, std::vector<std::shared_ptr<plugin>> exts);

	// hidden
	session_params(session_params const&);
	session_params(session_params&&);
	session_params& operator=(session_params const&) &;
	session_params& operator=(session_params&&) &;

	// The settings to configure the session with
	settings_pack settings;

	// specifies flags affecting the session construction. E.g. they can be used
	// to start a session in paused mode (by passing in ``session::paused``).
	session_flags_t flags{};

	// the plugins to add to the session as it is constructed
	std::vector<std::shared_ptr<plugin>> extensions;

	// DHT node ID and node addresses to bootstrap the DHT with.
	dht::dht_state dht_state;

	// function object to construct the storage object for DHT items.
	dht::dht_storage_constructor_type dht_storage_constructor;

	// this container can be used by extensions/plugins to store settings. It's
	// primarily here to make it convenient to save and restore state across
	// sessions, using read_session_params() and write_session_params().
	std::map<std::string, std::string> ext_state;

	// the IP filter to use for the session. This restricts which peers are allowed
	// to connect. As if passed to set_ip_filter().
	libTAU::ip_filter ip_filter;

#if TORRENT_ABI_VERSION <= 2

#include "libTAU/aux_/disable_deprecation_warnings_push.hpp"

	// this is deprecated. Use the dht_* settings instead.
	dht::dht_settings dht_settings;

#include "libTAU/aux_/disable_warnings_pop.hpp"

#endif
};

// These functions serialize and de-serialize a ``session_params`` object to and
// from bencoded form. The session_params object is used to initialize a new
// session using the state from a previous one (or by programmatically configure
// the session up-front).
// The flags parameter can be used to only save and load certain aspects of the
// session's state.
// The ``_buf`` suffix indicates the function operates on buffer rather than the
// bencoded structure.
// The torrents in a session are not part of the session_params state, they have
// to be restored separately.
TORRENT_EXPORT session_params read_session_params(bdecode_node const& e
	, save_state_flags_t flags = save_state_flags_t::all());
TORRENT_EXPORT session_params read_session_params(span<char const> buf
	, save_state_flags_t flags = save_state_flags_t::all());
TORRENT_EXPORT entry write_session_params(session_params const& sp
	, save_state_flags_t flags = save_state_flags_t::all());
TORRENT_EXPORT std::vector<char> write_session_params_buf(session_params const& sp
	, save_state_flags_t flags = save_state_flags_t::all());

}

#endif
