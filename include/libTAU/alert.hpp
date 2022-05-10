/*

Copyright (c) 2003, Daniel Wallin
Copyright (c) 2004, Magnus Jonsson
Copyright (c) 2004-2005, 2008-2009, 2013-2020, Arvid Norberg
Copyright (c) 2016, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_ALERT_HPP_INCLUDED
#define TORRENT_ALERT_HPP_INCLUDED

#include <string>

// OVERVIEW
//
// The pop_alerts() function on session is the main interface for retrieving
// alerts (warnings, messages and errors from libTAU). If no alerts have
// been posted by libTAU pop_alerts() will return an empty list.
//
// By default, only errors are reported. settings_pack::alert_mask can be
// used to specify which kinds of events should be reported. The alert mask is
// a combination of the alert_category_t flags in the alert class.
//
// Every alert belongs to one or more category. There is a cost associated with
// posting alerts. Only alerts that belong to an enabled category are
// posted. Setting the alert bitmask to 0 will disable all alerts (except those
// that are non-discardable). Alerts that are responses to API calls such as
// save_resume_data() and post_session_stats() are non-discardable and will be
// posted even if their category is disabled.
//
// There are other alert base classes that some alerts derive from, all the
// alerts that are generated for a specific torrent are derived from
// torrent_alert, and tracker events derive from tracker_alert.
//
// Alerts returned by pop_alerts() are only valid until the next call to
// pop_alerts(). You may not copy an alert object to access it after the next
// call to pop_alerts(). Internal members of alerts also become invalid once
// pop_alerts() is called again.

#include "libTAU/time.hpp"
#include "libTAU/config.hpp"
#include "libTAU/flags.hpp"

namespace libTAU {

// bitmask type used to define alert categories. Categories can be enabled
// and disabled by the settings_pack::alert_mask setting. Constants are defined
// in the lt::alert_category namespace
using alert_category_t = flags::bitfield_flag<std::uint32_t, struct alert_category_tag>;

namespace alert_category {

	// Enables alerts that report an error. This includes:
	//
	// * tracker errors
	// * tracker warnings
	// * file errors
	// * resume data failures
	// * web seed errors
	// * .torrent files errors
	// * listen socket errors
	// * port mapping errors
	inline constexpr alert_category_t error = 0_bit;

	// Enables alerts when peers send invalid requests, get banned or
	// snubbed.
	inline constexpr alert_category_t peer = 1_bit;

	// Enables alerts for port mapping events. For NAT-PMP and UPnP.
	inline constexpr alert_category_t port_mapping = 2_bit;

	// Enables alerts for when a torrent or the session changes state.
	inline constexpr alert_category_t status = 6_bit;

	// Alerts on events in the DHT node. For incoming searches or
	// bootstrapping being done etc.
	inline constexpr alert_category_t dht = 9_bit;

	// Enables debug logging alerts. These are available unless libTAU
	// was built with logging disabled (``TORRENT_DISABLE_LOGGING``). The
	// alerts being posted are log_alert and are session wide.
	inline constexpr alert_category_t session_log = 11_bit;

	// enables dht_log_alert, debug logging for the DHT
	inline constexpr alert_category_t dht_log = 15_bit;

	// enable events from pure dht operations not related to torrents
	inline constexpr alert_category_t dht_operation = 16_bit;

	// enables port mapping log events. This log is useful
	// for debugging the UPnP or NAT-PMP implementation
	inline constexpr alert_category_t port_mapping_log = 17_bit;

	// alerts on events in communication
    inline constexpr alert_category_t communication = 23_bit;

    // alerts on communication log
    inline constexpr alert_category_t communication_log = 24_bit;

    // alerts on events in blockchain
    inline constexpr alert_category_t blockchain = 25_bit;

    // alerts on blockchain log
    inline constexpr alert_category_t blockchain_log = 26_bit;

	// The full bitmask, representing all available categories.
	//
	// since the enum is signed, make sure this isn't
	// interpreted as -1. For instance, boost.python
	// does that and fails when assigning it to an
	// unsigned parameter.
	inline constexpr alert_category_t all = alert_category_t::all();

} // namespace alert_category

#include "libTAU/aux_/disable_deprecation_warnings_push.hpp"

	// The ``alert`` class is the base class that specific messages are derived from.
	// alert types are not copyable, and cannot be constructed by the client. The
	// pointers returned by libTAU are short lived (the details are described
	// under session_handle::pop_alerts())
	struct TORRENT_EXPORT alert
	{
#include "libTAU/aux_/disable_warnings_pop.hpp"

		// hidden
		TORRENT_UNEXPORT alert(alert const& rhs) = delete;
		alert& operator=(alert const&) = delete;
		alert(alert&& rhs) noexcept = default;

		static inline constexpr alert_category_t error_notification = 0_bit;
		static inline constexpr alert_category_t peer_notification = 1_bit;
		static inline constexpr alert_category_t port_mapping_notification = 2_bit;
		static inline constexpr alert_category_t status_notification = 6_bit;
		static inline constexpr alert_category_t dht_notification = 9_bit;
		static inline constexpr alert_category_t session_log_notification = 11_bit;
		static inline constexpr alert_category_t dht_log_notification = 15_bit;
		static inline constexpr alert_category_t dht_operation_notification = 16_bit;
		static inline constexpr alert_category_t port_mapping_log_notification = 17_bit;
		static inline constexpr alert_category_t communication_notification = 23_bit;
		static inline constexpr alert_category_t communication_log_notification = 24_bit;
		static inline constexpr alert_category_t blockchain_notification = 25_bit;
		static inline constexpr alert_category_t blockchain_log_notification = 26_bit;
		static inline constexpr alert_category_t all_categories = alert_category_t::all();

		// hidden
		TORRENT_UNEXPORT alert();
		// hidden
		virtual ~alert();

		// a timestamp is automatically created in the constructor
		time_point timestamp() const;

		// returns an integer that is unique to this alert type. It can be
		// compared against a specific alert by querying a static constant called ``alert_type``
		// in the alert. It can be used to determine the run-time type of an alert* in
		// order to cast to that alert type and access specific members.
		//
		// e.g:
		//
		// .. code:: c++
		//
		//	std::vector<alert*> alerts;
		//	ses.pop_alerts(&alerts);
		//	for (alert* a : alerts) {
		//		switch (a->type()) {
		//
		//			case read_piece_alert::alert_type:
		//			{
		//				auto* p = static_cast<read_piece_alert*>(a);
		//				if (p->ec) {
		//					// read_piece failed
		//					break;
		//				}
		//				// use p
		//				break;
		//			}
		//			case file_renamed_alert::alert_type:
		//			{
		//				// etc...
		//			}
		//		}
		//	}
		virtual int type() const noexcept = 0;

		// returns a string literal describing the type of the alert. It does
		// not include any information that might be bundled with the alert.
		virtual char const* what() const noexcept = 0;

		// generate a string describing the alert and the information bundled
		// with it. This is mainly intended for debug and development use. It is not suitable
		// to use this for applications that may be localized. Instead, handle each alert
		// type individually and extract and render the information from the alert depending
		// on the locale.
		virtual std::string message() const = 0;

		// returns a bitmask specifying which categories this alert belong to.
		virtual alert_category_t category() const noexcept = 0;

	private:
		time_point const m_timestamp;
	};

// When you get an alert, you can use ``alert_cast<>`` to attempt to cast the
// pointer to a specific alert type, in order to query it for more
// information.
//
// .. note::
//   ``alert_cast<>`` can only cast to an exact alert type, not a base class
template <typename T> T* alert_cast(alert* a)
{
	static_assert(std::is_base_of<alert, T>::value
		, "alert_cast<> can only be used with alert types (deriving from lt::alert)");

	if (a == nullptr) return nullptr;
	if (a->type() == T::alert_type) return static_cast<T*>(a);
	return nullptr;
}
template <typename T> T const* alert_cast(alert const* a)
{
	static_assert(std::is_base_of<alert, T>::value
		, "alert_cast<> can only be used with alert types (deriving from lt::alert)");
	if (a == nullptr) return nullptr;
	if (a->type() == T::alert_type) return static_cast<T const*>(a);
	return nullptr;
}

} // namespace libTAU

#endif // TORRENT_ALERT_HPP_INCLUDED
