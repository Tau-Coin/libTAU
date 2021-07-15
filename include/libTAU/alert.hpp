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

	// Enables alerts for events related to the storage. File errors and
	// synchronization events for moving the storage, renaming files etc.
	inline constexpr alert_category_t storage = 3_bit;

	// Enables all tracker events. Includes announcing to trackers,
	// receiving responses, warnings and errors.
	inline constexpr alert_category_t tracker = 4_bit;

	// Low level alerts for when peers are connected and disconnected.
	inline constexpr alert_category_t connect = 5_bit;

		// Enables alerts for when a torrent or the session changes state.
	inline constexpr alert_category_t status = 6_bit;

	// Alerts when a peer is blocked by the ip blocker or port blocker.
	inline constexpr alert_category_t ip_block = 7_bit;

	// Alerts when some limit is reached that might limit the download
	// or upload rate.
	inline constexpr alert_category_t performance_warning = 8_bit;

	// Alerts on events in the DHT node. For incoming searches or
	// bootstrapping being done etc.
	inline constexpr alert_category_t dht = 9_bit;

	// If you enable these alerts, you will receive a stats_alert
	// approximately once every second, for every active torrent.
	// These alerts contain all statistics counters for the interval since
	// the lasts stats alert.
	inline constexpr alert_category_t stats = 10_bit;

	// Enables debug logging alerts. These are available unless libTAU
	// was built with logging disabled (``TORRENT_DISABLE_LOGGING``). The
	// alerts being posted are log_alert and are session wide.
	inline constexpr alert_category_t session_log = 11_bit;

	// Enables debug logging alerts for torrents. These are available
	// unless libTAU was built with logging disabled
	// (``TORRENT_DISABLE_LOGGING``). The alerts being posted are
	// torrent_log_alert and are torrent wide debug events.
	inline constexpr alert_category_t torrent_log = 12_bit;

	// Enables debug logging alerts for peers. These are available unless
	// libTAU was built with logging disabled
	// (``TORRENT_DISABLE_LOGGING``). The alerts being posted are
	// peer_log_alert and low-level peer events and messages.
	inline constexpr alert_category_t peer_log = 13_bit;

	// enables the incoming_request_alert.
	inline constexpr alert_category_t incoming_request = 14_bit;

	// enables dht_log_alert, debug logging for the DHT
	inline constexpr alert_category_t dht_log = 15_bit;

	// enable events from pure dht operations not related to torrents
	inline constexpr alert_category_t dht_operation = 16_bit;

	// enables port mapping log events. This log is useful
	// for debugging the UPnP or NAT-PMP implementation
	inline constexpr alert_category_t port_mapping_log = 17_bit;

	// enables verbose logging from the piece picker.
	inline constexpr alert_category_t picker_log = 18_bit;

	// alerts when files complete downloading
	inline constexpr alert_category_t file_progress = 19_bit;

	// alerts when pieces complete downloading or fail hash check
	inline constexpr alert_category_t piece_progress = 20_bit;

	// alerts when we upload blocks to other peers
	inline constexpr alert_category_t upload = 21_bit;

	// alerts on individual blocks being requested, downloading, finished,
	// rejected, time-out and cancelled. This is likely to post alerts at a
	// high rate.
	inline constexpr alert_category_t block_progress = 22_bit;

	// alerts on events in communication
    inline constexpr alert_category_t communication = 23_bit;

    // alerts on communication log
    inline constexpr alert_category_t communication_log = 24_bit;

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

#if TORRENT_ABI_VERSION == 1
		using category_t = alert_category_t;
#endif

		static inline constexpr alert_category_t error_notification = 0_bit;
		static inline constexpr alert_category_t peer_notification = 1_bit;
		static inline constexpr alert_category_t port_mapping_notification = 2_bit;
		static inline constexpr alert_category_t storage_notification = 3_bit;
		static inline constexpr alert_category_t tracker_notification = 4_bit;
		static inline constexpr alert_category_t connect_notification = 5_bit;
#if TORRENT_ABI_VERSION == 1
		TORRENT_DEPRECATED
		static inline constexpr alert_category_t debug_notification = connect_notification;
#endif
		static inline constexpr alert_category_t status_notification = 6_bit;
#if TORRENT_ABI_VERSION == 1
		// Alerts for when blocks are requested and completed. Also when
		// pieces are completed.
		TORRENT_DEPRECATED
		static inline constexpr alert_category_t progress_notification = 7_bit;
#endif
		static inline constexpr alert_category_t ip_block_notification = 8_bit;
		static inline constexpr alert_category_t performance_warning = 9_bit;
		static inline constexpr alert_category_t dht_notification = 10_bit;

#if TORRENT_ABI_VERSION <= 2
		// If you enable these alerts, you will receive a stats_alert
		// approximately once every second, for every active torrent.
		// These alerts contain all statistics counters for the interval since
		// the lasts stats alert.
		TORRENT_DEPRECATED
		static inline constexpr alert_category_t stats_notification = 11_bit;
#endif
		static inline constexpr alert_category_t session_log_notification = 13_bit;
		static inline constexpr alert_category_t torrent_log_notification = 14_bit;
		static inline constexpr alert_category_t peer_log_notification = 15_bit;
		static inline constexpr alert_category_t incoming_request_notification = 16_bit;
		static inline constexpr alert_category_t dht_log_notification = 17_bit;
		static inline constexpr alert_category_t dht_operation_notification = 18_bit;
		static inline constexpr alert_category_t port_mapping_log_notification = 19_bit;
		static inline constexpr alert_category_t picker_log_notification = 20_bit;
		static inline constexpr alert_category_t file_progress_notification = 21_bit;
		static inline constexpr alert_category_t piece_progress_notification = 22_bit;
		static inline constexpr alert_category_t upload_notification = 23_bit;
		static inline constexpr alert_category_t block_progress_notification = 24_bit;
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