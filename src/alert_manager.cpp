/*

Copyright (c) 2003-2013, Daniel Wallin
Copyright (c) 2013-2020, Arvid Norberg
Copyright (c) 2015, Steven Siloti
Copyright (c) 2016, 2020, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/config.hpp"
#include "libTAU/aux_/alert_manager.hpp"
#include "libTAU/alert_types.hpp"

namespace libTAU {
namespace aux {

	alert_manager::alert_manager(int const queue_limit, alert_category_t const alert_mask)
		: m_alert_mask(alert_mask)
		, m_queue_size_limit(queue_limit)
	{}

	alert_manager::~alert_manager() = default;

	alert* alert_manager::wait_for_alert(time_duration max_wait)
	{
		std::unique_lock<std::recursive_mutex> lock(m_mutex);

		if (!m_alerts[m_generation].empty())
			return m_alerts[m_generation].front();

		// this call can be interrupted prematurely by other signals
		m_condition.wait_for(lock, max_wait);
		if (!m_alerts[m_generation].empty())
			return m_alerts[m_generation].front();

		return nullptr;
	}

	void alert_manager::maybe_notify(alert* a)
	{
		if (m_alerts[m_generation].size() == 1)
		{
			// we just posted to an empty queue. If anyone is waiting for
			// alerts, we need to notify them. Also (potentially) call the
			// user supplied m_notify callback to let the client wake up its
			// message loop to poll for alerts.
			if (m_notify) m_notify();

			// TODO: 2 keep a count of the number of threads waiting. Only if it's
			// > 0 notify them
			m_condition.notify_all();
		}

		TORRENT_UNUSED(a);
	}

	void alert_manager::set_notify_function(std::function<void()> const& fun)
	{
		std::unique_lock<std::recursive_mutex> lock(m_mutex);
		m_notify = fun;
		if (!m_alerts[m_generation].empty())
		{
			if (m_notify) m_notify();
		}
	}

	void alert_manager::get_all(std::vector<alert*>& alerts)
	{
		std::lock_guard<std::recursive_mutex> lock(m_mutex);

		if (m_alerts[m_generation].empty())
		{
			alerts.clear();
			return;
		}

		if (m_dropped.any()) {
			emplace_alert<alerts_dropped_alert>(m_dropped);
			m_dropped.reset();
		}

		m_alerts[m_generation].get_pointers(alerts);

		// swap buffers
		m_generation = (m_generation + 1) & 1;
		// clear the one we will start writing to now
		m_alerts[m_generation].clear();
		m_allocations[m_generation].reset();
	}

	bool alert_manager::pending() const
	{
		std::lock_guard<std::recursive_mutex> lock(m_mutex);
		return !m_alerts[m_generation].empty();
	}

	int alert_manager::set_alert_queue_size_limit(int queue_size_limit_)
	{
		std::lock_guard<std::recursive_mutex> lock(m_mutex);

		std::swap(m_queue_size_limit, queue_size_limit_);
		return queue_size_limit_;
	}
}
}
