/*

Copyright (c) 2014, 2017, 2019-2020, Arvid Norberg
Copyright (c) 2021, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/peer_class.hpp"

namespace libTAU {

	void peer_class::set_upload_limit(int limit)
	{
	}

	void peer_class::set_download_limit(int limit)
	{
	}

	void peer_class::get_info(peer_class_info* pci) const
	{
	}

	void peer_class::set_info(peer_class_info const* pci)
	{
	}

	peer_class_t peer_class_pool::new_peer_class(std::string label)
	{
		peer_class_t ret{0};
		if (!m_free_list.empty())
		{
			ret = m_free_list.back();
			m_free_list.pop_back();
			m_peer_classes[ret] = peer_class(std::move(label));
		}
		else
		{
			ret = m_peer_classes.end_index();
			m_peer_classes.emplace_back(std::move(label));
		}

		return ret;
	}

	void peer_class_pool::decref(peer_class_t c)
	{
		TORRENT_ASSERT(c < m_peer_classes.end_index());
		TORRENT_ASSERT(m_peer_classes[c].in_use);
		TORRENT_ASSERT(m_peer_classes[c].references > 0);

		--m_peer_classes[c].references;
		if (m_peer_classes[c].references) return;
		m_peer_classes[c].clear();
		m_free_list.push_back(c);
	}

	void peer_class_pool::incref(peer_class_t c)
	{
		TORRENT_ASSERT(c < m_peer_classes.end_index());
		TORRENT_ASSERT(m_peer_classes[c].in_use);

		++m_peer_classes[c].references;
	}

	peer_class* peer_class_pool::at(peer_class_t c)
	{
		if (c >= m_peer_classes.end_index() || !m_peer_classes[c].in_use) return nullptr;
		return &m_peer_classes[c];
	}

	peer_class const* peer_class_pool::at(peer_class_t c) const
	{
		if (c >= m_peer_classes.end_index() || !m_peer_classes[c].in_use) return nullptr;
		return &m_peer_classes[c];
	}
}
