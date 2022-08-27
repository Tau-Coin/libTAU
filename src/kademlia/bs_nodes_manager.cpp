/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <libTAU/config.hpp>
#include "libTAU/hex.hpp"
#include <libTAU/aux_/string_util.hpp>
#include <libTAU/aux_/io_bytes.hpp>
#include <libTAU/aux_/session_settings.hpp>
#include <libTAU/aux_/socket_io.hpp> // for print_endpoint
#include <libTAU/aux_/time.hpp> // for aux::time_now
#include <libTAU/aux_/ip_helpers.hpp> // for is_v6

#include <libTAU/kademlia/bs_nodes_manager.hpp>
#include <libTAU/kademlia/node.hpp>

#include <type_traits>
#include <functional>
#include <filesystem>
#include <tuple>
#include <cstring>
#include <cstdio>
#include <unistd.h>

namespace libTAU::dht {

namespace {

	bool file_exists(std::string const& name)
	{
		if (access(name.c_str(), F_OK) == 0)
		{
			return true;
		}

		return false;
	}

}

bs_nodes_manager::bs_nodes_manager(std::string const& dir
	, bs_nodes_storage_interface& bs_nodes_storage
	, dht_logger* log)
	: m_dir(dir)
	, m_bs_nodes_storage(bs_nodes_storage)
#ifndef TORRENT_DISABLE_LOGGING
	, m_log(log)
#endif
{
#ifdef TORRENT_DISABLE_LOGGING
	TORRENT_UNUSED(log);
#endif

	m_need_upgrade = false;
}

void bs_nodes_manager::load_bootstrap_nodes()
{
	read_version_file();

	if (!m_need_upgrade)
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_INFO))
		{
			m_log->log(dht_logger::bs_nodes_db, "no need to upgrade");
		}
#endif

		return;
	}

	std::vector<std::tuple<std::string, int, std::string>> bs_nodes;
	std::vector<bs_node_entry> nodes;
	error_code err;

	libTAU::aux::parse_comma_separated_string_port_key(referred_bs_nodes, bs_nodes);
	for (auto& bsn : bs_nodes)
	{
		std::string ip = std::get<0>(bsn);
		int port = std::get<1>(bsn);
		std::string pubkey = std::get<2>(bsn);
		address const addr = make_address(ip.c_str(), err);
		if (err) continue;

		udp::endpoint ep(addr, std::uint16_t(port));

		if (pubkey.size() != 64) continue;
		sha256_hash nid;
		span<char const> hexseed(pubkey.c_str(), 64);
		aux::from_hex(hexseed, nid.data());

#ifndef TORRENT_DISABLE_LOGGING
		if (m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_INFO))
		{
			m_log->log(dht_logger::bs_nodes_db, "add referred bs node, nid:%s, ep:%s"
				, aux::to_hex(nid).c_str(), aux::print_endpoint(ep).c_str());
		}
#endif

		nodes.push_back(bs_node_entry(nid, ep));
	}

	m_bs_nodes_storage.put(nodes);
}

void bs_nodes_manager::read_version_file()
{
	if (!std::filesystem::is_directory(m_dir))
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
		{
			m_log->log(dht_logger::bs_nodes_db, "%s is not dir", m_dir.c_str());
		}
#endif

		return;
	}

	std::string file = m_dir;
	file.append(PATH_SEPARATOR);
	file.append(version_file_name);

	if (file_exists(file))
	{
		FILE* version_file = fopen(file.c_str(), "r+");
		if (version_file == NULL)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (m_log != NULL
				&& m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
			{
				m_log->log(dht_logger::bs_nodes_db, "open file error:%s"
					, file.c_str());
			}
#endif

			return;
		}

		std::string version;
		char buf[10] = {0};
		fscanf(version_file, "%s\n", buf);
		version.append(buf, strlen(buf));

		if (bs_nodes_version == version)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_INFO))
			{
				m_log->log(dht_logger::bs_nodes_db, "version not changed:%s"
					, version.c_str());
			}
#endif

			fclose(version_file);
			return;
		}

#ifndef TORRENT_DISABLE_LOGGING
		if (m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_INFO))
		{
			m_log->log(dht_logger::bs_nodes_db, "version changed: old:%s, new:%s"
				, version.c_str(), bs_nodes_version.c_str());
		}
#endif

		m_need_upgrade = true;

		// reopen file and truncate file
		fclose(version_file);
		version_file = fopen(file.c_str(), "w");
		if (version_file == NULL)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (m_log != NULL
				&& m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
			{
				m_log->log(dht_logger::bs_nodes_db, "reopen file error:%s"
					, file.c_str());
			}
#endif

			return;
		}

		fprintf(version_file, "%s\n", bs_nodes_version.c_str());
		fclose(version_file);
	}
	else
	{
#ifndef TORRENT_DISABLE_LOGGING
		if (m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_INFO))
		{
			m_log->log(dht_logger::bs_nodes_db, "version file not exist:%s", file.c_str());
		}
#endif

		m_need_upgrade = true;

		FILE* version_file = fopen(file.c_str(), "w");
		if (version_file == NULL)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (m_log != NULL
				&& m_log->should_log(dht_logger::bs_nodes_db, aux::LOG_ERR))
			{
				m_log->log(dht_logger::bs_nodes_db, "open file error:%s"
					, file.c_str());
			}
#endif

			return;
		}

		fprintf(version_file, "%s\n", bs_nodes_version.c_str());
		fclose(version_file);
	}
}

} // namespace libTAU::dht
