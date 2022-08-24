/*

Copyright (c) 2022, Xianshui Sheng
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BOOTSTRAP_NODES_MANAGER_HPP
#define LIBTAU_BOOTSTRAP_NODES_MANAGER_HPP

#include <libTAU/socket.hpp>

#include <libTAU/kademlia/node_id.hpp>
#include <libTAU/kademlia/bs_nodes_storage.hpp>

#if defined(WIN32) || defined(_WIN32)
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

namespace libTAU {
namespace dht {

	static const std::string bs_nodes_version = "v0.01";
	static const std::string version_file_name = "bsn_version";

	static const std::string referred_bs_nodes = "";

		/*
		"tau://17C7EE719346488605DA6F5227377D0196DCE02841D0681A0E55BE5B44DD37B5@192.168.0.1:6681,"
		 "tau://a47a91e68dd4426f5b1492f67d02168bc4250fa5c3da2ffdccc7fc2d24a4fdc8@192.168.0.2:6882,"
		 "tau://a47a91e68dd4426f5b1492f67d02168bc4250fa5c3da2ffdccc7fc2d24a4fdc3@192.168.0.2:6883,"
		 "tau://a47a91e68dd4426f5b1492f67d02168bc4250fa5c3da2ffdccc7fc2d24a4fdc4@192.168.0.2:6884,"
		 "tau://a47a91e68dd4426f5b1492f67d02168bc4250fa5c3da2ffdccc7fc2d24a4fdc5@192.168.0.2:6885,"
		 "tau://a47a91e68dd4426f5b1492f67d02168bc4250fa5c3da2ffdccc7fc2d24a4fdc6@192.168.0.2:6886,"
		 "tau://a47a91e68dd4426f5b1492f67d02168bc4250fa5c3da2ffdccc7fc2d24a4fdc7@192.168.0.2:6887";
		 */

class TORRENT_EXTRA_EXPORT bs_nodes_manager
{
public:

	bs_nodes_manager(std::string const& dir
		, bs_nodes_storage_interface& bs_nodes_storage
		, dht_logger* log);

	void load_bootstrap_nodes();

private:

	void read_version_file();

	std::string m_dir;

	bool m_need_upgrade = false;

#ifndef TORRENT_DISABLE_LOGGING
	dht_logger* m_log;
#endif

	bs_nodes_storage_interface& m_bs_nodes_storage;
};

} // namespace dht
} // namespace libTAU

#endif // LIBTAU_BOOTSTRAP_NODES_MANAGER_HPP
