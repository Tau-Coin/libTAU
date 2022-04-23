/*

Copyright (c) 2015-2018, 2020-2021, Alden Torres
Copyright (c) 2015-2020, Arvid Norberg
Copyright (c) 2015, Thomas Yuan
Copyright (c) 2016, Steven Siloti
Copyright (c) 2017, Andrei Kurushin
Copyright (c) 2018, Amir Abrams
Copyright (c) 2020, Rosen Penev
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/kademlia/dht_storage.hpp"
#include "libTAU/kademlia/node_entry.hpp"
#include "libTAU/settings_pack.hpp"

#include <tuple>
#include <algorithm>
#include <utility>
#include <map>
#include <set>
#include <string>

#include <libTAU/aux_/socket_io.hpp>
#include <libTAU/aux_/time.hpp>
#include <libTAU/config.hpp>
#include <libTAU/aux_/bloom_filter.hpp>
#include <libTAU/aux_/random.hpp>
#include <libTAU/aux_/vector.hpp>
#include <libTAU/aux_/numeric_cast.hpp>
#include <libTAU/aux_/ip_helpers.hpp> // for is_v4
#include <libTAU/bdecode.hpp>

namespace libTAU::dht {
namespace {

	bool compare(const char *a, const char *b, int offset)
	{
		int i = 0;

		for (; i < offset && *(a + i) != '\0' && *(b + i) != '\0'; i++)
		{
			if (*(a + i) != *(b + i)) return 1;
		}

		if (i < offset) return 1;

		return 0;
	}

	struct dht_immutable_item
	{
		// the actual value
		std::unique_ptr<char[]> value;
		// this counts the number of IPs we have seen
		// announcing this item, this is used to determine
		// popularity if we reach the limit of items to store
		aux::bloom_filter<128> ips;
		// the last time we heard about this item
		// the correct interpretation of this field
		// requires a time reference
		time_point last_seen;
		// number of IPs in the bloom filter
		int num_announcers = 0;
		// size of malloced space pointed to by value
		int size = 0;
	};

	struct dht_mutable_item : dht_immutable_item
	{
		signature sig{};
		timestamp ts{};
		public_key key{};
		std::string salt;
	};

	void set_value(dht_immutable_item& item, span<char const> buf)
	{
		int const size = int(buf.size());
		if (item.size != size)
		{
			item.value.reset(new char[std::size_t(size)]);
			item.size = size;
		}
		std::copy(buf.begin(), buf.end(), item.value.get());
	}

	void touch_item(dht_immutable_item& f, address const& addr)
	{
		f.last_seen = aux::time_now();

		// maybe increase num_announcers if we haven't seen this IP before
		sha1_hash const iphash = aux::hash_address(addr);
		if (!f.ips.find(iphash))
		{
			f.ips.set(iphash);
			++f.num_announcers;
		}
	}

	// return true of the first argument is a better candidate for removal, i.e.
	// less important to keep
	struct immutable_item_comparator
	{
		explicit immutable_item_comparator(std::vector<node_id> const& node_ids) : m_node_ids(node_ids) {}
		immutable_item_comparator(immutable_item_comparator const&) = default;

		// explicitly disallow assignment, to silence msvc warning
		immutable_item_comparator& operator=(immutable_item_comparator const&) = delete;

		template <typename Item>
		bool operator()(std::pair<node_id const, Item> const& lhs
			, std::pair<node_id const, Item> const& rhs) const
		{
			int const l_distance = min_distance_exp(lhs.first, m_node_ids);
			int const r_distance = min_distance_exp(rhs.first, m_node_ids);

			// this is a score taking the popularity (number of announcers) and the
			// fit, in terms of distance from ideal storing node, into account.
			// each additional 5 announcers is worth one extra bit in the distance.
			// that is, an item with 10 announcers is allowed to be twice as far
			// from another item with 5 announcers, from our node ID. Twice as far
			// because it gets one more bit.
			return lhs.second.num_announcers / 5 - l_distance < rhs.second.num_announcers / 5 - r_distance;
		}

	private:

		std::vector<node_id> const& m_node_ids;
	};

	// picks the least important one (i.e. the one
	// the fewest peers are announcing, and farthest
	// from our node IDs)
	template<class Item>
	typename std::map<node_id, Item>::const_iterator pick_least_important_item(
		std::vector<node_id> const& node_ids, std::map<node_id, Item> const& table)
	{
		return std::min_element(table.begin(), table.end()
			, immutable_item_comparator(node_ids));
	}

	struct relays_bucket
	{
		static constexpr int relays_max_size = 8;

		// endpoints
		std::vector<node_entry> relays;

		// the last time when some endpoint is referred
		time_point last_queried;

		void referred(node_entry& e)
		{
			last_queried = aux::time_now();

			auto it = std::find_if(relays.begin(), relays.end(),
				[&e](node_entry const& ne)
				{ return ne.id == e.id; });
			if (it != relays.end())
			{
				if (it->ep() != e.ep())
				{
					it->endpoint = e.endpoint;
				}

				it->last_queried = aux::time_now();
				return;
			}

			e.last_queried = aux::time_now();

			if (relays.size() == relays_max_size)
			{
				// remove the oldest node entry
				auto min_it = std::min_element(relays.begin(), relays.end(),
					[](node_entry const& lhs, node_entry const& rhs)
					{ return lhs.last_queried < rhs.last_queried; });
				TORRENT_ASSERT(min_it != relays.end());
				relays.erase(min_it);
			}

			relays.push_back(e);
		}

		void find_node(std::vector<node_entry>& l, int count)
		{
			l.clear();
			if (relays.empty()) return;

			auto it = std::max_element(relays.begin(), relays.end(),
				[](node_entry const& lhs, node_entry const& rhs)
				{ return lhs.last_queried < rhs.last_queried; });
			l.push_back({it->id, it->ep()});
		}
	};

	class dht_default_storage final : public dht_storage_interface
	{
	public:

		explicit dht_default_storage(settings_interface const& settings)
			: m_settings(settings)
		{
			m_counters.reset();
		}

		~dht_default_storage() override = default;

		dht_default_storage(dht_default_storage const&) = delete;
		dht_default_storage& operator=(dht_default_storage const&) = delete;

		void update_node_ids(std::vector<node_id> const& ids) override
		{
			m_node_ids = ids;
		}

		bool get_immutable_item(sha256_hash const& target
			, entry& item) const override
		{
			auto const i = m_immutable_table.find(target);
			if (i == m_immutable_table.end()) return false;

			error_code ec;
			item["v"] = bdecode({i->second.value.get(), i->second.size}, ec);
			return true;
		}

		void put_immutable_item(sha256_hash const& target
			, span<char const> buf
			, address const& addr) override
		{
			TORRENT_ASSERT(!m_node_ids.empty());
			auto i = m_immutable_table.find(target);
			if (i == m_immutable_table.end())
			{
				// make sure we don't add too many items
				if (int(m_immutable_table.size()) >= m_settings.get_int(settings_pack::dht_max_dht_items))
				{
					auto const j = pick_least_important_item(m_node_ids
						, m_immutable_table);

					TORRENT_ASSERT(j != m_immutable_table.end());
					m_immutable_table.erase(j);
					m_counters.immutable_data -= 1;
				}
				dht_immutable_item to_add;
				set_value(to_add, buf);

				std::tie(i, std::ignore) = m_immutable_table.insert(
					std::make_pair(target, std::move(to_add)));
				m_counters.immutable_data += 1;
			}

//			std::fprintf(stderr, "added immutable item (%d)\n", int(m_immutable_table.size()));

			touch_item(i->second, addr);
		}

		bool get_mutable_item_timestamp(sha256_hash const& target
			, timestamp& ts) const override
		{
			auto const i = m_mutable_table.find(target);
			if (i == m_mutable_table.end()) return false;

			ts = i->second.ts;
			return true;
		}

		bool get_mutable_item(sha256_hash const& target
			, timestamp const ts, bool const force_fill
			, entry& item) const override
		{
			auto const i = m_mutable_table.find(target);
			if (i == m_mutable_table.end()) return false;

			dht_mutable_item const& f = i->second;
			item["ts"] = f.ts.value;
			if (force_fill || (timestamp(0) <= ts && ts < f.ts))
			{
				error_code ec;
				item["v"] = bdecode({f.value.get(), f.size}, ec);
				item["sig"] = f.sig.bytes;
				item["k"] = f.key.bytes;
				item["salt"] = f.salt;
			}
			return true;
		}

		bool get_mutable_item_target(sha256_hash const& prefix
			, sha256_hash& target) const override
		{
			if (m_mutable_table.empty()) return false;

			std::vector<sha256_hash> candidates;

			for (auto it = m_mutable_table.upper_bound(prefix);
				it != m_mutable_table.end()
					&& compare(prefix.data(), it->first.data(), 16) == 0;
				it++)
			{
				candidates.push_back(it->first);
			}

			if (candidates.empty()) return false;

			// randomly select a item target
			std::uint32_t random_max = std::uint32_t(candidates.size() - 1);
			std::uint32_t const r = aux::random(random_max);
			target = candidates[r];

			return true;
		}

		void put_mutable_item(sha256_hash const& target
			, span<char const> buf
			, signature const& sig
			, timestamp const ts
			, public_key const& pk
			, span<char const> salt
			, address const& addr) override
		{
			TORRENT_ASSERT(!m_node_ids.empty());
			auto i = m_mutable_table.find(target);
			if (i == m_mutable_table.end())
			{
				// this is the case where we don't have an item in this slot
				// make sure we don't add too many items
				if (int(m_mutable_table.size()) >= m_settings.get_int(settings_pack::dht_max_dht_items))
				{
					auto const j = pick_least_important_item(m_node_ids
						, m_mutable_table);

					TORRENT_ASSERT(j != m_mutable_table.end());
					m_mutable_table.erase(j);
					m_counters.mutable_data -= 1;
				}
				dht_mutable_item to_add;
				set_value(to_add, buf);
				to_add.ts = ts;
				to_add.salt = {salt.begin(), salt.end()};
				to_add.sig = sig;
				to_add.key = pk;

				std::tie(i, std::ignore) = m_mutable_table.insert(
					std::make_pair(target, std::move(to_add)));
				m_counters.mutable_data += 1;
			}
			else
			{
				// this is the case where we already have an item in this slot
				dht_mutable_item& item = i->second;

				if (item.ts <= ts)
				{
					set_value(item, buf);
					item.ts = ts;
					item.sig = sig;
				}
			}

			touch_item(i->second, addr);
		}

		void remove_mutable_item(sha256_hash const& target) override
		{
			auto i = m_mutable_table.find(target);
			if (i == m_mutable_table.end()) return;
			m_mutable_table.erase(i);
		}

		void relay_referred(node_id const& peer
			, node_entry const& ne) override
		{
			node_entry add_ne(ne.id, ne.endpoint);

			auto i = m_relays_table.find(peer);
			if (i == m_relays_table.end())
			{
				if (int(m_relays_table.size()) >= 1000)
				{
					auto const j = std::min_element(m_relays_table.begin()
						, m_relays_table.end()
						, [](std::pair<node_id const, relays_bucket> const& lhs
							, std::pair<node_id const, relays_bucket> const& rhs)
							{ return lhs.second.last_queried < rhs.second.last_queried; });
					TORRENT_ASSERT(j != m_relays_table.end());
					m_relays_table.erase(j);
				}

				relays_bucket to_add;
				to_add.referred(add_ne);

				std::tie(i, std::ignore) = m_relays_table.insert(
					std::make_pair(peer, std::move(to_add)));
			}
			else
			{
				relays_bucket& rb = i->second;
				rb.referred(add_ne);
			}
		}

		void find_relays(node_id const& peer
			, std::vector<node_entry>& l
			, int count
			, udp protocol) override
		{
			l.clear();
			auto const i = m_relays_table.find(peer);
			if (i == m_relays_table.end()) return;

			relays_bucket& rb = i->second;
			rb.find_node(l, count);
		}

		void tick() override
		{
			if (0 == m_settings.get_int(settings_pack::dht_item_lifetime)) return;

			time_point const now = aux::time_now();
			time_duration lifetime = seconds(m_settings.get_int(settings_pack::dht_item_lifetime));
			// item lifetime must >= 120 minutes.
			if (lifetime < minutes(120)) lifetime = minutes(120);

			// libTAU modify: if immutable table is not full, don't expire
			if (int(m_immutable_table.size()) >= m_settings.get_int(
					settings_pack::dht_max_dht_items))
			{
				for (auto i = m_immutable_table.begin(); i != m_immutable_table.end();)
				{
					if (i->second.last_seen + lifetime > now)
					{
						++i;
						continue;
					}
					i = m_immutable_table.erase(i);
					m_counters.immutable_data -= 1;
				}
			}

			// libTAU modify: if mutable table is not full, don't expire
			if (int(m_mutable_table.size()) >= m_settings.get_int(
					settings_pack::dht_max_dht_items))
			{
				for (auto i = m_mutable_table.begin(); i != m_mutable_table.end();)
				{
					if (i->second.last_seen + lifetime > now)
					{
						++i;
						continue;
					}
					i = m_mutable_table.erase(i);
					m_counters.mutable_data -= 1;
				}
			}
		}

		dht_storage_counters counters() const override
		{
			return m_counters;
		}

	private:
		settings_interface const& m_settings;
		dht_storage_counters m_counters;

		std::vector<node_id> m_node_ids;
		std::map<node_id, dht_immutable_item> m_immutable_table;
		std::map<node_id, dht_mutable_item> m_mutable_table;
		std::map<node_id, relays_bucket> m_relays_table;
	};
}

void dht_storage_counters::reset()
{
	torrents = 0;
	peers = 0;
	immutable_data = 0;
	mutable_data = 0;
}

std::unique_ptr<dht_storage_interface> dht_default_storage_constructor(
	settings_interface const& settings)
{
	return std::make_unique<dht_default_storage>(settings);
}

} // namespace libTAU::dht
