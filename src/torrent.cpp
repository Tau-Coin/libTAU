/*

Copyright (c) 2003-2021, Arvid Norberg
Copyright (c) 2003, Daniel Wallin
Copyright (c) 2004, Magnus Jonsson
Copyright (c) 2008, Andrew Resch
Copyright (c) 2015, Mikhail Titov
Copyright (c) 2015-2020, Steven Siloti
Copyright (c) 2016, Jonathan McDougall
Copyright (c) 2016-2021, Alden Torres
Copyright (c) 2016-2018, Pavel Pimenov
Copyright (c) 2016-2017, Andrei Kurushin
Copyright (c) 2017, Falcosc
Copyright (c) 2017, 2020, AllSeeingEyeTolledEweSew
Copyright (c) 2017, ximply
Copyright (c) 2018, Fernando Rodriguez
Copyright (c) 2018, d-komarov
Copyright (c) 2018, airium
Copyright (c) 2020, Viktor Elofsson
Copyright (c) 2020, Rosen Penev
Copyright (c) 2020, Paul-Louis Ageneau
Copyright (c) 2021, AdvenT
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/config.hpp"

#include <cstdarg> // for va_list
#include <ctime>
#include <algorithm>

#include <set>
#include <map>
#include <vector>
#include <cctype>
#include <memory>
#include <numeric>
#include <limits> // for numeric_limits
#include <cstdio> // for snprintf
#include <functional>

#include "libTAU/aux_/torrent.hpp"

#ifdef TORRENT_SSL_PEERS
#include "libTAU/aux_/ssl_stream.hpp"
#include "libTAU/aux_/ssl.hpp"
#endif // TORRENT_SSL_PEERS

#include "libTAU/torrent_handle.hpp"
#include "libTAU/announce_entry.hpp"
#include "libTAU/torrent_info.hpp"
#include "libTAU/aux_/parse_url.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/hasher.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/aux_/peer.hpp"
#include "libTAU/peer_id.hpp"
#include "libTAU/identify_client.hpp"
#include "libTAU/alert_types.hpp"
#include "libTAU/extensions.hpp"
#include "libTAU/aux_/session_interface.hpp"
#include "libTAU/aux_/instantiate_connection.hpp"
#include "libTAU/assert.hpp"
#include "libTAU/kademlia/dht_tracker.hpp"
#include "libTAU/aux_/http_connection.hpp"
#include "libTAU/aux_/random.hpp"
#include "libTAU/peer_class.hpp" // for peer_class
#include "libTAU/aux_/socket_io.hpp" // for read_*_endpoint
#include "libTAU/ip_filter.hpp"
#include "libTAU/performance_counters.hpp" // for counters
#include "libTAU/aux_/resolver_interface.hpp"
#include "libTAU/aux_/alloca.hpp"
#include "libTAU/aux_/resolve_links.hpp"
#include "libTAU/aux_/alert_manager.hpp"
#include "libTAU/disk_interface.hpp"
#include "libTAU/aux_/ip_helpers.hpp" // for is_ip_address
#include "libTAU/download_priority.hpp"
#include "libTAU/hex.hpp" // to_hex
#include "libTAU/aux_/range.hpp"
#include "libTAU/aux_/merkle.hpp"
#include "libTAU/mmap_disk_io.hpp" // for hasher_thread_divisor
#include "libTAU/aux_/numeric_cast.hpp"
#include "libTAU/aux_/path.hpp"
#include "libTAU/aux_/generate_peer_id.hpp"
#include "libTAU/aux_/announce_entry.hpp"
#include "libTAU/aux_/ssl.hpp"

#ifndef TORRENT_DISABLE_LOGGING
#include "libTAU/aux_/session_impl.hpp" // for tracker_logger
#endif

#include "libTAU/aux_/torrent_impl.hpp"

using namespace std::placeholders;

namespace libTAU::aux {
namespace {

bool is_downloading_state(int const st)
{
	switch (st)
	{
		case torrent_status::checking_files:
		case torrent_status::checking_resume_data:
			return false;
		case torrent_status::downloading_metadata:
		case torrent_status::downloading:
		case torrent_status::finished:
		case torrent_status::seeding:
			return true;
		default:
			// unexpected state
			TORRENT_ASSERT_FAIL_VAL(st);
			return false;
	}
}
} // anonymous namespace

	torrent_hot_members::torrent_hot_members(aux::session_interface& ses
		, add_torrent_params const& p, bool const session_paused)
		: m_ses(ses)
		, m_complete(0xffffff)
		, m_connections_initialized(false)
		, m_abort(false)
		, m_session_paused(session_paused)
#ifndef TORRENT_DISABLE_SHARE_MODE
#endif
		, m_have_all(false)
		, m_graceful_pause_mode(false)
		, m_max_connections(0xffffff)
		, m_state(torrent_status::checking_resume_data)
	{}

	torrent::torrent(
		aux::session_interface& ses
		, bool const session_paused
		, add_torrent_params&& p)
		: torrent_hot_members(ses, p, session_paused)
		, m_total_uploaded(p.total_uploaded)
		, m_total_downloaded(p.total_downloaded)
		, m_tracker_timer(ses.get_context())
		, m_inactivity_timer(ses.get_context())
		, m_trackerid(p.trackerid)
		, m_save_path(complete(p.save_path))
		, m_stats_counters(ses.stats_counters())
		, m_added_time(p.added_time ? p.added_time : std::time(nullptr))
		, m_completed_time(p.completed_time)
		, m_info_hash(p.info_hashes)
		, m_error_file(torrent_status::error_file_none)
		, m_sequence_number(-1)
		, m_peer_id(aux::generate_peer_id(settings()))
		, m_has_incoming(false)
		, m_files_checked(false)
		, m_storage_mode(p.storage_mode)
		, m_announcing(false)
		, m_added(false)
		, m_auto_sequential(false)
		, m_seed_mode(false)
		, m_max_uploads((1 << 24) - 1)
		, m_num_uploads(0)
		, m_pending_active_change(false)
		, m_v2_piece_layers_validated(false)
		, m_connect_boost_counter(static_cast<std::uint8_t>(settings().get_int(settings_pack::torrent_connect_boost)))
		, m_incomplete(0xffffff)
		, m_ssl_torrent(false)
		, m_deleted(false)
		, m_last_download(seconds32(p.last_download))
		, m_last_upload(seconds32(p.last_upload))
		, m_userdata(p.userdata)
		, m_current_gauge_state(static_cast<std::uint32_t>(no_gauge_state))
		, m_moving_storage(false)
		, m_inactive(false)
		, m_downloaded(0xffffff)
		, m_progress_ppm(0)
		, m_torrent_initialized(false)
		, m_outstanding_file_priority(false)
		, m_complete_sent(false)
	{
	}

	void torrent::load_merkle_trees(
		aux::vector<std::vector<sha256_hash>, file_index_t> trees_import
		, aux::vector<std::vector<bool>, file_index_t> mask)
	{
		auto const& fs = m_torrent_file->orig_files();

		for (file_index_t i{0}; i < fs.end_file(); ++i)
		{
			if (fs.pad_file_at(i) || fs.file_size(i) == 0)
				continue;

			if (i >= trees_import.end_index()) break;
			if (i < mask.end_index() && !mask[i].empty())
			{
				mask[i].resize(m_merkle_trees[i].size(), false);
				m_merkle_trees[i].load_sparse_tree(trees_import[i], mask[i]);
			}
			else
			{
				m_merkle_trees[i].load_tree(trees_import[i]);
			}
		}
	}

	void torrent::inc_stats_counter(int c, int value)
	{ m_ses.stats_counters().inc_stats_counter(c, value); }

	int torrent::current_stats_state() const
	{
		if (m_abort || !m_added)
			return counters::num_checking_torrents + no_gauge_state;

		if (has_error()) return counters::num_error_torrents;
		if (m_paused || m_graceful_pause_mode)
		{
			if (!is_auto_managed()) return counters::num_stopped_torrents;
			if (is_seed()) return counters::num_queued_seeding_torrents;
			return counters::num_queued_download_torrents;
		}
		if (state() == torrent_status::checking_files
#if TORRENT_ABI_VERSION == 1
			|| state() == torrent_status::queued_for_checking
#endif
			)
			return counters::num_checking_torrents;
		else if (is_seed()) return counters::num_seeding_torrents;
		else if (is_upload_only()) return counters::num_upload_only_torrents;
		return counters::num_downloading_torrents;
	}

	void torrent::update_gauge()
	{
		int const new_gauge_state = current_stats_state() - counters::num_checking_torrents;
		TORRENT_ASSERT(new_gauge_state >= 0);
		TORRENT_ASSERT(new_gauge_state <= no_gauge_state);

		if (new_gauge_state == int(m_current_gauge_state)) return;

		if (m_current_gauge_state != no_gauge_state)
			inc_stats_counter(m_current_gauge_state + counters::num_checking_torrents, -1);
		if (new_gauge_state != no_gauge_state)
			inc_stats_counter(new_gauge_state + counters::num_checking_torrents, 1);

		TORRENT_ASSERT(new_gauge_state >= 0);
		TORRENT_ASSERT(new_gauge_state <= no_gauge_state);
		m_current_gauge_state = static_cast<std::uint32_t>(new_gauge_state);
	}

	void torrent::leave_seed_mode(seed_mode_t const checking)
	{
		if (!m_seed_mode) return;

		if (checking == seed_mode_t::check_files)
		{
			// this means the user promised we had all the
			// files, but it turned out we didn't. This is
			// an error.

			// TODO: 2 post alert

#ifndef TORRENT_DISABLE_LOGGING
			debug_log("*** FAILED SEED MODE, rechecking");
#endif
		}

#ifndef TORRENT_DISABLE_LOGGING
		debug_log("*** LEAVING SEED MODE (%s)"
			, checking == seed_mode_t::skip_checking ? "as seed" : "as non-seed");
#endif
		m_seed_mode = false;
		// seed is false if we turned out not
		// to be a seed after all
		if (checking == seed_mode_t::check_files
			&& state() != torrent_status::checking_resume_data)
		{
			m_have_all = false;
			set_state(torrent_status::downloading);
			force_recheck();
		}
		m_num_verified = 0;
		m_verified.clear();
		m_verifying.clear();

		set_need_save_resume();
	}

	void torrent::verified(piece_index_t const piece)
	{
		TORRENT_ASSERT(!m_verified.get_bit(piece));
		++m_num_verified;
		m_verified.set_bit(piece);
	}

	void torrent::start()
	{
	}

	void torrent::set_apply_ip_filter(bool b)
	{
		if (b == m_apply_ip_filter) return;
		if (b)
		{
			inc_stats_counter(counters::non_filter_torrents, -1);
		}
		else
		{
			inc_stats_counter(counters::non_filter_torrents);
		}

		set_need_save_resume();

		m_apply_ip_filter = b;
		ip_filter_updated();
		state_updated();
	}

	void torrent::set_ip_filter(std::shared_ptr<const ip_filter> ipf)
	{
		m_ip_filter = std::move(ipf);
		if (!m_apply_ip_filter) return;
		ip_filter_updated();
	}

#ifndef TORRENT_DISABLE_DHT
	bool torrent::should_announce_dht() const
	{
		TORRENT_ASSERT(is_single_thread());
		if (!m_enable_dht) return false;
		if (!m_ses.announce_dht()) return false;

		if (!m_ses.dht()) return false;
		if (m_torrent_file->is_valid() && !m_files_checked) return false;
		if (!m_announce_to_dht) return false;
		if (m_paused) return false;

		// don't announce private torrents
		if (m_torrent_file->is_valid() && m_torrent_file->priv()) return false;
		if (m_trackers.empty()) return true;
		if (!settings().get_bool(settings_pack::use_dht_as_fallback)) return true;

		return std::none_of(m_trackers.begin(), m_trackers.end()
			, [](aux::announce_entry const& tr) { return bool(tr.verified); });
	}

#endif

	torrent::~torrent()
	{
		// TODO: 3 assert there are no outstanding async operations on this
		// torrent

		// The invariant can't be maintained here, since the torrent
		// is being destructed, all weak references to it have been
		// reset, which means that all its peers already have an
		// invalidated torrent pointer (so it cannot be verified to be correct)

		// i.e. the invariant can only be maintained if all connections have
		// been closed by the time the torrent is destructed. And they are
		// supposed to be closed. So we can still do the invariant check.

		// however, the torrent object may be destructed from the main
		// thread when shutting down, if the disk cache has references to it.
		// this means that the invariant check that this is called from the
		// network thread cannot be maintained

		TORRENT_ASSERT(m_peer_class == peer_class_t{0});
	}

	void torrent::read_piece(piece_index_t const piece)
	{
		error_code ec;
		if (m_abort || m_deleted)
		{
			ec.assign(boost::system::errc::operation_canceled, generic_category());
		}
		else if (!valid_metadata())
		{
			ec.assign(errors::no_metadata, libTAU_category());
		}
		else if (piece < piece_index_t{0} || piece >= m_torrent_file->end_piece())
		{
			ec.assign(errors::invalid_piece_index, libTAU_category());
		}

		if (ec)
		{
			return;
		}

		const int piece_size = m_torrent_file->piece_size(piece);
		const int blocks_in_piece = (piece_size + block_size() - 1) / block_size();

		TORRENT_ASSERT(blocks_in_piece > 0);
		TORRENT_ASSERT(piece_size > 0);

		if (blocks_in_piece == 0)
		{
			// this shouldn't actually happen
			boost::shared_array<char> buf;
			return;
		}

		std::shared_ptr<read_piece_struct> rp = std::make_shared<read_piece_struct>();
		rp->piece_data.reset(new (std::nothrow) char[std::size_t(piece_size)]);
		if (!rp->piece_data)
		{
			return;
		}
		rp->blocks_left = blocks_in_piece;
		rp->fail = false;

		peer_request r;
		r.piece = piece;
		r.start = 0;
		auto self = shared_from_this();
		for (int i = 0; i < blocks_in_piece; ++i, r.start += block_size())
		{
			r.length = std::min(piece_size - r.start, block_size());
			m_ses.disk_thread().async_read(m_storage, r
				, [self, r, rp](disk_buffer_holder block, storage_error const& se) mutable
				{ self->on_disk_read_complete(std::move(block), se, r, rp); });
		}
		m_ses.deferred_submit_jobs();
	}

#ifndef TORRENT_DISABLE_SHARE_MODE
	void torrent::send_share_mode()
	{
	}
#endif // TORRENT_DISABLE_SHARE_MODE

	void torrent::send_upload_only()
	{
	}

#ifndef TORRENT_DISABLE_SHARE_MODE
	void torrent::set_share_mode(bool s)
	{
		if (s == m_share_mode) return;

		m_share_mode = s;
		set_need_save_resume();
#ifndef TORRENT_DISABLE_LOGGING
		debug_log("*** set-share-mode: %d", s);
#endif
		if (m_share_mode)
		{
			std::size_t const num_files = valid_metadata()
				? std::size_t(m_torrent_file->num_files())
				: m_file_priority.size();
			// in share mode, all pieces have their priorities initialized to
			// dont_download
			prioritize_files(aux::vector<download_priority_t, file_index_t>(num_files, dont_download));
		}
	}
#endif // TORRENT_DISABLE_SHARE_MODE

	void torrent::set_upload_mode(bool b)
	{
	}

	void torrent::need_peer_list()
	{
		if (m_peer_list) return;
	}

	void torrent::handle_exception()
	{
		try
		{
			throw;
		}
		catch (system_error const& err)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				debug_log("torrent exception: (%d) %s: %s"
					, err.code().value(), err.code().message().c_str()
					, err.what());
			}
#endif
			set_error(err.code(), torrent_status::error_file_exception);
		}
		catch (std::exception const& err)
		{
			TORRENT_UNUSED(err);
			set_error(error_code(), torrent_status::error_file_exception);
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				debug_log("torrent exception: %s", err.what());
			}
#endif
		}
		catch (...)
		{
			set_error(error_code(), torrent_status::error_file_exception);
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				debug_log("torrent exception: unknown");
			}
#endif
		}
	}

	void torrent::on_piece_fail_sync(piece_index_t, piece_block) try
	{
	}
	catch (...) { handle_exception(); }

	void torrent::on_disk_read_complete(disk_buffer_holder buffer
		, storage_error const& se
		, peer_request const&  r, std::shared_ptr<read_piece_struct> rp) try
	{

	}
	catch (...) { handle_exception(); }

	storage_mode_t torrent::storage_mode() const
	{ return storage_mode_t(m_storage_mode); }

	void torrent::clear_peers()
	{
		disconnect_all(error_code(), operation_t::unknown);
		if (m_peer_list) m_peer_list->clear();
	}

	void torrent::set_sequential_range(piece_index_t first_piece, piece_index_t last_piece)
	{
	}

	void torrent::set_sequential_range(piece_index_t first_piece)
	{
	}

	void torrent::on_disk_write_complete(storage_error const& error
		, peer_request const& p) try
	{
	}
	catch (...) { handle_exception(); }

	peer_request torrent::to_req(piece_block const& p) const
	{
		int block_offset = p.block_index * block_size();
		int block = std::min(torrent_file().piece_size(
			p.piece_index) - block_offset, block_size());
		TORRENT_ASSERT(block > 0);
		TORRENT_ASSERT(block <= block_size());

		peer_request r;
		r.piece = p.piece_index;
		r.start = block_offset;
		r.length = block;
		return r;
	}

	std::string torrent::name() const
	{
		if (valid_metadata()) return m_torrent_file->name();
		if (m_name) return *m_name;
		return "";
	}

#ifdef TORRENT_SSL_PEERS
	bool torrent::verify_peer_cert(bool const preverified, ssl::verify_context& ctx)
	{
		// if the cert wasn't signed by the correct CA, fail the verification
		if (!preverified) return false;

		std::string expected = m_torrent_file->name();
#ifndef TORRENT_DISABLE_LOGGING
		std::string names;
		bool match = false;
#endif

#ifdef TORRENT_USE_OPENSSL
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wused-but-marked-unused"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wzero-as-null-pointer-constant"
#endif
		// we're only interested in checking the certificate at the end of the chain.
		// any certificate that isn't the leaf (i.e. the one presented by the peer)
		// should be accepted automatically, given preverified is true. The leaf certificate
		// need to be verified to make sure its DN matches the info-hash
		int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());
		if (depth > 0) return true;

		X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());

		// Go through the alternate names in the certificate looking for matching DNS entries
		auto* gens = static_cast<GENERAL_NAMES*>(
			X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));

		for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i)
		{
			GENERAL_NAME* gen = sk_GENERAL_NAME_value(gens, i);
			if (gen->type != GEN_DNS) continue;
			ASN1_IA5STRING* domain = gen->d.dNSName;
			if (domain->type != V_ASN1_IA5STRING || !domain->data || !domain->length) continue;
			auto const* torrent_name = reinterpret_cast<char const*>(domain->data);
			auto const name_length = aux::numeric_cast<std::size_t>(domain->length);

#ifndef TORRENT_DISABLE_LOGGING
			if (i > 1) names += " | n: ";
			names.append(torrent_name, name_length);
#endif
			if (std::strncmp(torrent_name, "*", name_length) == 0
				|| std::strncmp(torrent_name, expected.c_str(), name_length) == 0)
			{
#ifndef TORRENT_DISABLE_LOGGING
				match = true;
				// if we're logging, keep looping over all names,
				// for completeness of the log
				continue;
#else
				return true;
#endif
			}
		}

		// no match in the alternate names, so try the common names. We should only
		// use the "most specific" common name, which is the last one in the list.
		X509_NAME* name = X509_get_subject_name(cert);
		int i = -1;
		ASN1_STRING* common_name = nullptr;
		while ((i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0)
		{
			X509_NAME_ENTRY* name_entry = X509_NAME_get_entry(name, i);
			common_name = X509_NAME_ENTRY_get_data(name_entry);
		}
		if (common_name && common_name->data && common_name->length)
		{
			auto const* torrent_name = reinterpret_cast<char const*>(common_name->data);
			auto const name_length = aux::numeric_cast<std::size_t>(common_name->length);

#ifndef TORRENT_DISABLE_LOGGING
			if (!names.empty()) names += " | n: ";
			names.append(torrent_name, name_length);
#endif
			if (std::strncmp(torrent_name, "*", name_length) == 0
				|| std::strncmp(torrent_name, expected.c_str(), name_length) == 0)
			{
#ifdef TORRENT_DISABLE_LOGGING
				return true;
#else
				match = true;
#endif

			}
		}
#ifdef __clang__
#pragma clang diagnostic pop
#endif

#elif defined TORRENT_USE_GNUTLS
		gnutls_x509_crt_t cert = ctx.native_handle();

		// We don't use gnutls_x509_crt_check_hostname()
		// as it doesn't handle wildcards the way we need here

		char buf[256];
		unsigned int seq = 0;
		while(true) {
			size_t len = sizeof(buf);
			int ret = gnutls_x509_crt_get_subject_alt_name(cert, seq, buf, &len, nullptr);
			if(ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) break;
			if(ret == GNUTLS_E_SUCCESS)
			{
#ifndef TORRENT_DISABLE_LOGGING
				if (!names.empty()) names += " | n: ";
				names.append(buf, len);
#endif
				if (std::strncmp(buf, "*", len) == 0
					|| std::strncmp(buf, expected.c_str(), len) == 0)
				{
#ifndef TORRENT_DISABLE_LOGGING
					match = true;
					continue;
#else
					return true;
#endif
				}
			}
			++seq;
		}

		// no match in the alternate names, so try the common name
		size_t len = sizeof(buf);
		int ret = gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, buf, &len);
		if(ret == GNUTLS_E_SUCCESS)
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (!names.empty()) names += " | n: ";
			names.append(buf, len);
#endif
			if (std::strncmp(buf, "*", len) == 0
				|| std::strncmp(buf, expected.c_str(), len) == 0)
			{
#ifdef TORRENT_DISABLE_LOGGING
				return true;
#else
				match = true;
#endif
			}
		}
#endif // TORRENT_USE_GNUTLS

#ifndef TORRENT_DISABLE_LOGGING
		debug_log("<== incoming SSL CONNECTION [ n: %s | match: %s ]"
			, names.c_str(), match?"yes":"no");
		return match;
#else
		return false;
#endif
	}

	void torrent::init_ssl(string_view cert)
	{
		// create the SSL context for this torrent. We need to
		// inject the root certificate, and no other, to
		// verify other peers against
		std::unique_ptr<ssl::context> ctx(std::make_unique<ssl::context>(ssl::context::tls));

		ctx->set_options(ssl::context::default_workarounds
			| ssl::context::no_sslv2
			| ssl::context::no_sslv3
			| ssl::context::single_dh_use);

		error_code ec;
		ctx->set_verify_mode(ssl::context::verify_peer
			| ssl::context::verify_fail_if_no_peer_cert
			| ssl::context::verify_client_once, ec);
		if (ec)
		{
			set_error(ec, torrent_status::error_file_ssl_ctx);
			pause();
			return;
		}

		// the verification function verifies the distinguished name
		// of a peer certificate to make sure it matches the info-hash
		// of the torrent, or that it's a "star-cert"
		ctx->set_verify_callback(
				std::bind(&torrent::verify_peer_cert, this, _1, _2)
				, ec);
		if (ec)
		{
			set_error(ec, torrent_status::error_file_ssl_ctx);
			pause();
			return;
		}

		// set the root certificate as trust
		ssl::set_trust_certificate(ctx->native_handle(), cert, ec);
		if (ec)
		{
			set_error(ec, torrent_status::error_file_ssl_ctx);
			pause();
			return;
		}

#if 0
		char filename[100];
		std::snprintf(filename, sizeof(filename), "/tmp/%u.pem", random());
		FILE* f = fopen(filename, "w+");
		fwrite(cert.c_str(), cert.size(), 1, f);
		fclose(f);
		ctx->load_verify_file(filename);
#endif

		// if all went well, set the torrent ssl context to this one
		m_ssl_ctx = std::move(ctx);
	}
#endif // TORRENT_SSL_PEERS

	void torrent::construct_storage()
	{
		storage_params params{
			m_torrent_file->orig_files(),
			&m_torrent_file->orig_files() != &m_torrent_file->files()
				? &m_torrent_file->files() : nullptr,
			m_save_path,
			static_cast<storage_mode_t>(m_storage_mode),
			m_file_priority,
			m_info_hash.get_best()
		};

		// the shared_from_this() will create an intentional
		// cycle of ownership, se the hpp file for description.
		m_storage = m_ses.disk_thread().new_torrent(params, shared_from_this());
	}

	// this may not be called from a constructor because of the call to
	// shared_from_this(). It's either called when we start() the torrent, or at a
	// later time if it's a magnet link, once the metadata is downloaded
	void torrent::init()
	{
	}

	bool torrent::is_self_connection(peer_id const& pid) const
	{
		return m_outgoing_pids.count(pid) > 0;
	}

	void torrent::on_resume_data_checked(status_t const status
		, storage_error const& error) try
	{
	}
	catch (...) { handle_exception(); }

	void torrent::force_recheck()
	{
	}

	void torrent::on_force_recheck(status_t const status, storage_error const& error) try
	{
	}
	catch (...) { handle_exception(); }

	void torrent::start_checking() try
	{
	}
	catch (...) { handle_exception(); }

	// This is only used for checking of torrents. i.e. force-recheck or initial checking
	// of existing files
	void torrent::on_piece_hashed(aux::vector<sha256_hash> block_hashes
		, piece_index_t const piece, sha1_hash const& piece_hash
		, storage_error const& error) try
	{
	}
	catch (...) { handle_exception(); }

#if TORRENT_ABI_VERSION == 1
	void torrent::use_interface(std::string net_interfaces)
	{
		std::shared_ptr<settings_pack> p = std::make_shared<settings_pack>();
		p->set_str(settings_pack::outgoing_interfaces, std::move(net_interfaces));
		m_ses.apply_settings_pack(p);
	}
#endif

	void torrent::on_tracker_announce(error_code const& ec) try
	{
		COMPLETE_ASYNC("tracker::on_tracker_announce");
		TORRENT_ASSERT(is_single_thread());
		TORRENT_ASSERT(m_waiting_tracker > 0);
		--m_waiting_tracker;
		if (ec) return;
		if (m_abort) return;
		announce_with_tracker();
	}
	catch (...) { handle_exception(); }

	void torrent::lsd_announce()
	{
	}

#ifndef TORRENT_DISABLE_DHT

	void torrent::dht_announce()
	{
		TORRENT_ASSERT(is_single_thread());
		if (!m_ses.dht())
		{
#ifndef TORRENT_DISABLE_LOGGING
			debug_log("DHT: no dht initialized");
#endif
			return;
		}
		if (!should_announce_dht())
		{
#ifndef TORRENT_DISABLE_LOGGING
			if (should_log())
			{
				if (!m_ses.announce_dht())
					debug_log("DHT: no listen sockets");

				if (m_torrent_file->is_valid() && !m_files_checked)
					debug_log("DHT: files not checked, skipping DHT announce");

				if (!m_announce_to_dht)
					debug_log("DHT: queueing disabled DHT announce");

				if (m_paused)
					debug_log("DHT: torrent paused, no DHT announce");

				if (!m_enable_dht)
					debug_log("DHT: torrent has DHT disabled flag");

				if (m_torrent_file->is_valid() && m_torrent_file->priv())
					debug_log("DHT: private torrent, no DHT announce");

				if (settings().get_bool(settings_pack::use_dht_as_fallback))
				{
					int const verified_trackers = static_cast<int>(std::count_if(
						m_trackers.begin(), m_trackers.end()
						, [](aux::announce_entry const& t) { return t.verified; }));

					if (verified_trackers > 0)
						debug_log("DHT: only using DHT as fallback, and there are %d working trackers", verified_trackers);
				}
			}
#endif
			return;
		}

		TORRENT_ASSERT(!m_paused);

#ifndef TORRENT_DISABLE_LOGGING
		debug_log("START DHT announce");
		m_dht_start_time = aux::time_now();
#endif

		// if we're a seed, we tell the DHT for better scrape stats
		dht::announce_flags_t flags = is_seed() ? dht::announce::seed : dht::announce_flags_t{};

		// If this is an SSL torrent the announce needs to specify an SSL
		// listen port. DHT nodes only operate on non-SSL ports so SSL
		// torrents cannot use implied_port.
		// if we allow incoming uTP connections, set the implied_port
		// argument in the announce, this will make the DHT node use
		// our source port in the packet as our listen port, which is
		// likely more accurate when behind a NAT
		if (is_ssl_torrent())
		{
			flags |= dht::announce::ssl_torrent;
		}
		else if (settings().get_bool(settings_pack::enable_incoming_utp))
		{
			flags |= dht::announce::implied_port;
		}

		std::weak_ptr<torrent> self(shared_from_this());
		/*
		m_torrent_file->info_hashes().for_each([&](sha1_hash const& ih, protocol_version v)
		{
			m_ses.dht()->announce(ih, 0, flags
				, std::bind(&torrent::on_dht_announce_response_disp, self, v, _1));
		});
		 */
	}

	void torrent::on_dht_announce_response_disp(std::weak_ptr<torrent> const t
		, protocol_version const v, std::vector<tcp::endpoint> const& peers)
	{
		std::shared_ptr<torrent> tor = t.lock();
		if (!tor) return;
		tor->on_dht_announce_response(v, peers);
	}

	void torrent::on_dht_announce_response(protocol_version const v
		, std::vector<tcp::endpoint> const& peers) try
	{
	}
	catch (...) { handle_exception(); }

#endif

	namespace
	{
		struct announce_protocol_state
		{
			// the tier is kept as INT_MAX until we find the first
			// tracker that works, then it's set to that tracker's
			// tier.
			int tier = INT_MAX;

			// have we sent an announce in this tier yet?
			bool sent_announce = false;

			// have we finished sending announces on this listen socket?
			bool done = false;
		};

		struct announce_state
		{
			explicit announce_state(aux::listen_socket_handle s)
				: socket(std::move(s)) {}

			aux::listen_socket_handle socket;

			aux::array<announce_protocol_state, num_protocols, protocol_version> state;
		};
	}

	void torrent::announce_with_tracker(event_t e)
	{
	}

	void torrent::scrape_tracker(int idx, bool const user_triggered)
	{
	}

	void torrent::tracker_warning(tracker_request const& req, std::string const& msg)
	{
		TORRENT_ASSERT(is_single_thread());

		INVARIANT_CHECK;

		protocol_version const hash_version = req.info_hash == m_info_hash.v1
			? protocol_version::V1 : protocol_version::V2;

		aux::announce_entry* ae = find_tracker(req.url);
		tcp::endpoint local_endpoint;
		if (ae)
		{
			for (auto& aep : ae->endpoints)
			{
				if (aep.socket != req.outgoing_socket) continue;
				local_endpoint = aep.local_endpoint;
				aep.info_hashes[hash_version].message = msg;
				break;
			}
		}
	}

	void torrent::tracker_scrape_response(tracker_request const& req
		, int const complete, int const incomplete, int const downloaded, int /* downloaders */)
	{
		TORRENT_ASSERT(is_single_thread());

		INVARIANT_CHECK;
		TORRENT_ASSERT(req.kind & tracker_request::scrape_request);

		protocol_version const hash_version = req.info_hash == m_info_hash.v1
			? protocol_version::V1 : protocol_version::V2;

		aux::announce_entry* ae = find_tracker(req.url);
		tcp::endpoint local_endpoint;
		if (ae)
		{
			auto* aep = ae->find_endpoint(req.outgoing_socket);
			if (aep)
			{
				local_endpoint = aep->local_endpoint;
				if (incomplete >= 0) aep->info_hashes[hash_version].scrape_incomplete = incomplete;
				if (complete >= 0) aep->info_hashes[hash_version].scrape_complete = complete;
				if (downloaded >= 0) aep->info_hashes[hash_version].scrape_downloaded = downloaded;

				update_scrape_state();
			}
		}

	}

	void torrent::update_scrape_state()
	{
		// loop over all trackers and find the largest numbers for each scrape field
		// then update the torrent-wide understanding of number of downloaders and seeds
		int complete = -1;
		int incomplete = -1;
		int downloaded = -1;
		for (auto const& t : m_trackers)
		{
			for (auto const& aep : t.endpoints)
			{
				for (protocol_version const ih : all_versions)
				{
					auto const& a = aep.info_hashes[ih];
					complete = std::max(a.scrape_complete, complete);
					incomplete = std::max(a.scrape_incomplete, incomplete);
					downloaded = std::max(a.scrape_downloaded, downloaded);
				}
			}
		}

		if ((complete >= 0 && int(m_complete) != complete)
			|| (incomplete >= 0 && int(m_incomplete) != incomplete)
			|| (downloaded >= 0 && int(m_downloaded) != downloaded))
			state_updated();

		if (int(m_complete) != complete
			|| int(m_incomplete) != incomplete
			|| int(m_downloaded) != downloaded)
		{
			m_complete = std::uint32_t(complete);
			m_incomplete = std::uint32_t(incomplete);
			m_downloaded = std::uint32_t(downloaded);

			update_auto_sequential();

			// these numbers are cached in the resume data
			set_need_save_resume();
		}
	}

	void torrent::tracker_response(
		tracker_request const& r
		, address const& tracker_ip // this is the IP we connected to
		, std::list<address> const& tracker_ips // these are all the IPs it resolved to
		, struct tracker_response const& resp)
	{
	}

	void torrent::update_auto_sequential()
	{
	}

	void torrent::do_connect_boost()
	{
		if (m_connect_boost_counter == 0) return;

	}

	// this is the entry point for the client to force a re-announce. It's
	// considered a client-initiated announce (as opposed to the regular ones,
	// issued by libTAU)
	void torrent::force_tracker_request(time_point const t, int const tracker_idx
		, reannounce_flags_t const flags)
	{
		TORRENT_ASSERT_PRECOND((tracker_idx >= 0
			&& tracker_idx < int(m_trackers.size()))
			|| tracker_idx == -1);

		if (is_paused()) return;
		if (tracker_idx == -1)
		{
			for (auto& e : m_trackers)
			{
				for (auto& aep : e.endpoints)
				{
					for (auto& a : aep.info_hashes)
					{
						a.next_announce = (flags & torrent_handle::ignore_min_interval)
							? time_point_cast<seconds32>(t) + seconds32(1)
							: std::max(time_point_cast<seconds32>(t), a.min_announce) + seconds32(1);
						a.min_announce = a.next_announce;
						a.triggered_manually = true;
					}
				}
			}
		}
		else
		{
			if (tracker_idx < 0 || tracker_idx >= int(m_trackers.size()))
				return;
			aux::announce_entry& e = m_trackers[tracker_idx];
			for (auto& aep : e.endpoints)
			{
				for (auto& a : aep.info_hashes)
				{
					a.next_announce = (flags & torrent_handle::ignore_min_interval)
						? time_point_cast<seconds32>(t) + seconds32(1)
						: std::max(time_point_cast<seconds32>(t), a.min_announce) + seconds32(1);
					a.min_announce = a.next_announce;
					a.triggered_manually = true;
				}
			}
		}
		update_tracker_timer(aux::time_now32());
	}

#if TORRENT_ABI_VERSION == 1
	void torrent::set_tracker_login(std::string const& name
		, std::string const& pw)
	{
		m_username = name;
		m_password = pw;
	}
#endif

	void torrent::on_peer_name_lookup(error_code const& e
		, std::vector<address> const& host_list, int const port
		, protocol_version const v) try
	{
	}
	catch (...) { handle_exception(); }

	std::optional<std::int64_t> torrent::bytes_left() const
	{

		std::int64_t left = 0;

		return left;
	}

	// fills in total_wanted, total_wanted_done and total_done
// TODO: 3 this could probably be pulled out into a free function
	void torrent::bytes_done(torrent_status& st, status_flags_t const flags) const
	{
	}

	void torrent::on_piece_verified(aux::vector<sha256_hash> block_hashes
		, piece_index_t const piece
		, sha1_hash const& piece_hash, storage_error const& error) try
	{
	}
	catch (...) { handle_exception(); }

	void torrent::add_suggest_piece(piece_index_t const index)
	{
	}

	// this is called once we have completely downloaded piece
	// 'index', its hash has been verified. It's also called
	// during initial file check when we find a piece whose hash
	// is correct
	void torrent::we_have(piece_index_t const index)
	{
	}

	boost::tribool torrent::on_blocks_hashed(piece_index_t const piece
		, span<sha256_hash const> const block_hashes)
	{
		boost::tribool ret = boost::indeterminate;
		return ret;
	}

	// this is called when the piece hash is checked as correct. Note
	// that the piece picker and the torrent won't necessarily consider
	// us to have this piece yet, since it might not have been flushed
	// to disk yet. Only if we have predictive_piece_announce on will
	// we announce this piece to peers at this point.
	void torrent::piece_passed(piece_index_t const index)
	{
	}

#ifndef TORRENT_DISABLE_PREDICTIVE_PIECES
	// we believe we will complete this piece very soon
	// announce it to peers ahead of time to eliminate the
	// round-trip times involved in announcing it, requesting it
	// and sending it
	void torrent::predicted_have_piece(piece_index_t const index, time_duration const duration)
	{
	}
#endif

	// blocks may contain the block indices of the blocks that failed (if this is
	// a v2 torrent).
	void torrent::piece_failed(piece_index_t const index, std::vector<int> blocks)
	{
	}

	void torrent::on_piece_sync(piece_index_t const piece, std::vector<int> const& blocks) try
	{
	}
	catch (...) { handle_exception(); }

	void torrent::abort()
	{
		TORRENT_ASSERT(is_single_thread());

		if (m_abort) return;

		m_abort = true;
		update_want_peers();
		update_want_tick();
		update_want_scrape();
		update_gauge();
		stop_announcing();

	}

	// this is called when we're destructing non-gracefully. i.e. we're _just_
	// destructing everything.
	void torrent::panic()
	{
		m_storage.reset();
		// if there are any other peers allocated still, we need to clear them
		// now. They can't be cleared later because the allocator will already
		// have been destructed
		if (m_peer_list) m_peer_list->clear();
		m_outgoing_pids.clear();
		m_num_uploads = 0;
		m_num_connecting = 0;
		m_num_connecting_seeds = 0;
	}

#ifndef TORRENT_DISABLE_SUPERSEEDING
	void torrent::set_super_seeding(bool const on)
	{
	}

	// TODO: 3 this should return optional<>. piece index -1 should not be
	// allowed
	piece_index_t torrent::get_piece_to_super_seed(typed_bitfield<piece_index_t> const& bits)
	{
		// return a piece with low availability that is not in
		// the bitfield and that is not currently being super
		// seeded by any peer
		TORRENT_ASSERT(m_super_seeding);

		// do a linear search from the first piece
		int min_availability = 9999;
		std::vector<piece_index_t> avail_vec;
		if (avail_vec.empty()) return piece_index_t{-1};
		return avail_vec[random(std::uint32_t(avail_vec.size() - 1))];
	}
#endif

	void torrent::on_files_deleted(storage_error const& error) try
	{
		TORRENT_ASSERT(is_single_thread());
	}
	catch (...) { handle_exception(); }

	void torrent::on_file_renamed(std::string const& filename
		, file_index_t const file_idx
		, storage_error const& error) try
	{
		TORRENT_ASSERT(is_single_thread());

		if (!error)
		{
			m_torrent_file->rename_file(file_idx, filename);

			set_need_save_resume();
		}
	}
	catch (...) { handle_exception(); }

	void torrent::on_torrent_paused() try
	{
		TORRENT_ASSERT(is_single_thread());
	}
	catch (...) { handle_exception(); }

#if TORRENT_ABI_VERSION == 1
	std::string torrent::tracker_login() const
	{
		if (m_username.empty() && m_password.empty()) return "";
		return m_username + ":" + m_password;
	}
#endif

	std::uint32_t torrent::tracker_key() const
	{
		auto const self = reinterpret_cast<uintptr_t>(this);
		auto const ses = reinterpret_cast<uintptr_t>(&m_ses);
		std::uint32_t const storage = m_storage
			? static_cast<std::uint32_t>(static_cast<storage_index_t>(m_storage))
			: 0;
		sha1_hash const h = hasher(reinterpret_cast<char const*>(&self), sizeof(self))
			.update(reinterpret_cast<char const*>(&storage), sizeof(storage))
			.update(reinterpret_cast<char const*>(&ses), sizeof(ses))
			.final();
		unsigned char const* ptr = &h[0];
		return aux::read_uint32(ptr);
	}

#ifndef TORRENT_DISABLE_STREAMING
	void torrent::cancel_non_critical()
	{
	}

	void torrent::set_piece_deadline(piece_index_t const piece, int const t
		, deadline_flags_t const flags)
	{
	}

	void torrent::reset_piece_deadline(piece_index_t piece)
	{
		remove_time_critical_piece(piece);
	}

	void torrent::remove_time_critical_piece(piece_index_t const piece, bool const finished)
	{
	}

	void torrent::clear_time_critical()
	{
	}

	// remove time critical pieces where priority is 0
	void torrent::remove_time_critical_pieces(aux::vector<download_priority_t, piece_index_t> const& priority)
	{
		for (auto i = m_time_critical_pieces.begin(); i != m_time_critical_pieces.end();)
		{
			if (priority[i->piece] == dont_download)
			{
				i = m_time_critical_pieces.erase(i);
				continue;
			}
			++i;
		}
	}
#endif // TORRENT_DISABLE_STREAMING

	void torrent::piece_availability(aux::vector<int, piece_index_t>& avail) const
	{
	}

	void torrent::set_piece_priority(piece_index_t const index
		, download_priority_t const priority)
	{
	}

	void torrent::prioritize_piece_list(std::vector<std::pair<piece_index_t
		, download_priority_t>> const& pieces)
	{
	}

	void torrent::prioritize_pieces(aux::vector<download_priority_t, piece_index_t> const& pieces)
	{
	}

	void torrent::piece_priorities(aux::vector<download_priority_t, piece_index_t>* pieces) const
	{
	}

	namespace
	{
		aux::vector<download_priority_t, file_index_t> fix_priorities(
			aux::vector<download_priority_t, file_index_t> input
			, file_storage const* fs)
		{
			if (fs) input.resize(fs->num_files(), default_priority);

			for (file_index_t i : input.range())
			{
				// initialize pad files to priority 0
				if (input[i] > dont_download && fs && fs->pad_file_at(i))
					input[i] = dont_download;
				else if (input[i] > top_priority)
					input[i] = top_priority;
			}

			return input;
		}
	}

	void torrent::on_file_priority(storage_error const& err
		, aux::vector<download_priority_t, file_index_t> prios)
	{
	}

	void torrent::prioritize_files(aux::vector<download_priority_t, file_index_t> files)
	{
	}

	void torrent::set_file_priority(file_index_t const index
		, download_priority_t prio)
	{
	}

	download_priority_t torrent::file_priority(file_index_t const index) const
	{
		return m_file_priority[index];
	}

	void torrent::file_priorities(aux::vector<download_priority_t, file_index_t>* files) const
	{
	}

	void torrent::update_piece_priorities(
		aux::vector<download_priority_t, file_index_t> const& file_prios)
	{
	}

	// this is called when piece priorities have been updated
	// updates the interested flag in peers
	void torrent::update_peer_interest(bool const was_finished)
	{
	}

	std::vector<lt::announce_entry> torrent::trackers() const
	{
		std::vector<lt::announce_entry> ret;
		return ret;
	}

	void torrent::replace_trackers(std::vector<lt::announce_entry> const& urls)
	{
	}

	void torrent::prioritize_udp_trackers()
	{
	}

	bool torrent::add_tracker(lt::announce_entry const& url)
	{
		return true;
	}

	void torrent::trigger_unchoke() noexcept
	{
	}

	void torrent::trigger_optimistic_unchoke() noexcept
	{
	}

	void torrent::cancel_block(piece_block block)
	{
	}

#ifdef TORRENT_SSL_PEERS
	// certificate is a filename to a .pem file which is our
	// certificate. The certificate must be signed by the root
	// cert of the torrent file. any peer we connect to or that
	// connect to use must present a valid certificate signed
	// by the torrent root cert as well
	void torrent::set_ssl_cert(std::string const& certificate
		, std::string const& private_key
		, std::string const& dh_params
		, std::string const& passphrase)
	{
		if (!m_ssl_ctx)
		{
			return;
		}

		error_code ec;
		m_ssl_ctx->set_password_callback(
				[passphrase](std::size_t, ssl::context::password_purpose purpose)
				{
					return purpose == ssl::context::for_reading ? passphrase : "";
				}
				, ec);
		m_ssl_ctx->use_certificate_file(certificate, ssl::context::pem, ec);
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
			debug_log("*** use certificate file: %s", ec.message().c_str());
#endif
		m_ssl_ctx->use_private_key_file(private_key, ssl::context::pem, ec);
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
			debug_log("*** use private key file: %s", ec.message().c_str());
#endif
		m_ssl_ctx->use_tmp_dh_file(dh_params, ec);
#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
			debug_log("*** use DH file: %s", ec.message().c_str());
#endif
	}

	void torrent::set_ssl_cert_buffer(std::string const& certificate
		, std::string const& private_key
		, std::string const& dh_params)
	{
		if (!m_ssl_ctx) return;

		boost::asio::const_buffer certificate_buf(certificate.c_str(), certificate.size());

		error_code ec;
		m_ssl_ctx->use_certificate(certificate_buf, ssl::context::pem, ec);

		boost::asio::const_buffer private_key_buf(private_key.c_str(), private_key.size());
		m_ssl_ctx->use_private_key(private_key_buf, ssl::context::pem, ec);

		boost::asio::const_buffer dh_params_buf(dh_params.c_str(), dh_params.size());
		m_ssl_ctx->use_tmp_dh(dh_params_buf, ec);
	}

#endif

	void torrent::on_exception(std::exception const&)
	{
		set_error(errors::no_memory, torrent_status::error_file_none);
	}

	void torrent::on_error(error_code const& ec)
	{
		set_error(ec, torrent_status::error_file_none);
	}

	void torrent::on_remove_peers() noexcept
	{
	}

	void torrent::remove_web_seed_iter(std::list<web_seed_t>::iterator web)
	{
	}

	void torrent::connect_to_url_seed(std::list<web_seed_t>::iterator web)
	{
	}

	void torrent::on_proxy_name_lookup(error_code const& e
		, std::vector<address> const& addrs
		, std::list<web_seed_t>::iterator web, int port) try
	{
		TORRENT_ASSERT(is_single_thread());

		INVARIANT_CHECK;

		TORRENT_ASSERT(web->resolving);
#ifndef TORRENT_DISABLE_LOGGING
		debug_log("completed resolve proxy hostname for: %s", web->url.c_str());
		if (e && should_log())
			debug_log("proxy name lookup error: %s", e.message().c_str());
#endif
		web->resolving = false;

		if (web->removed)
		{
#ifndef TORRENT_DISABLE_LOGGING
			debug_log("removed web seed");
#endif
			remove_web_seed_iter(web);
			return;
		}

		if (m_abort) return;
		if (m_ses.is_aborted()) return;

		if (e || addrs.empty())
		{
			// the name lookup failed for the http host. Don't try
			// this host again
			remove_web_seed_iter(web);
			return;
		}

		tcp::endpoint a(addrs[0], std::uint16_t(port));

		std::string hostname;
		error_code ec;
		std::string protocol;
		std::tie(protocol, std::ignore, hostname, port, std::ignore)
			= parse_url_components(web->url, ec);
		if (port == -1) port = protocol == "http" ? 80 : 443;

		if (ec)
		{
			remove_web_seed_iter(web);
			return;
		}

		if (m_ip_filter && m_ip_filter->access(a.address()) & ip_filter::blocked)
		{
			return;
		}

	}
	catch (...) { handle_exception(); }

	void torrent::on_name_lookup(error_code const& e
		, std::vector<address> const& addrs
		, int const port
		, std::list<web_seed_t>::iterator web) try
	{
	}
	catch (...) { handle_exception(); }

	void torrent::connect_web_seed(std::list<web_seed_t>::iterator web, tcp::endpoint a)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(is_single_thread());
		if (m_abort) return;

		if (m_ip_filter && m_ip_filter->access(a.address()) & ip_filter::blocked)
		{
			return;
		}
	}

	void torrent::verify_block_hashes(piece_index_t index)
	{
	}

	std::shared_ptr<const torrent_info> torrent::get_torrent_file() const
	{
		if (!m_torrent_file->is_valid()) return {};
		return m_torrent_file;
	}

	std::shared_ptr<torrent_info> torrent::get_torrent_copy_with_hashes() const
	{
		if (!m_torrent_file->is_valid()) return {};
		auto ret = std::make_shared<torrent_info>(*m_torrent_file);

		if (ret->v2())
		{
			aux::vector<aux::vector<char>, file_index_t> v2_hashes;
			for (auto const& tree : m_merkle_trees)
			{
				auto const& layer = tree.get_piece_layer();
				std::vector<char> out_layer;
				out_layer.reserve(layer.size() * sha256_hash::size());
				for (auto const& h : layer)
					out_layer.insert(out_layer.end(), h.data(), h.data() + sha256_hash::size());
				v2_hashes.emplace_back(std::move(out_layer));
			}
			ret->set_piece_layers(std::move(v2_hashes));
		}

		return ret;
	}

	std::vector<std::vector<sha256_hash>> torrent::get_piece_layers() const
	{
		std::vector<std::vector<sha256_hash>> ret;
		for (auto const& tree : m_merkle_trees)
			ret.emplace_back(tree.get_piece_layer());
		return ret;
	}

	void torrent::enable_all_trackers()
	{
		for (aux::announce_entry& ae : m_trackers)
			for (aux::announce_endpoint& aep : ae.endpoints)
				aep.enabled = true;
	}

	void torrent::write_resume_data(resume_data_flags_t const flags, add_torrent_params& ret) const
	{
	}

#if TORRENT_ABI_VERSION == 1
	void torrent::get_full_peer_list(std::vector<peer_list_entry>* v) const
	{
	}
#endif

	void torrent::get_download_queue(std::vector<partial_piece_info>* queue) const
	{

	}

#if defined TORRENT_SSL_PEERS
	struct hostname_visitor
	{
		explicit hostname_visitor(std::string const& h) : hostname_(h) {}
		template <typename T>
		void operator()(T&) {}
		template <typename T>
		void operator()(ssl_stream<T>& s) { s.set_host_name(hostname_); }
		std::string const& hostname_;
	};

	struct ssl_handle_visitor
	{
		template <typename T>
		ssl::stream_handle_type operator()(T&)
		{ return nullptr; }

		template <typename T>
		ssl::stream_handle_type operator()(ssl_stream<T>& s)
		{ return s.handle(); }
	};
#endif

	bool torrent::connect_to_peer(torrent_peer* peerinfo, bool const ignore_limit)
	{
		return true;
	}

	void torrent::initialize_merkle_trees()
	{
		if (!info_hash().has_v2()) return;

		bool valid = m_torrent_file->v2_piece_hashes_verified();

		file_storage const& fs = m_torrent_file->orig_files();
		m_merkle_trees.reserve(fs.num_files());
		for (file_index_t i : fs.file_range())
		{
			if (fs.pad_file_at(i) || fs.file_size(i) == 0)
			{
				m_merkle_trees.emplace_back();
				continue;
			}
			m_merkle_trees.emplace_back(fs.file_num_blocks(i)
				, fs.piece_length() / default_block_size, fs.root_ptr(i));
			auto const piece_layer = m_torrent_file->piece_layer(i);
			if (piece_layer.empty())
			{
				valid = false;
				continue;
			}

			if (!m_merkle_trees[i].load_piece_layer(piece_layer))
			{
				set_error(errors::torrent_invalid_piece_layer
					, torrent_status::error_file_metadata);
				valid = false;
				m_merkle_trees[i] = aux::merkle_tree();
			}
		}

		m_v2_piece_layers_validated = valid;

		m_torrent_file->free_piece_layers();
	}

	bool torrent::set_metadata(span<char const> metadata_buf)
	{
		TORRENT_ASSERT(is_single_thread());
		INVARIANT_CHECK;

		if (m_torrent_file->is_valid()) return false;

		if (m_torrent_file->info_hashes().has_v1())
		{
			sha1_hash const info_hash = hasher(metadata_buf).final();
			if (info_hash != m_torrent_file->info_hashes().v1)
			{
				// check if the v1 hash is a truncated v2 hash
				sha256_hash const info_hash2 = hasher256(metadata_buf).final();
				if (sha1_hash(info_hash2.data()) != m_torrent_file->info_hashes().v1)
				{
					return false;
				}
			}
		}
		if (m_torrent_file->info_hashes().has_v2())
		{
			// we don't have to worry about computing the v2 hash twice because
			// if the v1 hash was a truncated v2 hash then the torrent_file should
			// not have a v2 hash and we shouldn't get here
			sha256_hash const info_hash = hasher256(metadata_buf).final();
			if (info_hash != m_torrent_file->info_hashes().v2)
			{
				return false;
			}
		}

		error_code ec;
		bdecode_node const metadata = bdecode(metadata_buf, ec);
		if (ec || !m_torrent_file->parse_info_section(metadata, ec
			, settings().get_int(settings_pack::max_piece_count)))
		{
			update_gauge();
			set_error(errors::invalid_swarm_metadata, torrent_status::error_file_none);
			pause();
			return false;
		}
		return true;
	}

	bool torrent::want_tick() const
	{
		return false;
	}

	void torrent::update_want_tick()
	{
		update_list(aux::session_interface::torrent_want_tick, want_tick());
	}

	// this function adjusts which lists this torrent is part of (checking,
	// seeding or downloading)
	void torrent::update_state_list()
	{
		bool is_checking = false;
		bool is_downloading = false;
		bool is_seeding = false;

		if (is_auto_managed() && !has_error())
		{
			if (m_state == torrent_status::checking_files)
			{
				is_checking = true;
			}
			else if (m_state == torrent_status::downloading_metadata
				|| m_state == torrent_status::downloading
				|| m_state == torrent_status::finished
				|| m_state == torrent_status::seeding)
			{
				// torrents that are started (not paused) and
				// inactive are not part of any list. They will not be touched because
				// they are inactive
				if (is_finished())
					is_seeding = true;
				else
					is_downloading = true;
			}
		}

		update_list(aux::session_interface::torrent_downloading_auto_managed
			, is_downloading);
		update_list(aux::session_interface::torrent_seeding_auto_managed
			, is_seeding);
		update_list(aux::session_interface::torrent_checking_auto_managed
			, is_checking);
	}

	// returns true if this torrent is interested in connecting to more peers
	bool torrent::want_peers() const
	{
		return true;
	}

	bool torrent::want_peers_download() const
	{
		return (m_state == torrent_status::downloading
			|| m_state == torrent_status::downloading_metadata)
			&& want_peers();
	}

	bool torrent::want_peers_finished() const
	{
		return (m_state == torrent_status::finished
			|| m_state == torrent_status::seeding)
			&& want_peers();
	}

	void torrent::update_want_peers()
	{
		update_list(aux::session_interface::torrent_want_peers_download, want_peers_download());
		update_list(aux::session_interface::torrent_want_peers_finished, want_peers_finished());
	}

	void torrent::update_want_scrape()
	{
		update_list(aux::session_interface::torrent_want_scrape
			, m_paused && m_auto_managed && !m_abort);
	}

	void torrent::update_list(torrent_list_index_t const list, bool in)
	{

	}

	void torrent::disconnect_all(error_code const& ec, operation_t op)
	{
	}

	int torrent::disconnect_peers(int const num, error_code const& ec)
	{
		return 0;
	}

	// called when torrent is finished (all interesting
	// pieces have been downloaded)
	void torrent::finished()
	{
	}

	// this is called when we were finished, but some files were
	// marked for downloading, and we are no longer finished
	void torrent::resume_download()
	{
		// the invariant doesn't hold here, because it expects the torrent
		// to be in downloading state (which it will be set to shortly)
//		INVARIANT_CHECK;

		TORRENT_ASSERT(m_state != torrent_status::checking_resume_data
			&& m_state != torrent_status::checking_files);

		// we're downloading now, which means we're no longer in seed mode
		if (m_seed_mode)
			leave_seed_mode(seed_mode_t::check_files);

		TORRENT_ASSERT(!is_finished());
		set_state(torrent_status::downloading);
		set_queue_position(last_pos);

		m_completed_time = 0;

#ifndef TORRENT_DISABLE_LOGGING
		debug_log("*** RESUME_DOWNLOAD");
#endif
		send_upload_only();
		update_want_tick();
		update_state_list();
	}

	void torrent::maybe_done_flushing()
	{
	}

	// called when torrent is complete. i.e. all pieces downloaded
	// not necessarily flushed to disk
	void torrent::completed()
	{
		maybe_done_flushing();

		set_state(torrent_status::seeding);
		m_became_seed = aux::time_now32();

		if (!m_announcing) return;

		time_point32 const now = aux::time_now32();
		for (auto& t : m_trackers)
		{
			for (auto& aep : t.endpoints)
			{
				if (!aep.enabled) continue;
				for (auto& a : aep.info_hashes)
				{
					if (a.complete_sent) continue;
					a.next_announce = now;
					a.min_announce = now;
				}
			}
		}
		announce_with_tracker();
	}

	int torrent::deprioritize_tracker(int index)
	{
		INVARIANT_CHECK;

		TORRENT_ASSERT(index >= 0);
		TORRENT_ASSERT(index < int(m_trackers.size()));
		if (index >= int(m_trackers.size())) return -1;

		while (index < int(m_trackers.size()) - 1 && m_trackers[index].tier == m_trackers[index + 1].tier)
		{
			using std::swap;
			swap(m_trackers[index], m_trackers[index + 1]);
			if (m_last_working_tracker == index) ++m_last_working_tracker;
			else if (m_last_working_tracker == index + 1) --m_last_working_tracker;
			++index;
		}
		return index;
	}

	void torrent::files_checked()
	{
	}

	aux::alert_manager& torrent::alerts() const
	{
		TORRENT_ASSERT(is_single_thread());
		return m_ses.alerts();
	}

	bool torrent::is_seed() const
	{
		return true;
	}

	bool torrent::is_finished() const
	{
		return true;
	}

	bool torrent::is_inactive() const
	{
		return false;
	}

	std::string torrent::save_path() const
	{
		return m_save_path;
	}

	void torrent::rename_file(file_index_t const index, std::string name)
	{
		INVARIANT_CHECK;

		file_storage const& fs = m_torrent_file->files();
		TORRENT_ASSERT(index >= file_index_t(0));
		TORRENT_ASSERT(index < fs.end_file());
		TORRENT_UNUSED(fs);

		// storage may be nullptr during shutdown
		if (!m_storage)
		{
			return;
		}

		m_ses.disk_thread().async_rename_file(m_storage, index, std::move(name)
			, std::bind(&torrent::on_file_renamed, shared_from_this(), _1, _2, _3));
		m_ses.deferred_submit_jobs();
	}

	void torrent::move_storage(std::string const& save_path, move_flags_t const flags)
	{
		TORRENT_ASSERT(is_single_thread());
		INVARIANT_CHECK;

		if (m_abort)
		{
			return;
		}

		// if we don't have metadata yet, we don't know anything about the file
		// structure and we have to assume we don't have any file.
		if (!valid_metadata())
		{
#if TORRENT_USE_UNC_PATHS
			std::string path = canonicalize_path(save_path);
#else
			std::string const& path = save_path;
#endif
			m_save_path = complete(path);
			return;
		}

		// storage may be nullptr during shutdown
		if (m_storage)
		{
#if TORRENT_USE_UNC_PATHS
			std::string path = canonicalize_path(save_path);
#else
			std::string path = save_path;
#endif
			m_ses.disk_thread().async_move_storage(m_storage, std::move(path), flags
				, std::bind(&torrent::on_storage_moved, shared_from_this(), _1, _2, _3));
			m_moving_storage = true;
			m_ses.deferred_submit_jobs();
		}
		else
		{
#if TORRENT_USE_UNC_PATHS
			m_save_path = canonicalize_path(save_path);
#else

			m_save_path = save_path;
#endif
			set_need_save_resume();
		}
	}

	void torrent::on_storage_moved(status_t const status, std::string const& path
		, storage_error const& error) try
	{
		TORRENT_ASSERT(is_single_thread());

		m_moving_storage = false;
		if (status == status_t::no_error
			|| status == status_t::need_full_check)
		{
			m_save_path = path;
			set_need_save_resume();
			if (status == status_t::need_full_check)
				force_recheck();
		}
	}
	catch (...) { handle_exception(); }

	torrent_handle torrent::get_handle()
	{
		TORRENT_ASSERT(is_single_thread());
		return torrent_handle(shared_from_this());
	}

	aux::session_settings const& torrent::settings() const
	{
		TORRENT_ASSERT(is_single_thread());
		return m_ses.settings();
	}

#if TORRENT_USE_INVARIANT_CHECKS
	void torrent::check_invariant() const
	{
	}
#endif

	void torrent::set_sequential_download(bool const sd)
	{
	}

	void torrent::queue_up()
	{
	}

	void torrent::queue_down()
	{
		set_queue_position(next(queue_position()));
	}

	void torrent::set_queue_position(queue_position_t const p)
	{
		TORRENT_ASSERT(is_single_thread());

		// finished torrents may not change their queue positions, as it's set to
		// -1
		if ((m_abort || is_finished()) && p != no_pos) return;

		TORRENT_ASSERT((p == no_pos) == is_finished()
			|| (!m_auto_managed && p == no_pos)
			|| (m_abort && p == no_pos)
			|| (!m_added && p == no_pos));
		if (p == m_sequence_number) return;

		TORRENT_ASSERT(p >= no_pos);

		state_updated();
	}

	void torrent::set_max_uploads(int limit, bool const state_update)
	{
	}

	void torrent::set_max_connections(int limit, bool const state_update)
	{
	}

	void torrent::set_upload_limit(int const limit)
	{
	}

	void torrent::set_download_limit(int const limit)
	{
	}

	void torrent::set_limit_impl(int limit, int const channel, bool const state_update)
	{
	}

	void torrent::setup_peer_class()
	{
	}

	int torrent::limit_impl(int const channel) const
	{
        return 1;
	}

	int torrent::upload_limit() const
	{
		return 1;
	}

	int torrent::download_limit() const
	{
		return 1;
	}

	bool torrent::delete_files(remove_flags_t const options)
	{
		TORRENT_ASSERT(is_single_thread());

#ifndef TORRENT_DISABLE_LOGGING
		log_to_all_peers("deleting files");
#endif

		disconnect_all(errors::torrent_removed, operation_t::bittorrent);
		stop_announcing();

		// storage may be nullptr during shutdown
		if (m_storage)
		{
			TORRENT_ASSERT(m_storage);
			m_ses.disk_thread().async_delete_files(m_storage, options
				, std::bind(&torrent::on_files_deleted, shared_from_this(), _1));
			m_deleted = true;
			m_ses.deferred_submit_jobs();
			return true;
		}
		return false;
	}

	void torrent::clear_error()
	{
	}

	std::string torrent::resolve_filename(file_index_t const file) const
	{
		if (file == torrent_status::error_file_none) return "";
		if (file == torrent_status::error_file_ssl_ctx) return "SSL Context";
		if (file == torrent_status::error_file_exception) return "exception";
		if (file == torrent_status::error_file_partfile) return "partfile";
		if (file == torrent_status::error_file_metadata) return "metadata";

		if (m_storage && file >= file_index_t(0))
		{
			file_storage const& st = m_torrent_file->files();
			return st.file_path(file, m_save_path);
		}
		else
		{
			return m_save_path;
		}
	}

	void torrent::set_error(error_code const& ec, file_index_t const error_file)
	{
		TORRENT_ASSERT(is_single_thread());
		m_error = ec;
		m_error_file = error_file;

		update_gauge();

#ifndef TORRENT_DISABLE_LOGGING
		if (ec)
		{
			char buf[1024];
			std::snprintf(buf, sizeof(buf), "error %s: %s", ec.message().c_str()
				, resolve_filename(error_file).c_str());
			log_to_all_peers(buf);
		}
#endif

		state_updated();
		update_state_list();
	}

	void torrent::auto_managed(bool a)
	{
		TORRENT_ASSERT(is_single_thread());
		INVARIANT_CHECK;

		if (m_auto_managed == a) return;
		bool const checking_files = should_check_files();
		m_auto_managed = a;
		update_gauge();
		update_want_scrape();
		update_state_list();

		state_updated();

		// we need to save this new state as well
		set_need_save_resume();

		if (!checking_files && should_check_files())
		{
			start_checking();
		}
	}

	namespace {

	std::uint16_t clamped_subtract_u16(int const a, int const b)
	{
		if (a < b) return 0;
		return std::uint16_t(a - b);
	}

	} // anonymous namespace

	// this is called every time the session timer takes a step back. Since the
	// session time is meant to fit in 16 bits, it only covers a range of
	// about 18 hours. This means every few hours the whole epoch of this
	// clock is shifted forward. All timestamp in this clock must then be
	// shifted backwards to remain the same. Anything that's shifted back
	// beyond the new epoch is clamped to 0 (to represent the oldest timestamp
	// currently representable by the session_time)
	void torrent::step_session_time(int const seconds)
	{
		if (!m_peer_list) return;
		for (auto* pe : *m_peer_list)
		{
			pe->last_optimistically_unchoked
				= clamped_subtract_u16(pe->last_optimistically_unchoked, seconds);
			pe->last_connected = clamped_subtract_u16(pe->last_connected, seconds);
		}
	}

	// the higher seed rank, the more important to seed
	int torrent::seed_rank(aux::session_settings const& s) const
	{
		return 0;
	}

	// this is an async operation triggered by the client
	// TODO: add a flag to ignore stats, and only care about resume data for
	// content. For unchanged files, don't trigger a load of the metadata
	// just to save an empty resume data file
	void torrent::save_resume_data(resume_data_flags_t const flags)
	{
		TORRENT_ASSERT(is_single_thread());
		INVARIANT_CHECK;

		if (m_abort)
		{
			return;
		}

		if ((flags & torrent_handle::only_if_modified) && !m_need_save_resume_data)
		{
			return;
		}

		m_need_save_resume_data = false;
		state_updated();

		if ((flags & torrent_handle::flush_disk_cache) && m_storage)
		{
			m_ses.disk_thread().async_release_files(m_storage);
			m_ses.deferred_submit_jobs();
		}

		state_updated();

		add_torrent_params atp;
		write_resume_data(flags, atp);
	}

	bool torrent::should_check_files() const
	{
		TORRENT_ASSERT(is_single_thread());
		return m_state == torrent_status::checking_files
			&& !m_paused
			&& !has_error()
			&& !m_abort
			&& !m_session_paused;
	}

	void torrent::flush_cache()
	{
		TORRENT_ASSERT(is_single_thread());

		// storage may be nullptr during shutdown
		if (!m_storage)
		{
			TORRENT_ASSERT(m_abort);
			return;
		}
		m_ses.disk_thread().async_release_files(m_storage
			, std::bind(&torrent::on_cache_flushed, shared_from_this(), true));
		m_ses.deferred_submit_jobs();
	}

	void torrent::on_cache_flushed(bool const manually_triggered) try
	{
		TORRENT_ASSERT(is_single_thread());

		if (m_ses.is_aborted()) return;

	}
	catch (...) { handle_exception(); }

	void torrent::on_torrent_aborted()
	{
		TORRENT_ASSERT(is_single_thread());

		// there should be no more disk activity for this torrent now, we can
		// release the disk io handle
		m_storage.reset();
	}

	bool torrent::is_paused() const
	{
		return m_paused || m_session_paused;
	}

	void torrent::pause(pause_flags_t const flags)
	{
		TORRENT_ASSERT(is_single_thread());
		INVARIANT_CHECK;

		if (!m_paused)
		{
			// we need to save this new state
			set_need_save_resume();
		}

		set_paused(true, flags | torrent_handle::clear_disk_cache);
	}

	void torrent::do_pause(pause_flags_t const flags, bool const was_paused)
	{
	}

#ifndef TORRENT_DISABLE_LOGGING
	void torrent::log_to_all_peers(char const* message)
	{
	}
#endif

	// add or remove a url that will be attempted for
	// finding the file(s) in this torrent.
	web_seed_t* torrent::add_web_seed(std::string const& url
		, std::string const& auth
		, web_seed_entry::headers_t const& extra_headers
		, web_seed_flag_t const flags)
	{
		web_seed_t ent(url, auth, extra_headers);
		ent.ephemeral = bool(flags & ephemeral);
		ent.no_local_ips = bool(flags & no_local_ips);

		// don't add duplicates
		auto const it = std::find(m_web_seeds.begin(), m_web_seeds.end(), ent);
		if (it != m_web_seeds.end()) return &*it;
		m_web_seeds.emplace_back(std::move(ent));
		set_need_save_resume();
		update_want_tick();
		return &m_web_seeds.back();
	}

	void torrent::set_session_paused(bool const b)
	{
		if (m_session_paused == b) return;
		bool const paused_before = is_paused();
		m_session_paused = b;

		if (paused_before == is_paused()) return;

		if (b) do_pause();
		else do_resume();
	}

	void torrent::set_paused(bool const b, pause_flags_t flags)
	{
	}

	void torrent::resume()
	{
		TORRENT_ASSERT(is_single_thread());
		INVARIANT_CHECK;

		if (!m_paused
			&& m_announce_to_dht
			&& m_announce_to_trackers
			&& m_announce_to_lsd) return;

		m_announce_to_dht = true;
		m_announce_to_trackers = true;
		m_announce_to_lsd = true;
		m_paused = false;
		if (!m_session_paused) m_graceful_pause_mode = false;

		update_gauge();

		// we need to save this new state
		set_need_save_resume();

		do_resume();
	}

	void torrent::do_resume()
	{
		TORRENT_ASSERT(is_single_thread());
		if (is_paused())
		{
			update_want_tick();
			return;
		}

		m_started = aux::time_now32();
		if (is_seed()) m_became_seed = m_started;
		if (is_finished()) m_became_finished = m_started;

		clear_error();

		if (should_check_files()) start_checking();

		state_updated();
		update_want_peers();
		update_want_tick();
		update_want_scrape();
		update_gauge();

		if (m_state == torrent_status::checking_files) return;

		start_announcing();

		do_connect_boost();
	}

	namespace
	{
		struct timer_state
		{
			explicit timer_state(aux::listen_socket_handle s)
				: socket(std::move(s)) {}

			aux::listen_socket_handle socket;

			struct state_t
			{
				int tier = INT_MAX;
				bool found_working = false;
				bool done = false;
			};
			aux::array<state_t, num_protocols, protocol_version> state;
		};
	}

	void torrent::update_tracker_timer(time_point32 const now)
	{
		TORRENT_ASSERT(is_single_thread());
		if (!m_announcing)
		{
#ifndef TORRENT_DISABLE_LOGGING
			debug_log("*** update tracker timer: not announcing");
#endif
			return;
		}

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"
#endif
		aux::array<bool const, num_protocols, protocol_version> const supports_protocol{
		{
			m_info_hash.has_v1(),
			m_info_hash.has_v2()
		}};
#ifdef __clang__
#pragma clang diagnostic pop
#endif

		time_point32 next_announce = time_point32::max();

		std::vector<timer_state> listen_socket_states;

#ifndef TORRENT_DISABLE_LOGGING
		int idx = -1;
		if (should_log())
		{
			debug_log("*** update_tracker_timer: "
				"[ announce_to_all_tiers: %d announce_to_all_trackers: %d num_trackers: %d ]"
				, settings().get_bool(settings_pack::announce_to_all_tiers)
				, settings().get_bool(settings_pack::announce_to_all_trackers)
				, int(m_trackers.size()));
		}
#endif
		for (auto const& t : m_trackers)
		{
#ifndef TORRENT_DISABLE_LOGGING
			++idx;
#endif
			for (auto const& aep : t.endpoints)
			{
				auto aep_state_iter = std::find_if(listen_socket_states.begin(), listen_socket_states.end()
					, [&](timer_state const& s) { return s.socket == aep.socket; });
				if (aep_state_iter == listen_socket_states.end())
				{
					listen_socket_states.emplace_back(aep.socket);
					aep_state_iter = listen_socket_states.end() - 1;
				}
				timer_state& ep_state = *aep_state_iter;

				if (!aep.enabled) continue;
				for (protocol_version const ih : all_versions)
				{
					if (!supports_protocol[ih]) continue;

					auto& state = ep_state.state[ih];
					auto const& a = aep.info_hashes[ih];

					if (state.done) continue;

#ifndef TORRENT_DISABLE_LOGGING
					if (should_log())
					{
						debug_log("*** tracker: (%d) [ep: %s ] \"%s\" ["
							" found: %d i->tier: %d tier: %d"
							" working: %d fails: %d limit: %d upd: %d ]"
							, idx, print_endpoint(aep.local_endpoint).c_str(), t.url.c_str()
							, state.found_working, t.tier, state.tier, a.is_working()
							, a.fails, t.fail_limit, a.updating);
					}
#endif

					if (settings().get_bool(settings_pack::announce_to_all_tiers)
						&& state.found_working
						&& t.tier <= state.tier
						&& state.tier != INT_MAX)
						continue;

					if (t.tier > state.tier && !settings().get_bool(settings_pack::announce_to_all_tiers)) break;
					if (a.is_working()) { state.tier = t.tier; state.found_working = false; }
					if (a.fails >= t.fail_limit && t.fail_limit != 0) continue;
					if (a.updating)
					{
						state.found_working = true;
					}
					else
					{
						time_point32 const next_tracker_announce = std::max(a.next_announce, a.min_announce);
						if (next_tracker_announce < next_announce
							&& (!state.found_working || a.is_working()))
							next_announce = next_tracker_announce;
					}
					if (a.is_working()) state.found_working = true;
					if (state.found_working
						&& !settings().get_bool(settings_pack::announce_to_all_trackers)
						&& !settings().get_bool(settings_pack::announce_to_all_tiers))
						state.done = true;
				}
			}

			if (std::all_of(listen_socket_states.begin(), listen_socket_states.end()
				, [supports_protocol](timer_state const& s) {
					for (protocol_version const ih : all_versions)
					{
						if (supports_protocol[ih] && !s.state[ih].done)
							return false;
					}
					return true;
				}))
				break;
		}

		if (next_announce <= now) next_announce = now;

#ifndef TORRENT_DISABLE_LOGGING
		debug_log("*** update tracker timer: next_announce < now %d"
			" m_waiting_tracker: %d next_announce_in: %d"
			, next_announce <= now, m_waiting_tracker
			, int(total_seconds(next_announce - now)));
#endif

		// don't re-issue the timer if it's the same expiration time as last time
		// if m_waiting_tracker is 0, expires_at() is undefined
		if (m_waiting_tracker && m_tracker_timer.expiry() == next_announce) return;

		m_tracker_timer.expires_at(next_announce);
		ADD_OUTSTANDING_ASYNC("tracker::on_tracker_announce");
		++m_waiting_tracker;
		m_tracker_timer.async_wait([self = shared_from_this()](error_code const& e)
			{ self->wrap(&torrent::on_tracker_announce, e); });
	}

	void torrent::start_announcing()
	{
		TORRENT_ASSERT(is_single_thread());
		TORRENT_ASSERT(state() != torrent_status::checking_files);
		if (is_paused())
		{
#ifndef TORRENT_DISABLE_LOGGING
			debug_log("start_announcing(), paused");
#endif
			return;
		}
		// if we don't have metadata, we need to announce
		// before checking files, to get peers to
		// request the metadata from
		if (!m_files_checked && valid_metadata())
		{
#ifndef TORRENT_DISABLE_LOGGING
			debug_log("start_announcing(), files not checked (with valid metadata)");
#endif
			return;
		}
		if (m_announcing) return;

		m_announcing = true;

		if (!m_trackers.empty())
		{
			// tell the tracker that we're back
			for (auto& t : m_trackers) t.reset();
		}

		// reset the stats, since from the tracker's
		// point of view, this is a new session
		m_total_failed_bytes = 0;
		m_total_redundant_bytes = 0;
		m_stat.clear();

		update_want_tick();

		announce_with_tracker();

		lsd_announce();
	}

	void torrent::stop_announcing()
	{
		TORRENT_ASSERT(is_single_thread());
		if (!m_announcing) return;

		m_tracker_timer.cancel();

		m_announcing = false;

		time_point32 const now = aux::time_now32();
		for (auto& t : m_trackers)
		{
			for (auto& aep : t.endpoints)
			{
				for (auto& a : aep.info_hashes)
				{
					a.next_announce = now;
					a.min_announce = now;
				}
			}
		}
		announce_with_tracker(event_t::stopped);
	}

	seconds32 torrent::finished_time() const
	{
		if(!is_finished() || is_paused())
			return m_finished_time;

		return m_finished_time + duration_cast<seconds32>(
			aux::time_now() - m_became_finished);
	}

	seconds32 torrent::active_time() const
	{
		if (is_paused())
			return m_active_time;

		// m_active_time does not account for the current "session", just the
		// time before we last started this torrent. To get the current time, we
		// need to add the time since we started it
		return m_active_time + duration_cast<seconds32>(
			aux::time_now() - m_started);
	}

	seconds32 torrent::seeding_time() const
	{
		if(!is_seed() || is_paused())
			return m_seeding_time;
		// m_seeding_time does not account for the current "session", just the
		// time before we last started this torrent. To get the current time, we
		// need to add the time since we started it
		return m_seeding_time + duration_cast<seconds32>(
			aux::time_now() - m_became_seed);
	}

	seconds32 torrent::upload_mode_time() const
	{
		if(!m_upload_mode)
			return seconds32(0);

		return aux::time_now32() - m_upload_mode_time;
	}

	void torrent::second_tick(int const tick_interval_ms)
	{
	}

	bool torrent::is_inactive_internal() const
	{
		if (is_finished())
			return m_stat.upload_payload_rate()
				< settings().get_int(settings_pack::inactive_up_rate);
		else
			return m_stat.download_payload_rate()
				< settings().get_int(settings_pack::inactive_down_rate);
	}

	void torrent::on_inactivity_tick(error_code const& ec) try
	{
		m_pending_active_change = false;

		if (ec) return;

		bool const is_inactive = is_inactive_internal();
		if (is_inactive == m_inactive) return;

		m_inactive = is_inactive;

		update_state_list();
		update_want_tick();

	}
	catch (...) { handle_exception(); }

	namespace {
		int zero_or(int const val, int const def_val)
		{ return (val <= 0) ? def_val : val; }
	}

	void torrent::maybe_connect_web_seeds()
	{
	}

#ifndef TORRENT_DISABLE_SHARE_MODE
	void torrent::recalc_share_mode()
	{
	}
#endif // TORRENT_DISABLE_SHARE_MODE

	void torrent::sent_bytes(int const bytes_payload, int const bytes_protocol)
	{
		m_stat.sent_bytes(bytes_payload, bytes_protocol);
		m_ses.sent_bytes(bytes_payload, bytes_protocol);
	}

	void torrent::received_bytes(int const bytes_payload, int const bytes_protocol)
	{
		m_stat.received_bytes(bytes_payload, bytes_protocol);
		m_ses.received_bytes(bytes_payload, bytes_protocol);
	}

	void torrent::trancieve_ip_packet(int const bytes, bool const ipv6)
	{
		m_stat.trancieve_ip_packet(bytes, ipv6);
		m_ses.trancieve_ip_packet(bytes, ipv6);
	}

	void torrent::sent_syn(bool const ipv6)
	{
		m_stat.sent_syn(ipv6);
		m_ses.sent_syn(ipv6);
	}

	void torrent::received_synack(bool const ipv6)
	{
		m_stat.received_synack(ipv6);
		m_ses.received_synack(ipv6);
	}

	std::set<std::string> torrent::web_seeds() const
	{
		TORRENT_ASSERT(is_single_thread());
		std::set<std::string> ret;
		return ret;
	}

	void torrent::remove_web_seed(std::string const& url)
	{
		auto const i = std::find_if(m_web_seeds.begin(), m_web_seeds.end()
			, [&] (web_seed_t const& w) { return w.url == url; });

		if (i != m_web_seeds.end())
		{
			remove_web_seed_iter(i);
			set_need_save_resume();
		}
	}

	torrent_state torrent::get_peer_list_state()
	{
		torrent_state ret;
		ret.is_finished = is_finished();
		ret.allow_multiple_connections_per_ip = settings().get_bool(settings_pack::allow_multiple_connections_per_ip);
		ret.max_peerlist_size = is_paused()
			? settings().get_int(settings_pack::max_paused_peerlist_size)
			: settings().get_int(settings_pack::max_peerlist_size);
		ret.min_reconnect_time = settings().get_int(settings_pack::min_reconnect_time);

		ret.ip = m_ses.external_address();
		ret.port = m_ses.listen_port();
		ret.max_failcount = settings().get_int(settings_pack::max_failcount);
		return ret;
	}

	bool torrent::try_connect_peer()
	{
		return true;
	}

	bool torrent::ban_peer(torrent_peer* tp)
	{
		if (!settings().get_bool(settings_pack::ban_web_seeds) && tp->web_seed)
			return false;

		need_peer_list();
		if (!m_peer_list->ban_peer(tp)) return false;
		update_want_peers();

		inc_stats_counter(counters::num_banned_peers);
		return true;
	}

	void torrent::set_seed(torrent_peer* p, bool const s)
	{
		if (bool(p->seed) == s) return;
		if (s)
		{
			TORRENT_ASSERT(m_num_seeds < 0xffff);
			++m_num_seeds;
		}
		else
		{
			TORRENT_ASSERT(m_num_seeds > 0);
			--m_num_seeds;
		}

		need_peer_list();
		m_peer_list->set_seed(p, s);
		update_auto_sequential();
	}

	void torrent::clear_failcount(torrent_peer* p)
	{
		need_peer_list();
		m_peer_list->set_failcount(p, 0);
		update_want_peers();
	}

	std::pair<peer_list::iterator, peer_list::iterator> torrent::find_peers(address const& a)
	{
		need_peer_list();
		return m_peer_list->find_peers(a);
	}

	void torrent::update_peer_port(int const port, torrent_peer* p
		, peer_source_flags_t const src)
	{
		need_peer_list();
		torrent_state st = get_peer_list_state();
		m_peer_list->update_peer_port(port, p, src, &st);
		peers_erased(st.erased);
		update_want_peers();
	}

	// verify piece is used when checking resume data or when the user
	// adds a piece
	void torrent::verify_piece(piece_index_t const piece)
	{
	}

	aux::announce_entry* torrent::find_tracker(std::string const& url)
	{
		auto i = std::find_if(m_trackers.begin(), m_trackers.end()
			, [&url](aux::announce_entry const& ae) { return ae.url == url; });
		if (i == m_trackers.end()) return nullptr;
		return &*i;
	}

	void torrent::ip_filter_updated()
	{
		if (!m_apply_ip_filter) return;
		if (!m_peer_list) return;
		if (!m_ip_filter) return;

		torrent_state st = get_peer_list_state();
		std::vector<address> banned;
		m_peer_list->apply_ip_filter(*m_ip_filter, &st, banned);

		peers_erased(st.erased);
	}

	void torrent::port_filter_updated()
	{
		if (!m_apply_ip_filter) return;
		if (!m_peer_list) return;

		torrent_state st = get_peer_list_state();
		std::vector<address> banned;
		m_peer_list->apply_port_filter(m_ses.get_port_filter(), &st, banned);

		peers_erased(st.erased);
	}

	// this is called when torrent_peers are removed from the peer_list
	// (peer-list). It removes any references we may have to those torrent_peers,
	// so we don't leave then dangling
	void torrent::peers_erased(std::vector<torrent_peer*> const& peers)
	{
	}

	void torrent::new_external_ip()
	{
		if (m_peer_list) m_peer_list->clear_peer_prio();
	}

	void torrent::stop_when_ready(bool const b)
	{
		m_stop_when_ready = b;

		// to avoid race condition, if we're already in a downloading state,
		// trigger the stop-when-ready logic immediately.
		if (m_stop_when_ready && is_downloading_state(m_state))
		{
#ifndef TORRENT_DISABLE_LOGGING
			debug_log("stop_when_ready triggered");
#endif
			auto_managed(false);
			pause();
			m_stop_when_ready = false;
		}
	}

	void torrent::set_state(torrent_status::state_t const s)
	{
		TORRENT_ASSERT(is_single_thread());
		TORRENT_ASSERT(s != 0); // this state isn't used anymore

#if TORRENT_USE_ASSERTS

		if (s == torrent_status::seeding)
		{
			TORRENT_ASSERT(is_seed());
			TORRENT_ASSERT(is_finished());
		}
		if (s == torrent_status::finished)
			TORRENT_ASSERT(is_finished());
		if (s == torrent_status::downloading && m_state == torrent_status::finished)
			TORRENT_ASSERT(!is_finished());
#endif

		if (int(m_state) == s) return;

		if (m_stop_when_ready
			&& !is_downloading_state(m_state)
			&& is_downloading_state(s))
		{
#ifndef TORRENT_DISABLE_LOGGING
			debug_log("stop_when_ready triggered");
#endif
			// stop_when_ready is set, and we're transitioning from a downloading
			// state to a non-downloading state. pause the torrent. Note that
			// "downloading" is defined broadly to include any state where we
			// either upload or download (for the purpose of this flag).
			auto_managed(false);
			pause();
			m_stop_when_ready = false;
		}

		m_state = s;

#ifndef TORRENT_DISABLE_LOGGING
		debug_log("set_state() %d", m_state);
#endif

		update_gauge();
		update_want_peers();
		update_want_tick();
		update_state_list();

		state_updated();

	}

	void torrent::state_updated()
	{
		// if this fails, this function is probably called
		// from within the torrent constructor, which it
		// shouldn't be. Whichever function ends up calling
		// this should probably be moved to torrent::start()
		TORRENT_ASSERT(shared_from_this());

	}

	void torrent::status(torrent_status* st, status_flags_t const flags)
	{
	}

	int torrent::priority() const
	{
		return 1;
	}

#if TORRENT_ABI_VERSION == 1
	void torrent::set_priority(int const prio)
	{
		// priority 1 is default
		if (prio == 1 && m_peer_class == peer_class_t{}) return;

		if (m_peer_class == peer_class_t{})
			setup_peer_class();

		state_updated();
	}
#endif

	void torrent::add_redundant_bytes(int const b, waste_reason const reason)
	{
		TORRENT_ASSERT(is_single_thread());
		TORRENT_ASSERT(b > 0);
		TORRENT_ASSERT(static_cast<int>(reason) >= 0);
		TORRENT_ASSERT(static_cast<int>(reason) < static_cast<int>(waste_reason::max));

		if (m_total_redundant_bytes <= std::numeric_limits<std::int64_t>::max() - b)
			m_total_redundant_bytes += b;
		else
			m_total_redundant_bytes = std::numeric_limits<std::int64_t>::max();

		// the stats counters are 64 bits, so we don't check for overflow there
		m_stats_counters.inc_stats_counter(counters::recv_redundant_bytes, b);
		m_stats_counters.inc_stats_counter(counters::waste_piece_timed_out + static_cast<int>(reason), b);
	}

	void torrent::add_failed_bytes(int const b)
	{
		TORRENT_ASSERT(is_single_thread());
		TORRENT_ASSERT(b > 0);
		if (m_total_failed_bytes <= std::numeric_limits<std::int64_t>::max() - b)
			m_total_failed_bytes += b;
		else
			m_total_failed_bytes = std::numeric_limits<std::int64_t>::max();

		// the stats counters are 64 bits, so we don't check for overflow there
		m_stats_counters.inc_stats_counter(counters::recv_failed_bytes, b);
	}

	// the number of connected peers that are seeds
	int torrent::num_seeds() const
	{
		TORRENT_ASSERT(is_single_thread());
		INVARIANT_CHECK;

		return int(m_num_seeds) - int(m_num_connecting_seeds);
	}

	// the number of connected peers that are not seeds
	int torrent::num_downloaders() const
	{
		return 0;
	}

	void torrent::tracker_request_error(tracker_request const& r
		, error_code const& ec, operation_t const op, std::string const& msg
		, seconds32 const retry_interval)
	{
		TORRENT_ASSERT(is_single_thread());

		INVARIANT_CHECK;

// some older versions of clang had a bug where it would fire this warning here
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"
#endif
		aux::array<bool const, num_protocols, protocol_version> const supports_protocol
		{ {
			m_info_hash.has_v1(),
			m_info_hash.has_v2()
		} };
#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifndef TORRENT_DISABLE_LOGGING
		if (should_log())
		{
			debug_log("*** tracker error: (%d) %s [%s] %s", ec.value()
				, ec.message().c_str(), operation_name(op), msg.c_str());
		}
#endif
		if (!(r.kind & tracker_request::scrape_request))
		{
			// announce request
			aux::announce_entry* ae = find_tracker(r.url);
			int fails = 0;
			tcp::endpoint local_endpoint;
			if (ae)
			{
				auto aep = std::find_if(ae->endpoints.begin(), ae->endpoints.end()
					, [&](aux::announce_endpoint const& e) { return e.socket == r.outgoing_socket; });

				if (aep != ae->endpoints.end())
				{
					protocol_version const hash_version = r.info_hash == m_info_hash.v1
						? protocol_version::V1 : protocol_version::V2;
					auto& a = aep->info_hashes[hash_version];
					local_endpoint = aep->local_endpoint;
					a.failed(settings().get_int(settings_pack::tracker_backoff)
						, retry_interval);
					a.last_error = ec;
					a.message = msg;
					fails = a.fails;

#ifndef TORRENT_DISABLE_LOGGING
					debug_log("*** increment tracker fail count [ep: %s url: %s %d]"
						, print_endpoint(aep->local_endpoint).c_str(), r.url.c_str(), a.fails);
#endif
					// don't try to announce from this endpoint again
					if (ec == boost::system::errc::address_family_not_supported
						|| ec == boost::system::errc::host_unreachable
						|| ec == lt::errors::announce_skipped)
					{
						aep->enabled = false;
#ifndef TORRENT_DISABLE_LOGGING
						debug_log("*** disabling endpoint [ep: %s url: %s ]"
							, print_endpoint(aep->local_endpoint).c_str(), r.url.c_str());
#endif
					}
				}
				else if (r.outgoing_socket)
				{
#ifndef TORRENT_DISABLE_LOGGING
					debug_log("*** no matching endpoint for request [%s, %s]"
						, r.url.c_str(), print_endpoint(r.outgoing_socket.get_local_endpoint()).c_str());
#endif
				}

				int const tracker_index = int(ae - m_trackers.data());

				// never talk to this tracker again
				if (ec == error_code(410, http_category())) ae->fail_limit = 1;

				// if all endpoints fail, then we de-prioritize the tracker and try
				// the next one in the tier
				if (std::all_of(ae->endpoints.begin(), ae->endpoints.end()
					, [&](aux::announce_endpoint const& ep)
					{
						for (protocol_version const ih : all_versions)
							if (supports_protocol[ih] && ep.info_hashes[ih].is_working())
								return false;
						return true;
					}))
				{
					deprioritize_tracker(tracker_index);
				}
			}
		}
		else
		{
			aux::announce_entry* ae = find_tracker(r.url);

			// scrape request
			if (ec == error_code(410, http_category()))
			{
				// never talk to this tracker again
				if (ae != nullptr) ae->fail_limit = 1;
			}
		}
		// announce to the next working tracker
		// We may have changed state into checking by now, in which case we
		// shouldn't keep trying to announce
		if ((!m_abort && !is_paused() && state() != torrent_status::checking_files)
			|| r.event == event_t::stopped)
		{
			announce_with_tracker(r.event);
		}
		update_tracker_timer(aux::time_now32());
	}

#ifndef TORRENT_DISABLE_LOGGING
	bool torrent::should_log() const
	{
		return true;
	}

	TORRENT_FORMAT(2,3)
	void torrent::debug_log(char const* fmt, ...) const noexcept try
	{
		va_list v;
		va_start(v, fmt);
		va_end(v);
	}
	catch (std::exception const&) {}
#endif

}
