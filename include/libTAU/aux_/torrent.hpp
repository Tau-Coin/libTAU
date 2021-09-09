/*

Copyright (c) 2003-2021, Arvid Norberg
Copyright (c) 2003, Daniel Wallin
Copyright (c) 2004, Magnus Jonsson
Copyright (c) 2016-2021, Alden Torres
Copyright (c) 2017, Falcosc
Copyright (c) 2017, Pavel Pimenov
Copyright (c) 2017, AllSeeingEyeTolledEweSew
Copyright (c) 2018-2019, Steven Siloti
Copyright (c) 2018, d-komarov
Copyright (c) 2019, ghbplayer
Copyright (c) 2020, Viktor Elofsson
Copyright (c) 2020, Paul-Louis Ageneau
Copyright (c) 2021, AdvenT
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_TORRENT_HPP_INCLUDE
#define TORRENT_TORRENT_HPP_INCLUDE

#include <algorithm>
#include <vector>
#include <set>
#include <list>
#include <deque>
#include <limits> // for numeric_limits
#include <memory> // for unique_ptr
#include <optional>

#include "libTAU/aux_/disable_warnings_push.hpp"
#include <boost/logic/tribool.hpp>
#include "libTAU/aux_/disable_warnings_pop.hpp"

#include "libTAU/fwd.hpp"
#include "libTAU/torrent_handle.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/torrent_info.hpp"
#include "libTAU/socket.hpp"
#include "libTAU/address.hpp"
#include "libTAU/aux_/tracker_manager.hpp"
#include "libTAU/aux_/stat.hpp"
#include "libTAU/alert.hpp"
#include "libTAU/config.hpp"
#include "libTAU/aux_/bandwidth_limit.hpp"
#include "libTAU/aux_/bandwidth_queue_entry.hpp"
#include "libTAU/storage_defs.hpp"
#include "libTAU/assert.hpp"
#include "libTAU/aux_/session_interface.hpp"
#include "libTAU/aux_/time.hpp"
#include "libTAU/aux_/deadline_timer.hpp"
#include "libTAU/aux_/peer_class_set.hpp"
#include "libTAU/aux_/link.hpp"
#include "libTAU/aux_/vector_utils.hpp"
#include "libTAU/aux_/debug.hpp"
#include "libTAU/disk_interface.hpp"
#include "libTAU/aux_/suggest_piece.hpp"
#include "libTAU/units.hpp"
#include "libTAU/aux_/vector.hpp"
#include "libTAU/aux_/deferred_handler.hpp"
#include "libTAU/aux_/allocating_handler.hpp"
#include "libTAU/aux_/announce_entry.hpp"
#include "libTAU/extensions.hpp" // for add_peer_flags_t
#include "libTAU/aux_/ssl.hpp"

// define as 0 to disable. 1 enables debug output of the pieces and requested
// blocks. 2 also enables trace output of the time critical piece picking
// logic
#define TORRENT_DEBUG_STREAMING 0

namespace libTAU::aux {

	struct tracker_request;
	class http_parser;

	using web_seed_flag_t = flags::bitfield_flag<std::uint8_t, struct web_seed_flag_tag>;

	// internal
	enum class waste_reason
	{
		piece_timed_out, piece_cancelled, piece_unknown, piece_seed
		, piece_end_game, piece_closing
		, max
	};

#ifndef TORRENT_DISABLE_STREAMING
	struct time_critical_piece
	{
		// when this piece was first requested
		time_point first_requested;
		// when this piece was last requested
		time_point last_requested;
		// by what time we want this piece
		time_point deadline;
		// 1 = send alert with piece data when available
		deadline_flags_t flags;
		// how many peers it's been requested from
		int peers;
		// the piece index
		piece_index_t piece;
#if TORRENT_DEBUG_STREAMING > 0
		// the number of multiple requests are allowed
		// to blocks still not downloaded (debugging only)
		int timed_out;
#endif
		bool operator<(time_critical_piece const& rhs) const
		{ return deadline < rhs.deadline; }
	};
#endif // TORRENT_DISABLE_STREAMING

	struct TORRENT_EXTRA_EXPORT torrent_hot_members
	{
		torrent_hot_members(aux::session_interface& ses
			, add_torrent_params const& p, bool session_paused);

	protected:

		// TODO: make this a raw pointer. perhaps keep the shared_ptr
		// around further down the object to maintain an owner
		std::shared_ptr<torrent_info> m_torrent_file;

		// a back reference to the session
		// this torrent belongs to.
		aux::session_interface& m_ses;

		// this vector is sorted at all times, by the pointer value.
		// use sorted_insert() and sorted_find() on it. The GNU STL
		// implementation on Darwin uses significantly less memory to
		// represent a vector than a set, and this set is typically
		// relatively small, and it's cheap to copy pointers.

		// the scrape data from the tracker response, this
		// is optional and may be 0xffffff
		std::uint32_t m_complete:24;

		// set to true when this torrent may not download anything
		bool m_upload_mode:1;

		// this is set to false as long as the connections
		// of this torrent haven't been initialized. If we
		// have metadata from the start, connections are
		// initialized immediately, if we didn't have metadata,
		// they are initialized right after files_checked().
		// valid_resume_data() will return false as long as
		// the connections aren't initialized, to avoid
		// them from altering the piece-picker before it
		// has been initialized with files_checked().
		bool m_connections_initialized:1;

		// is set to true when the torrent has
		// been aborted.
		bool m_abort:1;

		// is true if this torrent has allows having peers
		bool m_paused:1;

		// is true if the session is paused, in which case the torrent is
		// effectively paused as well.
		bool m_session_paused:1;

#ifndef TORRENT_DISABLE_SHARE_MODE
		// this is set when the torrent is in share-mode
		bool m_share_mode:1;
#endif

		// this is true if we have all pieces. If it's false,
		// it means we either don't have any pieces, or, if
		// there is a piece_picker object present, it contains
		// the state of how many pieces we have
		bool m_have_all:1;

		// set to true when this torrent has been paused but
		// is waiting to finish all current download requests
		// before actually closing all connections, when in graceful pause mode,
		// m_paused is also true.
		bool m_graceful_pause_mode:1;

		// state subscription. If set, a pointer to this torrent will be added
		// to the session_impl::m_torrent_lists[torrent_state_updates]
		// whenever this torrent's state changes (any state).
		bool m_state_subscription:1;

		// the maximum number of connections for this torrent
		std::uint32_t m_max_connections:24;

		// the state of this torrent (queued, checking, downloading, etc.)
		std::uint32_t m_state:3;
	};

	// a torrent is a class that holds information
	// for a specific download. It updates itself against
	// the tracker
	struct TORRENT_EXTRA_EXPORT torrent
		: private single_threaded
		, private torrent_hot_members
		, request_callback
		, peer_class_set
		, std::enable_shared_from_this<torrent>
	{
		// add_torrent_params may contain large merkle trees that are best
		// moved. Deleting the const& overload ensures that it's always moved in.
		torrent(aux::session_interface& ses, bool session_paused, add_torrent_params&& p);
		torrent(aux::session_interface&, bool, add_torrent_params const& p) = delete;
		~torrent() override;

		// This may be called from multiple threads
		info_hash_t const& info_hash() const { return m_info_hash; }

		bool is_deleted() const { return m_deleted; }

		// starts the announce timer
		void start();

		void added()
		{
			TORRENT_ASSERT(m_added == false);
			m_added = true;
			update_gauge();
		}

		void removed()
		{
			TORRENT_ASSERT(m_added == true);
			m_added = false;
			set_queue_position(no_pos);
			// make sure we decrement the gauge counter for this torrent
			update_gauge();
		}

		// returns which stats gauge this torrent currently
		// has incremented.
		int current_stats_state() const;

#if TORRENT_USE_ASSERTS
		bool is_single_thread() const { return single_threaded::is_single_thread(); }
#endif

		// this is called when the torrent has metadata.
		// it will initialize the storage and the piece-picker
		void init();

		void load_merkle_trees(aux::vector<std::vector<sha256_hash>, file_index_t> t
			, aux::vector<std::vector<bool>, file_index_t> mask);

		// checks to see if this peer id is used in one of our own outgoing
		// connections.
		bool is_self_connection(peer_id const& pid) const;

		void on_resume_data_checked(status_t status, storage_error const& error);
		void on_force_recheck(status_t status, storage_error const& error);
		void on_piece_hashed(aux::vector<sha256_hash> block_hashes
			, piece_index_t piece, sha1_hash const& piece_hash
			, storage_error const& error);
		void files_checked();
		void start_checking();

		void start_announcing();
		void stop_announcing();

		void send_upload_only();

#ifndef TORRENT_DISABLE_SHARE_MODE
		void send_share_mode();
		void set_share_mode(bool s);
		bool share_mode() const { return m_share_mode; }
#endif

		// TODO: make graceful pause also finish all sending blocks
		// before disconnecting
		bool graceful_pause() const { return m_graceful_pause_mode; }

		void set_upload_mode(bool b);
		bool upload_mode() const { return m_upload_mode || m_graceful_pause_mode; }
		bool is_upload_only() const { return is_finished() || upload_mode(); }

		int seed_rank(aux::session_settings const& s) const;

		void on_disk_write_complete(storage_error const& error
			, peer_request const& p);

		void set_progress_ppm(int p) { m_progress_ppm = std::uint32_t(p); }
		struct read_piece_struct
		{
			boost::shared_array<char> piece_data;
			int blocks_left;
			bool fail;
			error_code error;
		};
		void read_piece(piece_index_t);
		void set_sequential_range(piece_index_t first_piece, piece_index_t last_piece);
		void set_sequential_range(piece_index_t first_piece);
		void on_disk_read_complete(disk_buffer_holder, storage_error const&
			, peer_request const&, std::shared_ptr<read_piece_struct>);

		storage_mode_t storage_mode() const;

		// this will flag the torrent as aborted. The main
		// loop in session_impl will check for this state
		// on all torrents once every second, and take
		// the necessary actions then.
		void abort();
		bool is_aborted() const { return m_abort; }
		void panic();

		void new_external_ip();

		torrent_status::state_t state() const
		{ return torrent_status::state_t(m_state); }
		void set_state(torrent_status::state_t s);

		aux::session_settings const& settings() const;
		aux::session_interface& session() { return m_ses; }

		void set_sequential_download(bool sd);
		bool is_sequential_download() const
		{ return m_sequential_download || m_auto_sequential; }

		void queue_up();
		void queue_down();
		void set_queue_position(queue_position_t p);
		queue_position_t queue_position() const { return m_sequence_number; }
		// used internally
		void set_queue_position_impl(queue_position_t const p)
		{
			if (m_sequence_number == p) return;
			m_sequence_number = p;
			state_updated();
		}

		void second_tick(int tick_interval_ms);

		// see if we need to connect to web seeds, and if so,
		// connect to them
		void maybe_connect_web_seeds();

		std::string name() const;

		stat statistics() const { return m_stat; }
		std::optional<std::int64_t> bytes_left() const;

		void bytes_done(torrent_status& st, status_flags_t) const;

		void sent_bytes(int bytes_payload, int bytes_protocol);
		void received_bytes(int bytes_payload, int bytes_protocol);
		void trancieve_ip_packet(int bytes, bool ipv6);
		void sent_syn(bool ipv6);
		void received_synack(bool ipv6);

		void set_ip_filter(std::shared_ptr<const ip_filter> ipf);
		void port_filter_updated();
		ip_filter const* get_ip_filter() { return m_ip_filter.get(); }

		std::string resolve_filename(file_index_t file) const;
		void handle_exception();

		enum class disk_class { none, write };
		void clear_error();

		void set_error(error_code const& ec, file_index_t file);
		bool has_error() const { return !!m_error; }
		error_code error() const { return m_error; }

		void flush_cache();
		void pause(pause_flags_t flags = {});
		void resume();

		void set_session_paused(bool b);
		void set_paused(bool b, pause_flags_t flags = torrent_handle::clear_disk_cache);
		void set_announce_to_dht(bool b) { m_announce_to_dht = b; }
		void set_announce_to_trackers(bool b) { m_announce_to_trackers = b; }
		void set_announce_to_lsd(bool b) { m_announce_to_lsd = b; }

		void stop_when_ready(bool b);

		time_point32 started() const { return m_started; }
		void step_session_time(int seconds);
		void do_pause(pause_flags_t flags = torrent_handle::clear_disk_cache, bool was_paused = false);
		void do_resume();

		seconds32 finished_time() const;
		seconds32 active_time() const;
		seconds32 seeding_time() const;
		seconds32 upload_mode_time() const;

		bool is_paused() const;
		bool is_torrent_paused() const { return m_paused; }
		void force_recheck();
		void save_resume_data(resume_data_flags_t flags);

		bool need_save_resume_data() const { return m_need_save_resume_data; }

		void set_need_save_resume()
		{
			m_need_save_resume_data = true;
		}

		bool is_auto_managed() const { return m_auto_managed; }
		void auto_managed(bool a);

		bool should_check_files() const;

		bool delete_files(remove_flags_t options);
		void peers_erased(std::vector<torrent_peer*> const& peers);

		void piece_availability(aux::vector<int, piece_index_t>& avail) const;

		void prioritize_pieces(aux::vector<download_priority_t, piece_index_t> const& pieces);
		void prioritize_piece_list(std::vector<std::pair<piece_index_t, download_priority_t>> const& pieces);

		void set_file_priority(file_index_t index, download_priority_t priority);
		download_priority_t file_priority(file_index_t index) const;

		void on_file_priority(storage_error const& err, aux::vector<download_priority_t, file_index_t> prios);
		void prioritize_files(aux::vector<download_priority_t, file_index_t> files);
		void file_priorities(aux::vector<download_priority_t, file_index_t>*) const;

#ifndef TORRENT_DISABLE_STREAMING
		void cancel_non_critical();
		void set_piece_deadline(piece_index_t piece, int t, deadline_flags_t flags);
		void reset_piece_deadline(piece_index_t piece);
		void clear_time_critical();
#endif // TORRENT_DISABLE_STREAMING

		void status(torrent_status* st, status_flags_t flags);

		// this torrent changed state, if the user is subscribing to
		// it, add it to the m_state_updates list in session_impl
		void state_updated();

#if TORRENT_ABI_VERSION == 1
		void use_interface(std::string net_interface);
#endif

		bool connect_to_peer(torrent_peer*, bool ignore_limit = false);

		int priority() const;
#if TORRENT_ABI_VERSION == 1
		void set_priority(int prio);
#endif // TORRENT_ABI_VERSION

// --------------------------------------------
		// BANDWIDTH MANAGEMENT

		void set_upload_limit(int limit);
		int upload_limit() const;
		void set_download_limit(int limit);
		int download_limit() const;

		peer_class_t peer_class() const { return m_peer_class; }

		void set_max_uploads(int limit, bool state_update = true);
		int max_uploads() const { return int(m_max_uploads); }
		void set_max_connections(int limit, bool state_update = true);
		int max_connections() const { return int(m_max_connections); }

// --------------------------------------------
		// PEER MANAGEMENT

		static inline constexpr web_seed_flag_t ephemeral = 0_bit;
		static inline constexpr web_seed_flag_t no_local_ips = 1_bit;

		std::set<std::string> web_seeds() const;

		bool free_upload_slots() const
		{ return m_num_uploads < m_max_uploads; }

		void trigger_unchoke() noexcept;
		void trigger_optimistic_unchoke() noexcept;

		bool want_tick() const;
		void update_want_tick();
		void update_state_list();

		bool want_peers() const;
		bool want_peers_download() const;
		bool want_peers_finished() const;

		void update_want_peers();
		void update_want_scrape();
		void update_gauge();

		bool try_connect_peer();
		bool ban_peer(torrent_peer* tp);
		void update_peer_port(int port, torrent_peer* p, peer_source_flags_t src);
		void set_seed(torrent_peer* p, bool s);
		void clear_failcount(torrent_peer* p);

		// the number of peers that belong to this torrent
		int num_seeds() const;
		int num_downloaders() const;

		void get_download_queue(std::vector<partial_piece_info>* queue) const;

		void update_auto_sequential();
	public:
// --------------------------------------------
		// TRACKER MANAGEMENT

		// these are callbacks called by the tracker_connection instance
		// (either http_tracker_connection or udp_tracker_connection)
		// when this torrent got a response from its tracker request
		// or when a failure occurred
		void tracker_response(
			tracker_request const& r
			, address const& tracker_ip
			, std::list<address> const& tracker_ips
			, struct tracker_response const& resp) override;
		void tracker_request_error(tracker_request const& r
			, error_code const& ec, operation_t op, const std::string& msg
			, seconds32 retry_interval) override;
		void tracker_warning(tracker_request const& req
			, std::string const& msg) override;
		void tracker_scrape_response(tracker_request const& req
			, int complete, int incomplete, int downloaded, int downloaders) override;

		void update_scrape_state();

#if TORRENT_ABI_VERSION == 1
		// if no password and username is set
		// this will return an empty string, otherwise
		// it will concatenate the login and password
		// ready to be sent over http (but without
		// base64 encoding).
		std::string tracker_login() const;
#endif

		// generate the tracker key for this torrent.
		// The key is passed to http trackers as ``&key=``.
		std::uint32_t tracker_key() const;

		// if we need a connect boost, connect some peers
		// immediately
		void do_connect_boost();

		// forcefully sets next_announce to the current time
		void force_tracker_request(time_point, int tracker_idx, reannounce_flags_t flags);
		void scrape_tracker(int idx, bool user_triggered);
		void announce_with_tracker(event_t e = event_t::none);

#ifndef TORRENT_DISABLE_DHT
		void dht_announce();
#endif

#if TORRENT_ABI_VERSION == 1
		// sets the username and password that will be sent to
		// the tracker
		void set_tracker_login(std::string const& name, std::string const& pw);
#endif

		aux::announce_entry* find_tracker(std::string const& url);

// --------------------------------------------
		// PIECE MANAGEMENT

#ifndef TORRENT_DISABLE_SHARE_MODE
		void recalc_share_mode();
#endif

#ifndef TORRENT_DISABLE_SUPERSEEDING
		bool super_seeding() const
		{
			// we're not super seeding if we're not a seed
			return m_super_seeding;
		}

		void set_super_seeding(bool on);
		piece_index_t get_piece_to_super_seed(typed_bitfield<piece_index_t> const&);
#endif

#ifndef TORRENT_DISABLE_PREDICTIVE_PIECES
		// a predictive piece is a piece that we might
		// not have yet, but still announced to peers, anticipating that
		// we'll have it very soon
		bool is_predictive_piece(piece_index_t index) const
		{
			return std::binary_search(m_predictive_pieces.begin(), m_predictive_pieces.end(), index);
		}
#endif // TORRENT_DISABLE_PREDICTIVE_PIECES

	private:

		// called when we learn that we have a piece
		// only once per piece
		void we_have(piece_index_t index);

		// process the v2 block hashes for a piece
		boost::tribool on_blocks_hashed(piece_index_t piece
			, span<sha256_hash const> block_hashes);

	public:

		int num_have() const
		{
			// pretend we have every piece when in seed mode
			if (m_seed_mode) return m_torrent_file->num_pieces();
			if (m_have_all) return m_torrent_file->num_pieces();
			return 0;
		}

		// the number of pieces that have passed
		// hash check, but aren't necessarily
		// flushed to disk yet
		int num_passed() const
		{
			if (m_have_all) return m_torrent_file->num_pieces();
			return 0;
		}

		int block_size() const
		{
			return valid_metadata()
				? (std::min)(m_torrent_file->piece_length(), default_block_size)
				: default_block_size;
		}
		void disconnect_all(error_code const& ec, operation_t op);
		int disconnect_peers(int num, error_code const& ec);

		// called every time a block is marked as finished in the
		// piece picker. We might have completed the torrent and
		// we can delete the piece picker
		void maybe_done_flushing();

		// this is called when the torrent has completed
		// the download. It will post an event, disconnect
		// all seeds and let the tracker know we're finished.
		void completed();

		// this is the asio callback that is called when a name
		// lookup for a PEER is completed.
		void on_peer_name_lookup(error_code const&
			, std::vector<address> const&
			, int port
			, protocol_version);

		// re-evaluates whether this torrent should be considered inactive or not
		void on_inactivity_tick(error_code const& ec);


		// calculate the instantaneous inactive state (the externally facing
		// inactive state is not instantaneous, but low-pass filtered)
		bool is_inactive_internal() const;

		// remove a web seed, or schedule it for removal in case there
		// are outstanding operations on it

		// this is called when the torrent has finished. i.e.
		// all the pieces we have not filtered have been downloaded.
		// If no pieces are filtered, this is called first and then
		// completed() is called immediately after it.
		void finished();

		// This is the opposite of finished. It is called if we used
		// to be finished but enabled some files for download so that
		// we wasn't finished anymore.
		void resume_download();

		void verify_piece(piece_index_t piece);
		void on_piece_verified(aux::vector<sha256_hash> block_hashes
			, piece_index_t piece
			, sha1_hash const& piece_hash, storage_error const& error);

		// piece_passed is called when a piece passes the hash check
		// this will tell all peers that we just got his piece
		// and also let the piece picker know that we have this piece
		// so it wont pick it for download
		void piece_passed(piece_index_t index);

		// piece_failed is called when a piece fails the hash check
		// for failures detected with v2 hashes the failing blocks(s)
		// are specified in blocks
		// *blocks must be sorted in acending order*
		void piece_failed(piece_index_t index, std::vector<int> blocks = std::vector<int>());

		// this is the handler for hash failure piece synchronization
		// i.e. resetting the piece
		void on_piece_sync(piece_index_t piece, std::vector<int> const& blocks);

		void add_redundant_bytes(int b, waste_reason reason);
		void add_failed_bytes(int b);

		// this is true if we have all the pieces, but not necessarily flushed them to disk
		bool is_seed() const;

		// this is true if we have all the pieces that we want
		// the pieces don't necessarily need to be flushed to disk
		bool is_finished() const;

		bool is_inactive() const;

		std::string save_path() const;
		aux::alert_manager& alerts() const;

		void update_max_failcount()
		{
		}
		void clear_peers();

		bool has_storage() const { return bool(m_storage); }
		storage_index_t storage() const { return m_storage; }

		torrent_info const& torrent_file() const
		{ return *m_torrent_file; }

		void verify_block_hashes(piece_index_t index);

		std::shared_ptr<const torrent_info> get_torrent_file() const;

		std::shared_ptr<torrent_info> get_torrent_copy_with_hashes() const;

		std::vector<std::vector<sha256_hash>> get_piece_layers() const;

		std::vector<lt::announce_entry> trackers() const;

		// this sets all the "enabled" states on all trackers, giving them
		// all one more chance of being tried
		void enable_all_trackers();

		void replace_trackers(std::vector<lt::announce_entry> const& urls);

		// returns true if the tracker was added, and false if it was already
		// in the tracker list (in which case the source was added to the
		// entry in the list)
		bool add_tracker(lt::announce_entry const& url);

		torrent_handle get_handle();

		void write_resume_data(resume_data_flags_t const flags, add_torrent_params& ret) const;

		void seen_complete() { m_last_seen_complete = ::time(nullptr); }
		int time_since_complete() const { return int(::time(nullptr) - m_last_seen_complete); }
		time_t last_seen_complete() const { return m_last_seen_complete; }

		template <typename Fun, typename... Args>
		void wrap(Fun f, Args&&... a);

		// LOGGING
#ifndef TORRENT_DISABLE_LOGGING
		bool should_log() const override;
		void debug_log(const char* fmt, ...) const noexcept override TORRENT_FORMAT(2,3);

		void log_to_all_peers(char const* message);
		time_point m_dht_start_time;
#endif

		// DEBUG
#if TORRENT_USE_INVARIANT_CHECKS
		void check_invariant() const;
#endif

// --------------------------------------------
		// RESOURCE MANAGEMENT

		// flags are defined in storage.hpp
		void move_storage(std::string const& save_path, move_flags_t flags);

		// renames the file with the given index to the new name
		// the name may include a directory path
		// posts alert to indicate success or failure
		void rename_file(file_index_t index, std::string name);

		// unless this returns true, new connections must wait
		// with their initialization.
		bool ready_for_connections() const
		{ return m_connections_initialized; }
		bool valid_metadata() const
		{ return m_torrent_file->is_valid(); }
		bool are_files_checked() const
		{ return m_files_checked; }

		void initialize_merkle_trees();

		// parses the info section from the given
		// bencoded tree and moves the torrent
		// to the checker thread for initial checking
		// of the storage.
		// a return value of false indicates an error
		bool set_metadata(span<char const> metadata);

		queue_position_t sequence_number() const { return m_sequence_number; }

		bool seed_mode() const { return m_seed_mode; }

		enum class seed_mode_t { check_files, skip_checking };

		void leave_seed_mode(seed_mode_t checking);

		bool all_verified() const
		{ return int(m_num_verified) == m_torrent_file->num_pieces(); }
		bool verifying_piece(piece_index_t const piece) const
		{ return m_verifying.get_bit(piece); }
		void verifying(piece_index_t const piece)
		{
			TORRENT_ASSERT(m_verifying.get_bit(piece) == false);
			m_verifying.set_bit(piece);
		}
		bool verified_piece(piece_index_t piece) const
		{ return m_verified.get_bit(piece); }
		void verified(piece_index_t piece);

		// this is called once periodically for torrents
		// that are not private
		void lsd_announce();

		void update_last_upload() { m_last_upload = aux::time_now32(); }

		void set_apply_ip_filter(bool b);
		bool apply_ip_filter() const { return m_apply_ip_filter; }

#ifndef TORRENT_DISABLE_PREDICTIVE_PIECES
		std::vector<piece_index_t> const& predictive_pieces() const
		{ return m_predictive_pieces; }

		// this is called whenever we predict to have this piece
		// within one second
		void predicted_have_piece(piece_index_t index, time_duration duration);
#endif

		void clear_in_state_update()
		{
			TORRENT_ASSERT(m_links[aux::session_interface::torrent_state_updates].in_list());
			m_links[aux::session_interface::torrent_state_updates].clear();
		}

		void inc_num_connecting(torrent_peer* pp)
		{
		}
		void dec_num_connecting(torrent_peer* pp)
		{
		}

		bool is_ssl_torrent() const { return m_ssl_torrent; }
#ifdef TORRENT_SSL_PEERS
		void set_ssl_cert(std::string const& certificate
			, std::string const& private_key
			, std::string const& dh_params
			, std::string const& passphrase);
		void set_ssl_cert_buffer(std::string const& certificate
			, std::string const& private_key
			, std::string const& dh_params);
		ssl::context* ssl_ctx() const { return m_ssl_ctx.get(); }
#endif

		int num_time_critical_pieces() const
		{
#ifndef TORRENT_DISABLE_STREAMING
			return int(m_time_critical_pieces.size());
#else
			return 0;
#endif
		}

		int get_suggest_pieces(std::vector<piece_index_t>& p
			, typed_bitfield<piece_index_t> const& bits
			, int const n)
		{
			return m_suggest_pieces.get_pieces(p, bits, n);
		}
		void add_suggest_piece(piece_index_t index);

		client_data_t get_userdata() const { return m_userdata; }

		static constexpr int no_gauge_state = 0xf;

	private:

		void on_exception(std::exception const& e);
		void on_error(error_code const& ec);

		// trigger deferred disconnection of peers
		void on_remove_peers() noexcept;

		void ip_filter_updated();

		void inc_stats_counter(int c, int value = 1);

		void construct_storage();
		void update_list(torrent_list_index_t list, bool in);

		void on_files_deleted(storage_error const& error);
		void on_torrent_paused();
		void on_storage_moved(status_t status, std::string const& path
			, storage_error const& error);
		void on_file_renamed(std::string const& filename
			, file_index_t file_idx
			, storage_error const& error);
		void on_cache_flushed(bool manually_triggered);

		// this is used when a torrent is being removed.It synchronizes with the
		// disk thread
		void on_torrent_aborted();

		// upload and download rate limits for the torrent
		void set_limit_impl(int limit, int channel, bool state_update = true);
		int limit_impl(int channel) const;

		int deprioritize_tracker(int tracker_index);

		void update_peer_interest(bool was_finished);
		void prioritize_udp_trackers();

		void update_tracker_timer(time_point32 now);

		void on_tracker_announce(error_code const& ec);

#ifndef TORRENT_DISABLE_DHT
		static void on_dht_announce_response_disp(std::weak_ptr<torrent> t
			, protocol_version v, std::vector<tcp::endpoint> const& peers);
		void on_dht_announce_response(protocol_version v, std::vector<tcp::endpoint> const& peers);
		bool should_announce_dht() const;
#endif

#ifndef TORRENT_DISABLE_STREAMING
		void remove_time_critical_piece(piece_index_t piece, bool finished = false);
		void remove_time_critical_pieces(aux::vector<download_priority_t, piece_index_t> const& priority);
		void request_time_critical_pieces();
#endif // TORRENT_DISABLE_STREAMING

		std::shared_ptr<const ip_filter> m_ip_filter;

		// all time totals of uploaded and downloaded payload
		// stored in resume data
		std::int64_t m_total_uploaded = 0;
		std::int64_t m_total_downloaded = 0;

		// this is a handle that keeps the storage object in the disk io subsystem
		// alive, as well as the index referencing the storage/torrent in the disk
		// I/O. When this destructs, the torrent will be removed from the disk
		// subsystem.
		storage_holder m_storage;

#ifdef TORRENT_SSL_PEERS
		std::unique_ptr<ssl::context> m_ssl_ctx;

		bool verify_peer_cert(bool const preverified, ssl::verify_context& ctx);

		void init_ssl(string_view cert);
#endif

		void setup_peer_class();

		// The list of web seeds in this torrent. Seeds with fatal errors are
		// removed from the set. It's important that iterators are not
		// invalidated as entries are added and removed from this list, hence the
		// std::list

		// used for tracker announces
		deadline_timer m_tracker_timer;

		// used to detect when we are active or inactive for long enough
		// to trigger the auto-manage logic
		deadline_timer m_inactivity_timer;

		// this is the upload and download statistics for the whole torrent.
		// it's updated from all its peers once every second.
		stat m_stat;

		// -----------------------------

		// this vector is allocated lazily. If no file priorities are
		// ever changed, this remains empty. Any unallocated slot
		// implicitly means the file has priority 4.
		// TODO: this wastes 5 bits per file
		aux::vector<download_priority_t, file_index_t> m_file_priority;

		// any file priority updates attempted while another file priority update
		// is in-progress/outstanding with the disk I/O thread, are queued up in
		// this dictionary. Once the outstanding update comes back, all of these
		// are applied in one batch
		std::map<file_index_t, download_priority_t> m_deferred_file_priorities;

		// a queue of the most recent low-availability pieces we accessed on disk.
		// These are good candidates for suggesting other peers to request from
		// us.
		aux::suggest_piece m_suggest_pieces;

		aux::vector<aux::announce_entry> m_trackers;

#ifndef TORRENT_DISABLE_STREAMING
		// this list is sorted by time_critical_piece::deadline
		std::vector<time_critical_piece> m_time_critical_pieces;
#endif

		std::string m_trackerid;
#if TORRENT_ABI_VERSION == 1
		// deprecated in 1.1
		std::string m_username;
		std::string m_password;
#endif

		std::string m_save_path;

#ifndef TORRENT_DISABLE_PREDICTIVE_PIECES
		// this is a list of all pieces that we have announced
		// as having, without actually having yet. If we receive
		// a request for a piece in this list, we need to hold off
		// on responding until we have completed the piece and
		// verified its hash. If the hash fails, send reject to
		// peers with outstanding requests, and dont_have to other
		// peers. This vector is ordered, to make lookups fast.

		// TODO: 3 factor out predictive pieces and all operations on it into a
		// separate class (to use as memeber here instead)
		std::vector<piece_index_t> m_predictive_pieces;
#endif

		// v2 merkle tree for each file
		aux::vector<aux::merkle_tree, file_index_t> m_merkle_trees;

		// the performance counters of this session
		counters& m_stats_counters;

		// each bit represents a piece. a set bit means
		// the piece has had its hash verified. This
		// is only used in seed mode (when m_seed_mode
		// is true)
		typed_bitfield<piece_index_t> m_verified;

		// this means there is an outstanding, async, operation
		// to verify each piece that has a 1
		typed_bitfield<piece_index_t> m_verifying;

		// set if there's an error on this torrent
		error_code m_error;

		// used if there is any resume data. Some of the information from the
		// add_torrent_params struct are needed later in the torrent object's life
		// cycle, and not in the constructor. So we need to save if away here
		std::unique_ptr<add_torrent_params> m_add_torrent_params;

		// if the torrent is started without metadata, it may
		// still be given a name until the metadata is received
		// once the metadata is received this field will no
		// longer be used and will be reset
		std::unique_ptr<std::string> m_name;

		// the posix time this torrent was added and when
		// it was completed. If the torrent isn't yet
		// completed, m_completed_time is 0
		std::time_t m_added_time;
		std::time_t m_completed_time;

		// this was the last time _we_ saw a seed in this swarm
		std::time_t m_last_seen_complete = 0;

		// this is the time last any of our peers saw a seed
		// in this swarm
		std::time_t m_swarm_last_seen_complete = 0;

		// keep a copy if the info-hash here, so it can be accessed from multiple
		// threads, and be cheap to access from the client
		info_hash_t m_info_hash;

	public:
		// these are the lists this torrent belongs to. For more
		// details about each list, see session_impl.hpp. Each list
		// represents a group this torrent belongs to and makes it
		// efficient to enumerate only torrents belonging to a specific
		// group. Such as torrents that want peer connections or want
		// to be ticked etc.

		// TODO: 3 factor out the links (as well as update_list() to a separate
		// class that torrent can inherit)
		aux::array<link, aux::session_interface::num_torrent_lists, torrent_list_index_t>
			m_links;

	private:

		// m_num_verified = m_verified.count()
		std::uint32_t m_num_verified = 0;

		// if this torrent is running, this was the time
		// when it was started. This is used to have a
		// bias towards keeping seeding torrents that
		// recently was started, to avoid oscillation
		// this is specified at a second granularity
		time_point32 m_started = aux::time_now32();

		// if we're a seed, this is the timestamp of when we became one
		time_point32 m_became_seed = aux::time_now32();

		// if we're finished, this is the timestamp of when we finished
		time_point32 m_became_finished = aux::time_now32();

		// when checking, this is the first piece we have not
		// issued a hash job for
		piece_index_t m_checking_piece{0};

		// the number of pieces we completed the check of
		piece_index_t m_num_checked_pieces{0};

		// if the error occurred on a file, this is the index of that file
		// there are a few special cases, when this is negative. See
		// set_error()
		file_index_t m_error_file;

		// the average time it takes to download one time critical piece
		std::int32_t m_average_piece_time = 0;

		// the average piece download time deviation
		std::int32_t m_piece_time_deviation = 0;

		// the number of bytes that has been
		// downloaded that failed the hash-test
		std::int64_t m_total_failed_bytes = 0;
		std::int64_t m_total_redundant_bytes = 0;

		// the sequence number for this torrent, this is a
		// monotonically increasing number for each added torrent
		queue_position_t m_sequence_number;

		// used to post a message to defer disconnecting peers
		aux::deferred_handler m_deferred_disconnect;
		aux::handler_storage<aux::deferred_handler_max_size, aux::defer_handler> m_deferred_handler_storage;

		// these are the peer IDs we've used for our outgoing peer connections for
		// this torrent. If we get an incoming peer claiming to have one of these,
		// it's a connection to ourself, and we should reject it.
		std::set<peer_id> m_outgoing_pids;

		// for torrents who have a bandwidth limit, this is != 0
		// and refers to a peer_class in the session.
		peer_class_t m_peer_class{0};

		// of all peers in m_connections, this is the number
		// of peers that are outgoing and still waiting to
		// complete the connection. This is used to possibly
		// kick out these connections when we get incoming
		// connections (if we've reached the connection limit)
		std::uint16_t m_num_connecting = 0;

		// this is the peer id we generate when we add the torrent. Peers won't
		// use this (they generate their own peer ids) but this is used in case
		// the tracker returns peer IDs, to identify ourself in the peer list to
		// avoid connecting back to it.
		peer_id m_peer_id;

		// ==============================
		// The following members are specifically
		// ordered to make the 24 bit members
		// properly 32 bit aligned by inserting
		// 8 bits after each one
		// ==============================

		// if we're currently in upload-mode this is the time timestamp of when
		// we entered it
		time_point32 m_upload_mode_time = aux::time_now32();

		// true when this torrent should announce to
		// trackers
		bool m_announce_to_trackers:1;

		// true when this torrent should announce to
		// the local network
		bool m_announce_to_lsd:1;

		// is set to true every time there is an incoming
		// connection to this torrent
		bool m_has_incoming:1;

		// this is set to true when the files are checked
		// before the files are checked, we don't try to
		// connect to peers
		bool m_files_checked:1;

		// determines the storage state for this torrent.
		unsigned int m_storage_mode:2;

		// this is true while tracker announcing is enabled
		// is is disabled while paused and checking files
		bool m_announcing:1;

		// this is true when the torrent has been added to the session. Before
		// then, it isn't included in the counters (session_stats)
		bool m_added:1;

		// this is > 0 while the tracker deadline timer
		// is in use. i.e. one or more trackers are waiting
		// for a reannounce
		std::int8_t m_waiting_tracker = 0;

// ----

		// total time we've been active on this torrent. i.e. either (trying to)
		// download or seed. does not count time when the torrent is stopped or
		// paused. specified in seconds. This only track time _before_ we started
		// the torrent this last time. When the torrent is paused, this counter is
		// incremented to include this current session.
		seconds32 m_active_time{0};

		// the index to the last tracker that worked
		std::int8_t m_last_working_tracker = -1;

// ----

		// total time we've been finished with this torrent.
		// does not count when the torrent is stopped or paused.
		seconds32 m_finished_time{0};

		// this variable keeps track of whether the torrent
		// has been set to be downloaded sequentially.
		bool m_sequential_download:1;

		// this is set if the auto_sequential setting is true and this swarm
		// satisfies the criteria to be considered high-availability. i.e. if
		// there's mostly seeds in the swarm, download the files sequentially
		// for improved disk I/O performance.
		bool m_auto_sequential:1;

		// this means we haven't verified the file content
		// of the files we're seeding. the m_verified bitfield
		// indicates which pieces have been verified and which
		// haven't
		bool m_seed_mode:1;

#ifndef TORRENT_DISABLE_SUPERSEEDING
		// if this is true, we're currently super seeding this
		// torrent.
		bool m_super_seeding:1;
#endif

		// if this is set, whenever transitioning into a downloading/seeding state
		// from a non-downloading/seeding state, the torrent is paused.
		bool m_stop_when_ready:1;

		// set to false when saving resume data. Set to true
		// whenever something is downloaded
		bool m_need_save_resume_data:1;

		// when this is true, this torrent participates in the DHT
		bool m_enable_dht:1;

		// when this is true, this torrent participates in local service discovery
		bool m_enable_lsd:1;

// ----

		// total time we've been available as a seed on this torrent.
		// does not count when the torrent is stopped or paused. This value only
		// accounts for the time prior to the current start of the torrent. When
		// the torrent is paused, this counter is incremented to account for the
		// additional seeding time.
		seconds32 m_seeding_time{0};

// ----

		// the maximum number of uploads for this torrent
		std::uint32_t m_max_uploads:24;

		// 8 bits free

// ----

		// the number of unchoked peers in this torrent
		unsigned int m_num_uploads:24;

		// 4 unused bits

		// when this is true, this torrent supports peer exchange
		bool m_enable_pex:1;

		// set to true if the session IP filter applies to this
		// torrent or not. Defaults to true.
		bool m_apply_ip_filter:1;

		// this is true when our effective inactive state is different from our
		// actual inactive state. Whenever this state changes, there is a
		// quarantine period until we change the effective state. This is to avoid
		// flapping. If the state changes back during this period, we cancel the
		// quarantine
		bool m_pending_active_change:1;

		// this is set to true if all piece layers were successfully loaded and
		// validated. Only for v2 torrents
		bool m_v2_piece_layers_validated:1;

// ----

		// the number of (16kiB) blocks that fall entirely in pad files
		// i.e. blocks that we consider we have on start-up
		std::uint16_t m_padding_blocks = 0;

		// this is set to the connect boost quota for this torrent.
		// After having received this many priority peer connection attempts, it
		// falls back onto the steady state peer connection logic, driven by the
		// session tick. Each tracker response, as long as this is non-zero, will
		// attempt to connect to peers immediately and decrement the counter.
		// We give torrents a connect boost when they are first added and then
		// every time they resume from being paused.
		std::uint8_t m_connect_boost_counter;

// ----

		// the scrape data from the tracker response, this
		// is optional and may be 0xffffff
		std::uint32_t m_incomplete:24;

		// true when the torrent should announce to
		// the DHT
		bool m_announce_to_dht:1;

		// even if we're not built to support SSL torrents,
		// remember that this is an SSL torrent, so that we don't
		// accidentally start seeding it without any authentication.
		bool m_ssl_torrent:1;

		// this is set to true if we're trying to delete the
		// files belonging to it. When set, don't write any
		// more blocks to disk!
		bool m_deleted:1;

// ----

		// the timestamp of the last piece passed for this torrent specified in
		// seconds since epoch.
		time_point32 m_last_download{seconds32(0)};

		// the number of peer connections to seeds. This should be the same as
		// counting the peer connections that say true for is_seed()
		std::uint16_t m_num_seeds = 0;

		// this is the number of peers that are seeds, and count against
		// m_num_seeds, but have not yet been connected
		std::uint16_t m_num_connecting_seeds = 0;

		// the timestamp of the last byte uploaded from this torrent specified in
		// seconds since epoch.
		time_point32 m_last_upload{seconds32(0)};

		// user data as passed in by add_torrent_params
		client_data_t m_userdata;

// ----

		// if this is true, libTAU may pause and resume
		// this torrent depending on queuing rules. Torrents
		// started with auto_managed flag set may be added in
		// a paused state in case there are no available
		// slots.
		bool m_auto_managed:1;

		// the current stats gauge this torrent counts against
		std::uint32_t m_current_gauge_state:4;

		// set to true while moving the storage
		bool m_moving_storage:1;

		// this is true if this torrent is considered inactive from the
		// queuing mechanism's point of view. If a torrent doesn't transfer
		// at high enough rates, it's inactive.
		bool m_inactive:1;

// ----

		// the scrape data from the tracker response, this
		// is optional and may be 0xffffff
		std::uint32_t m_downloaded:24;

#if TORRENT_ABI_VERSION == 1
		// the timestamp of the last scrape request to one of the trackers in
		// this torrent specified in session_time. This is signed because it must
		// be able to represent time before the session started
		time_point32 m_last_scrape{seconds32(0)};
#endif

// ----

		// progress parts per million (the number of
		// millionths of completeness)
		std::uint32_t m_progress_ppm:20;

		// set to true once init() completes successfully. This is important to
		// track in case it fails and need to be retried if the client clears
		// the torrent error
		bool m_torrent_initialized:1;

		// this is set to true while waiting for an async_set_file_priority
		bool m_outstanding_file_priority:1;

		// set to true if we've sent an event=completed to any tracker. This will
		// prevent us from sending it again to anyone
		bool m_complete_sent:1;

#if TORRENT_USE_ASSERTS
		// set to true when torrent is start()ed. It may only be started once
		bool m_was_started = false;
		bool m_outstanding_check_files = false;

		// this is set to true while we're looping over m_connections. We may not
		// mutate the list while doing this
		mutable int m_iterating_connections = 0;
#endif
	};
}

#endif // TORRENT_TORRENT_HPP_INCLUDED
