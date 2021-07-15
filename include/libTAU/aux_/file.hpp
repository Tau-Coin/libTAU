/*

Copyright (c) 2004, 2008-2010, 2014-2018, 2020, Arvid Norberg
Copyright (c) 2016, Steven Siloti
Copyright (c) 2021, Alden Torres
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef TORRENT_FILE_HPP_INCLUDED
#define TORRENT_FILE_HPP_INCLUDED

#include <memory>
#include <string>
#include <functional>

#include "libTAU/config.hpp"
#include "libTAU/string_view.hpp"
#include "libTAU/span.hpp"
#include "libTAU/aux_/storage_utils.hpp"
#include "libTAU/aux_/open_mode.hpp"
#include "libTAU/flags.hpp"

#include "libTAU/aux_/disable_warnings_push.hpp"

#ifdef TORRENT_WINDOWS
// windows part
#include "libTAU/aux_/windows.hpp"
#include <winioctl.h>
#include <sys/types.h>
#else
// posix part

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h> // for DIR

#endif

#include "libTAU/aux_/disable_warnings_pop.hpp"

#include "libTAU/error_code.hpp"
#include "libTAU/assert.hpp"
#include "libTAU/time.hpp"

namespace libTAU::aux {

#ifdef TORRENT_WINDOWS
	using handle_type = HANDLE;
#else
	using handle_type = int;
#endif

	struct TORRENT_EXTRA_EXPORT file
	{
		file();
		file(std::string const& p, aux::open_mode_t m, error_code& ec);
		file(file&&) noexcept;
		file& operator=(file&&);
		~file();

		file(file const&) = delete;
		file& operator=(file const&) = delete;

		std::int64_t writev(std::int64_t file_offset, span<iovec_t const> bufs
			, error_code& ec, aux::open_mode_t flags = {});
		std::int64_t readv(std::int64_t file_offset, span<iovec_t const> bufs
			, error_code& ec, aux::open_mode_t flags = {});

	private:
		handle_type m_file_handle;
	};
}

#endif // TORRENT_FILE_HPP_INCLUDED