/*

Copyright (c) 2019-2020, Arvid Norberg
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <cstdint>
#include "libTAU/read_resume_data.hpp"
#include "libTAU/write_resume_data.hpp"
#include "libTAU/add_torrent_params.hpp"

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
	lt::error_code ec;
	auto ret = lt::read_resume_data({reinterpret_cast<char const*>(data), int(size)}, ec);
	auto buf = write_resume_data_buf(ret);
	return 0;
}

