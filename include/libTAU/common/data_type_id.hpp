/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_DATA_TYPE_ID_HPP
#define LIBTAU_DATA_TYPE_ID_HPP

#include "libTAU/common/message_entry.hpp"
#include "libTAU/common/block_entry.hpp"
#include "libTAU/common/transaction_entry.hpp"

namespace libTAU::common {

    const std::int64_t message_entry::data_type_id = 0;
    const std::int64_t block_entry::data_type_id = 1;
    const std::int64_t transaction_entry::data_type_id = 2;

}

#endif //LIBTAU_DATA_TYPE_ID_HPP
