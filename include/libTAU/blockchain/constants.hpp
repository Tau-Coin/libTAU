/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_CONSTANTS_HPP
#define LIBTAU_CONSTANTS_HPP


#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"

namespace libTAU::blockchain {

    // block time
    constexpr int DEFAULT_BLOCK_TIME = 300;
    constexpr int DEFAULT_MIN_BLOCK_TIME = 60;
    constexpr int DEFAULT_MAX_BLOCK_TIME = 540;

    // 0x010000000000000000
    constexpr std::int64_t DiffAdjustNumerator = 0x01;
    constexpr std::int64_t DiffAdjustNumeratorHalf = 0x0100000000;
    constexpr std::int64_t DiffAdjustNumeratorCoe = 0x800000000000000; //2^59

}

#endif //LIBTAU_CONSTANTS_HPP
