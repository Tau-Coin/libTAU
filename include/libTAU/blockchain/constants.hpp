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

    // 2^64 = 0x010000000000000000
    constexpr int64_t GenesisBaseTarget = 1111111111;

    constexpr int averageBlockTime = 300;

    constexpr int minRatio = 265;

    constexpr int maxRatio = 335;

    // 2^64 = 0x010000000000000000
    const aux::bigint DiffAdjustNumerator = aux::bigint(1) << 64;
    // 2^32 = 0x0100000000
    const aux::bigint DiffAdjustNumeratorHalf = aux::bigint(1) << 32;
    // 2^59 = 0x800000000000000
    const aux::bigint DiffAdjustNumeratorCoe = aux::bigint(1) << 59;

}

#endif //LIBTAU_CONSTANTS_HPP
