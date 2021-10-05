/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_CONSENSUS_HPP
#define LIBTAU_CONSENSUS_HPP

#include "libTAU/sha1_hash.hpp"
#include "libTAU/blockchain/constants.hpp"
#include "libTAU/blockchain/block.hpp"

namespace libTAU::blockchain {
    struct consensus {

        static std::int64_t calculate_required_base_target(block &previousBlock, block &ancestor3);

        static sha256_hash calculate_generation_signature(const sha256_hash &preGenerationSignature, const dht::public_key& pubkey);

        /**
         * get miner target value
         * target = base target * mining power * time
         */
        static std::int64_t calculate_miner_target_value(std::int64_t baseTarget, std::int64_t power, std::int64_t time);

        static std::int64_t calculate_random_hit(const sha256_hash &generationSignature);

        /**
         * calculate cumulative difficulty: last cumulative difficulty + DiffAdjustNumerator / base target
         */
        static std::int64_t calculate_cumulative_difficulty(std::int64_t lastCumulativeDifficulty, std::int64_t baseTarget);

        static std::int64_t calculate_mining_time_interval(std::int64_t hit, std::int64_t baseTarget, std::int64_t power);

        static bool verify_hit(std::int64_t hit, std::int64_t baseTarget, std::int64_t power, std::int64_t timeInterval);

    };
}

#endif //LIBTAU_CONSENSUS_HPP
