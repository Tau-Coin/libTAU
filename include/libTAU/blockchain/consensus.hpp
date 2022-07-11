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

        static std::uint64_t calculate_required_base_target(const block &previousBlock, block &ancestor3);

        static sha1_hash calculate_generation_signature(const sha1_hash &preGenerationSignature, const dht::public_key& pubkey);

        /**
         * get miner target value
         * target = base target * mining power * time
         */
//        static std::uint64_t calculate_miner_target_value(uint64_t baseTarget, uint64_t power, uint64_t time);

        static std::uint64_t calculate_random_hit(const sha1_hash &generationSignature);

        /**
         * calculate cumulative difficulty: last cumulative difficulty + DiffAdjustNumerator / base target
         */
        static std::uint64_t calculate_cumulative_difficulty(uint64_t lastCumulativeDifficulty, uint64_t baseTarget);

        static std::uint64_t calculate_mining_time_interval(uint64_t hit, uint64_t baseTarget, uint64_t power);

//        static bool verify_hit(uint64_t hit, uint64_t baseTarget, uint64_t power, uint64_t timeInterval);

    };
}

#endif //LIBTAU_CONSENSUS_HPP
