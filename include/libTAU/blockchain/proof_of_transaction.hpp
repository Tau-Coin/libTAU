/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_PROOF_OF_TRANSACTION_HPP
#define LIBTAU_PROOF_OF_TRANSACTION_HPP


#include "libTAU/blockchain/block.hpp"

namespace libTAU::blockchain {
    struct proof_of_transaction {

        static std::int64_t calculate_required_base_target(block previousBlock, block ancestor3);

        static aux::bytes calculate_generation_signature(aux::bytes preGenerationSignature, aux::bytes pubkey);

        /**
         * get miner target value
         * target = base target * mining power * time
         */
        static std::int64_t calculate_miner_target_value(std::int64_t baseTarget, std::int64_t power, std::int64_t time);

        static std::int64_t calculate_random_hit(aux::bytes generationSignature);

        /**
         * calculate cumulative difficulty: last cumulative difficulty + DiffAdjustNumerator / base target
         */
        static std::int64_t calculate_cumulative_difficulty(std::int64_t lastCumulativeDifficulty, std::int64_t baseTarget);

        static std::int64_t calculate_mining_time_interval(std::int64_t hit, std::int64_t baseTarget, std::int64_t power);

        static bool verifyHit(std::int64_t hit, std::int64_t baseTarget, std::int64_t power, std::int64_t timeInterval);

    };
}

#endif //LIBTAU_PROOF_OF_TRANSACTION_HPP
