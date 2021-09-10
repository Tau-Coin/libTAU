/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/proof_of_transaction.hpp"

namespace libTAU::blockchain {

    std::int64_t proof_of_transaction::calculate_required_base_target(block previousBlock, block ancestor3) {
        return 0;
    }

    aux::bytes
    proof_of_transaction::calculate_generation_signature(aux::bytes preGenerationSignature, aux::bytes pubkey) {
        return libTAU::aux::bytes();
    }

    std::int64_t
    proof_of_transaction::calculate_miner_target_value(std::int64_t baseTarget, std::int64_t power, std::int64_t time) {
        return baseTarget * power * time;
    }

    std::int64_t proof_of_transaction::calculate_random_hit(aux::bytes generationSignature) {
        return 0;
    }

    std::int64_t proof_of_transaction::calculate_cumulative_difficulty(std::int64_t lastCumulativeDifficulty,
                                                                       std::int64_t baseTarget) {
        return 0;
    }

    std::int64_t proof_of_transaction::calculate_mining_time_interval(std::int64_t hit, std::int64_t baseTarget,
                                                                      std::int64_t power) {
        return 0;
    }

    bool proof_of_transaction::verifyHit(std::int64_t hit, std::int64_t baseTarget, std::int64_t power,
                                         std::int64_t timeInterval) {
        return false;
    }

}