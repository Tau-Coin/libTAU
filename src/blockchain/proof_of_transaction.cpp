/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/proof_of_transaction.hpp"
#include "libTAU/kademlia/item.hpp"

namespace libTAU::blockchain {

    std::int64_t proof_of_transaction::calculate_required_base_target(block previousBlock, block ancestor3) {
        return 0;
    }

    aux::bytes proof_of_transaction::calculate_generation_signature(aux::bytes preGenerationSignature, aux::bytes pubkey) {
        std::string data;
        data.insert(data.end(), preGenerationSignature.begin(), preGenerationSignature.end());
        data.insert(data.end(), pubkey.begin(), pubkey.end());

        sha256_hash hash = dht::item_target_id(data);

        return libTAU::aux::bytes(hash.begin(), hash.end());
    }

    std::int64_t proof_of_transaction::calculate_miner_target_value(std::int64_t baseTarget, std::int64_t power, std::int64_t time) {
        return baseTarget * power * time;
    }

    std::int64_t proof_of_transaction::calculate_random_hit(aux::bytes generationSignature) {
        return 0;
    }

    std::int64_t proof_of_transaction::calculate_cumulative_difficulty(std::int64_t lastCumulativeDifficulty,
                                                                       std::int64_t baseTarget) {
        return lastCumulativeDifficulty + DiffAdjustNumerator/baseTarget;
    }

    std::int64_t proof_of_transaction::calculate_mining_time_interval(std::int64_t hit, std::int64_t baseTarget,
                                                                      std::int64_t power) {
        return 0;
    }

    bool proof_of_transaction::verify_hit(std::int64_t hit, std::int64_t baseTarget, std::int64_t power,
                                         std::int64_t timeInterval) {
        return false;
    }

}