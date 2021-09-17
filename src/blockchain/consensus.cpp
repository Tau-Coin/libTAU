/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/consensus.hpp"
#include "libTAU/kademlia/item.hpp"

namespace libTAU::blockchain {

    std::int64_t consensus::calculate_required_base_target(block previousBlock, block ancestor3) {
        return 0;
    }

    aux::bytes consensus::calculate_generation_signature(sha256_hash preGenerationSignature, const dht::public_key& pubkey) {
        std::string data;
        data.insert(data.end(), preGenerationSignature.begin(), preGenerationSignature.end());
        data.insert(data.end(), pubkey.bytes.begin(), pubkey.bytes.end());

        sha256_hash hash = dht::item_target_id(data);

        return libTAU::aux::bytes(hash.begin(), hash.end());
    }

    std::int64_t consensus::calculate_miner_target_value(std::int64_t baseTarget, std::int64_t power, std::int64_t time) {
        return baseTarget * power * time;
    }

    std::int64_t consensus::calculate_random_hit(sha256_hash generationSignature) {
        return 0;
    }

    std::int64_t consensus::calculate_cumulative_difficulty(std::int64_t lastCumulativeDifficulty,
                                                                       std::int64_t baseTarget) {
        return lastCumulativeDifficulty + DiffAdjustNumerator/baseTarget;
    }

    std::int64_t consensus::calculate_mining_time_interval(std::int64_t hit, std::int64_t baseTarget,
                                                                      std::int64_t power) {
        return 0;
    }

    bool consensus::verify_hit(std::int64_t hit, std::int64_t baseTarget, std::int64_t power,
                                         std::int64_t timeInterval) {
        return false;
    }

}