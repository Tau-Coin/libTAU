/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include <cmath>

#include "libTAU/blockchain/consensus.hpp"
#include "libTAU/hasher.hpp"
#include "libTAU/kademlia/item.hpp"

namespace libTAU::blockchain {

    std::uint64_t consensus::calculate_required_base_target(const block &previousBlock, block &ancestor3) {
        if (previousBlock.block_number() % CHAIN_EPOCH_BLOCK_SIZE <= 3) {
            return previousBlock.base_target();
        }

        long totalTimeInterval = 0;
        if (previousBlock.timestamp() > ancestor3.timestamp()) {
            totalTimeInterval = previousBlock.timestamp() -ancestor3.timestamp();
        }

        long timeAver = totalTimeInterval / 3;

        std::uint64_t previousBlockBaseTarget = previousBlock.base_target();
        std::uint64_t requiredBaseTarget;

        if (timeAver > DEFAULT_BLOCK_TIME) {
            long min;

            if (timeAver < MAX_RATIO) {
                min = timeAver;
            } else {
                min = MAX_RATIO;
            }

            // notes: previousBlockBaseTarget * min may be overflow
//            requiredBaseTarget = previousBlockBaseTarget * min / DEFAULT_BLOCK_TIME;
            requiredBaseTarget = previousBlockBaseTarget / DEFAULT_BLOCK_TIME * min;
        } else {
            long max;

            if (timeAver > MIN_RATIO) {
                max = timeAver;
            } else {
                max = MIN_RATIO;
            }

            // 注意计算顺序：在计算机中整数的乘除法的计算顺序，对最终结果是有影响的，比如：
            // 3 / 2 * 2 = 2, 而3 * 2 / 2 = 3, 因此下面1、2、3的计算结果是不一样的
            // 这里采用和公式中的顺序一样，即：
            // If 𝐼𝑛 > AverageBlockTime, 𝑇(𝑏,𝑛) = 𝑇(𝑏,𝑛−1) * (min(𝐼𝑛,𝑅𝑚𝑎𝑥) / AverageBlockTime).
            // If 𝐼𝑛 < AverageBlockTime, 𝑇(𝑏,𝑛) = 𝑇(𝑏,𝑛−1) * (1− 𝛾 * (AverageBlockTime−max(𝐼𝑛,𝑅𝑚𝑖𝑛)) / AverageBlockTime)
//            auto delta = previousBlockBaseTarget * 64 / 100 * (DEFAULT_BLOCK_TIME - max) / DEFAULT_BLOCK_TIME;
            auto delta = previousBlockBaseTarget / 100 * 64 / DEFAULT_BLOCK_TIME * (DEFAULT_BLOCK_TIME - max);
            requiredBaseTarget = previousBlockBaseTarget - delta;
        }

        if (requiredBaseTarget > MAX_BASE_TARGET) {
            requiredBaseTarget = MAX_BASE_TARGET;
        }

        return requiredBaseTarget;
    }

    sha1_hash consensus::calculate_generation_signature(const sha1_hash &preGenerationSignature, const dht::public_key& pubkey) {
        std::string data;
        data.insert(data.end(), preGenerationSignature.begin(), preGenerationSignature.end());
        data.insert(data.end(), pubkey.bytes.begin(), pubkey.bytes.end());

        return hasher(data).final();
    }

    // note: result --> data overflow
//    std::uint64_t consensus::calculate_miner_target_value(uint64_t baseTarget, uint64_t power, uint64_t time) {
//        return baseTarget * power * time;
//    }

    std::uint64_t consensus::calculate_random_hit(const sha1_hash &generationSignature) {
        std::uint64_t hit = 0;
        for (int i = 0; i < 8; i++) {
            std::uint8_t b = generationSignature[7 - i];
            hit = hit << 8;
            hit += b;
        }

        return hit;
    }

    std::uint64_t consensus::calculate_cumulative_difficulty(uint64_t lastCumulativeDifficulty, uint64_t baseTarget) {
        return static_cast<uint64_t>(lastCumulativeDifficulty + DiffAdjustNumerator / baseTarget);
    }

    // Note: DEFAULT_MIN_BLOCK_TIME/DEFAULT_MAX_BLOCK_TIME is different from nxt
    std::uint64_t consensus::calculate_mining_time_interval(uint64_t hit, uint64_t baseTarget, uint64_t power) {
//        if (power == 0) {
//            return MAX_VALID_BLOCK_TIME;
//        }

        uint64_t real_power = ceil(std::log2(power + 2));
        if (real_power == 0) {
            return MAX_VALID_BLOCK_TIME;
        }

        auto interval = hit / baseTarget / real_power;

        // make sure target > hit
        interval++;

        if (interval > MAX_VALID_BLOCK_TIME) {
            interval = MAX_VALID_BLOCK_TIME;
        }

        if (interval < MIN_VALID_BLOCK_TIME) {
            interval = MIN_VALID_BLOCK_TIME;
        }

//        if (interval < DEFAULT_MIN_BLOCK_TIME) {
//            interval = DEFAULT_MIN_BLOCK_TIME;
//        } else if (interval > DEFAULT_MAX_BLOCK_TIME) {
//            interval = DEFAULT_MAX_BLOCK_TIME;
//        }

        return interval;
    }

//    bool consensus::verify_hit(uint64_t hit, uint64_t baseTarget, uint64_t power, uint64_t timeInterval) {
////        if (timeInterval < DEFAULT_MIN_BLOCK_TIME) {
////            return false;
////        } else if (timeInterval >= DEFAULT_MAX_BLOCK_TIME) {
////            return true;
////        } else {
//            auto target = calculate_miner_target_value(baseTarget, power, timeInterval);
//            if (target <= hit) {
//                return false;
//            }
////        }
//
//        return true;
//    }

}
