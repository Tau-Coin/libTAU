/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/consensus.hpp"
#include "libTAU/kademlia/item.hpp"

namespace libTAU::blockchain {

    std::int64_t consensus::calculate_required_base_target(block &previousBlock, block &ancestor3) {
        if (previousBlock.block_number() <= 3) {
            return GenesisBaseTarget;
        }

        long totalTimeInterval = 0;
        if (previousBlock.timestamp() > ancestor3.timestamp()) {
            totalTimeInterval = previousBlock.timestamp() -ancestor3.timestamp();
        }

        long timeAver = totalTimeInterval / 3;

        auto previousBlockBaseTarget = previousBlock.base_target();
        std::int64_t requiredBaseTarget;

        if (timeAver > averageBlockTime ) {
            long min;

            if (timeAver < maxRatio) {
                min = timeAver;
            } else {
                min = maxRatio;
            }

            requiredBaseTarget = previousBlockBaseTarget * min / averageBlockTime;
        } else {
            long max;

            if (timeAver > minRatio) {
                max = timeAver;
            } else {
                max = minRatio;
            }

            // 注意计算顺序：在计算机中整数的乘除法的计算顺序，对最终结果是有影响的，比如：
            // 3 / 2 * 2 = 2, 而3 * 2 / 2 = 3, 因此下面1、2、3的计算结果是不一样的
            // 这里采用和公式中的顺序一样，即：
            // If 𝐼𝑛 > AverageBlockTime, 𝑇(𝑏,𝑛) = 𝑇(𝑏,𝑛−1) * (min(𝐼𝑛,𝑅𝑚𝑎𝑥) / AverageBlockTime).
            // If 𝐼𝑛 < AverageBlockTime, 𝑇(𝑏,𝑛) = 𝑇(𝑏,𝑛−1) * (1− 𝛾 * (AverageBlockTime−max(𝐼𝑛,𝑅𝑚𝑖𝑛)) / AverageBlockTime)
            auto delta = previousBlockBaseTarget * 64 / 100 * (averageBlockTime - max) / averageBlockTime;
            requiredBaseTarget = previousBlockBaseTarget - delta;
        }

        return requiredBaseTarget;
    }

    sha256_hash consensus::calculate_generation_signature(const sha256_hash &preGenerationSignature, const dht::public_key& pubkey) {
        std::string data;
        data.insert(data.end(), preGenerationSignature.begin(), preGenerationSignature.end());
        data.insert(data.end(), pubkey.bytes.begin(), pubkey.bytes.end());

        return dht::item_target_id(data);
    }

    std::int64_t consensus::calculate_miner_target_value(std::int64_t baseTarget, std::int64_t power, std::int64_t time) {
        return baseTarget * power * time;
    }

    std::int64_t consensus::calculate_random_hit(const sha256_hash &generationSignature) {
        std::int64_t hit = 0;
        for (int i = 0; i < 8; i++) {
            auto b = generationSignature[7 - i];
            hit = hit << 8;
            hit += b;
        }

        return hit;
    }

    std::int64_t consensus::calculate_cumulative_difficulty(std::int64_t lastCumulativeDifficulty,
                                                                       std::int64_t baseTarget) {
        return static_cast<int64_t>(lastCumulativeDifficulty + DiffAdjustNumerator / baseTarget);
    }

    std::int64_t consensus::calculate_mining_time_interval(std::int64_t hit, std::int64_t baseTarget,
                                                                      std::int64_t power) {
        std::int64_t interval = hit / (baseTarget * power);
        auto remainder = hit % (baseTarget * power);
        if (remainder > 0) {
            interval++;
        }
//        if (timeInterval < this.minBlockTime) {
//            timeInterval = this.minBlockTime;
//        } else if (timeInterval > this.maxBlockTime) {
//            timeInterval = this.maxBlockTime;
//        }

        return interval;
    }

    bool consensus::verify_hit(std::int64_t hit, std::int64_t baseTarget, std::int64_t power,
                                         std::int64_t timeInterval) {
        auto target = calculate_miner_target_value(baseTarget, power, timeInterval);
        if (hit < target) {
            return false;
        }
//        if (timeInterval < this.minBlockTime) {
//            logger.error("Chain ID:{}: Time interval is less than MinBlockTime[{}]",
//                         new String(this.chainID), this.minBlockTime);
//            return false;
//        } else if (timeInterval >= this.maxBlockTime) {
//            logger.debug("Chain ID:{}: OK. Time interval is greater than MaxBlockTime[{}]",
//                         new String(this.chainID), this.maxBlockTime);
//            return true;
//        } else {
//            BigInteger target = this.calculateMinerTargetValue(baseTarget, power, timeInterval);
//            if (target.compareTo(hit) <= 0) {
//                logger.error("Chain ID:{}: Invalid POT: target[{}] <= hit[{}]",
//                             new String(this.chainID), target, hit);
//                return false;
//            }
//        }
        return true;
    }

}