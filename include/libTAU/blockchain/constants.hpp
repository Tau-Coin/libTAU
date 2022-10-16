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
#include "libTAU/kademlia/types.hpp"

namespace libTAU::blockchain {

    const aux::bytes TAU_CHAIN_ID = aux::asBytes("TAUCOINabc");
    const std::int64_t TAU_CHAIN_GENESIS_TIMESTAMP = 1638761707; // seconds
    const std::vector<dht::public_key> TAU_CHAIN_GENESIS_ACCOUNT = {
            dht::public_key(aux::fromHex("63ec42130442c91e23d56dc73708e06eb164883ab74c9813764c3fd0e2042dc4").data()),
            dht::public_key(aux::fromHex("809df518ee450ded0a659aeb4bc5bec636e2cff012fc88d343b7419af974bb81").data()),
            dht::public_key(aux::fromHex("2a62868271f3d3455e4b1ea0c1f96263732d0347349f9daa3247107ce1b2b2f9").data()),
            dht::public_key(aux::fromHex("3e87c35d2079858d88dcb113edadaf1b339fcd4f74c539faa9a9bd59e787f124").data())};

    const std::set<dht::public_key> TAU_CHAIN_FOLLOWED_PEERS = {
            dht::public_key(aux::fromHex("63ec42130442c91e23d56dc73708e06eb164883ab74c9813764c3fd0e2042dc4").data()),
            dht::public_key(aux::fromHex("809df518ee450ded0a659aeb4bc5bec636e2cff012fc88d343b7419af974bb81").data()),
            dht::public_key(aux::fromHex("2a62868271f3d3455e4b1ea0c1f96263732d0347349f9daa3247107ce1b2b2f9").data()),
            dht::public_key(aux::fromHex("3e87c35d2079858d88dcb113edadaf1b339fcd4f74c539faa9a9bd59e787f124").data())};

    // chain id
    // todo:validate
    constexpr int CHAIN_ID_MAX_LENGTH = 32;
    constexpr int CHAIN_ID_HASH_MAX_LENGTH = 4;
    constexpr int CHAIN_ID_TYPE_MAX_LENGTH = 4;
    constexpr int CHAIN_ID_COMMUNITY_NAME_MAX_LENGTH = 24;

    constexpr int CHAIN_EPOCH_BLOCK_SIZE = 50;

    constexpr int MAX_ACCOUNT_SIZE = 774;

    constexpr int MAX_STATE_ARRAY_SIZE = MAX_ACCOUNT_SIZE / 43;

    constexpr int short_chain_id_length = 4;

    // block time
    constexpr int DEFAULT_BLOCK_TIME = 300;

    constexpr int MIN_VALID_BLOCK_TIME = 60; // 1min
    constexpr int MAX_VALID_BLOCK_TIME = 10 * 60; // 10min

    constexpr int MIN_RATIO = 265;
    constexpr int MAX_RATIO = 335;

    // genesis block balance
    constexpr int64_t GENESIS_BLOCK_BALANCE = 1000000;
    // miner bonus
    constexpr int64_t MINER_BONUS = 10;

    constexpr uint64_t MAX_BASE_TARGET = UINT64_MAX / 2;

    // 0x21D0369D036978
    constexpr uint64_t GENESIS_BASE_TARGET = 39517607212509560;

    // 2^64 = 0x010000000000000000
    const aux::bigint DiffAdjustNumerator = aux::bigint(1) << 64;
    // 2^32 = 0x0100000000
    const aux::bigint DiffAdjustNumeratorHalf = aux::bigint(1) << 32;
    // 2^59 = 0x800000000000000
    const aux::bigint DiffAdjustNumeratorCoe = aux::bigint(1) << 59;

}

#endif //LIBTAU_CONSTANTS_HPP
