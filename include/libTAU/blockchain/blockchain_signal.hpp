/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_BLOCKCHAIN_SIGNAL_HPP
#define LIBTAU_BLOCKCHAIN_SIGNAL_HPP


#include <map>

#include "libTAU/communication/immutable_data_info.hpp"


namespace libTAU::blockchain {
    using immutable_data_info = communication::immutable_data_info;

    class blockchain_signal {
    public:

    private:
        sha256_hash m_consensus_point_block_hash;

        std::int64_t m_consensus_point_block_number;

        immutable_data_info m_best_block;

        immutable_data_info m_immutable_block;

        immutable_data_info m_tx;

        sha256_hash m_demand_block_hash;

        sha256_hash m_demand_tx_hash;

        std::map<aux::bytes, aux::bytes> m_tx_hash_prefix_array;
    };
}


#endif //LIBTAU_BLOCKCHAIN_SIGNAL_HPP
