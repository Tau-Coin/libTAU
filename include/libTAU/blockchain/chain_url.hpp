/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_CHAIN_URL_HPP
#define LIBTAU_CHAIN_URL_HPP


#include <utility>

#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"
#include "libTAU/kademlia/types.hpp"

// URL TAUchain:?bs=pk1&bs=pk2&dn=chainID
namespace libTAU {
    namespace blockchain {
        class chain_url {

            const std::string URL_PREFIX = "TAUchain:?";
            const std::string KEY_PEER = "bs";
            const std::string KEY_CHAIN_ID = "dn";

        public:
            chain_url(std::string url);

            chain_url(aux::bytes mChainId, std::set<dht::public_key> mPeers) : m_chain_id(std::move(mChainId)),
                                                                                             m_peers(std::move(mPeers)) {}

            const aux::bytes &chain_id() const { return m_chain_id; }

            const std::set<dht::public_key> &peers() const { return m_peers; }

            std::string get_URL();

        private:

            aux::bytes m_chain_id;

            std::set<dht::public_key> m_peers;
        };
    }
}


#endif //LIBTAU_CHAIN_URL_HPP
