/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/blockchain/chain_url.hpp"

namespace libTAU::blockchain {
    // URL tauchain:?bs=pk1&bs=pk2&dn=chainID
    chain_url::chain_url(std::string url) {
        size_t index = url.find(URL_PREFIX);
        url = url.substr(index + URL_PREFIX.size());

        // bs=pk1&bs=pk2&dn=chainID
        index = url.find_first_of('&');
        while (index != std::string::npos) {
            // bs=pk1
            std::string kv = url.substr(0, index);
            auto i = kv.find('=');
            auto k = kv.substr(0, i);
            auto v = kv.substr(i + 1);
            if (k == KEY_PEER) {
                m_peers.emplace(v.data());
            }

            url = url.substr(index + 1);

            index = url.find_first_of('&');
        }

        std::string kv = url;
        auto i = kv.find('=');
        auto k = kv.substr(0, i);
        auto v = kv.substr(i + 1);
        if (k == KEY_CHAIN_ID) {
            m_chain_id = aux::bytes(v.begin(), v.end());
        }

    }

    std::string chain_url::get_URL() {
        std::string url = URL_PREFIX;

        bool first = true;
        for (auto const& peer: m_peers) {
            if (first) {
                first = false;
            } else {
                url.append("&");
            }
            std::string p(peer.bytes.begin(), peer.bytes.end());
            url.append("bs=").append(p);
        }

        std::string chain_id(m_chain_id.begin(), m_chain_id.end());
        url.append("&dn=").append(chain_id);

        return url;
    }
}
