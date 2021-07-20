/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_IMMUTABLE_INFO_HPP
#define LIBTAU_IMMUTABLE_INFO_HPP

#include <utility>

#include <libTAU/kademlia/node_entry.hpp>
#include <libTAU/entry.hpp>
#include <libTAU/aux_/common.h>
#include <libTAU/aux_/rlp.h>

namespace libTAU::communication {

    class immutable_data_info {
    public:
        immutable_data_info() = default;
        // @param _rlp rlp encode ref
        explicit immutable_data_info(aux::bytesConstRef _rlp);

        // @param _rlp rlp encode
        explicit immutable_data_info(aux::bytes const& _rlp): immutable_data_info(&_rlp) {}

        // construct online signal
        immutable_data_info(sha256_hash target, std::vector<dht::node_entry> entries) :
            m_target(std::move(target)), m_entries(std::move(entries)) {}

        // @returns target(immutable data hash)
        const sha256_hash &target() const { return m_target; }

        // @returns entries
        const std::vector<dht::node_entry> &entries() const { return m_entries; }

        // Serialises this online signal to an RLPStream
        void streamRLP(aux::RLPStream& _s) const;

        // @returns the RLP serialisation of this message
        aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

    private:
        // Construct immutable data info object from rlp serialisation
        void populate(aux::RLP const& encode);

        sha256_hash m_target;

        std::vector<dht::node_entry> m_entries;
    };
}


#endif //LIBTAU_IMMUTABLE_INFO_HPP
