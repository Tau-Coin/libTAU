/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_ONLINE_SIGNAL_HPP
#define LIBTAU_ONLINE_SIGNAL_HPP


#include <libTAU/aux_/common.h>
#include <libTAU/aux_/rlp.h>

#include <utility>
#include <ostream>
#include "libTAU/aux_/export.hpp"
#include "libTAU/communication/immutable_data_info.hpp"

namespace libTAU {
    namespace communication {

	    // The ``online_signal`` class represents
        // one type of mutable wrapper,
        // is used to publish online info in XX channel
        struct TORRENT_EXPORT online_signal {

            // @param _rlp rlp encode ref
//            explicit online_signal(aux::bytesConstRef _rlp);

            // @param Construct with entry
            explicit online_signal(const entry& e);

            // @param _rlp rlp encode
//            explicit online_signal(aux::bytes const& _rlp): online_signal(&_rlp) {}

            // construct online signal
            online_signal(aux::bytes mDeviceId, aux::bytes mHashPrefixBytes,
                          aux::bytes mFriendInfo, immutable_data_info mPayload) :
                          m_device_id(std::move(mDeviceId)), m_hash_prefix_bytes(std::move(mHashPrefixBytes)),
                          m_friend_info(std::move(mFriendInfo)), m_payload(std::move(mPayload)) {}

            // @returns device id
            aux::bytes device_id() const { return m_device_id; }

            // @returns hash prefix bytes
            aux::bytes hash_prefix_bytes() const { return m_hash_prefix_bytes; }

            // @returns friend info bytes
            aux::bytes friend_info() const { return m_friend_info; }

            // payload: immutable data info, including hash, end point
            const immutable_data_info &payload() const { return m_payload; }

            // Serialises this online signal to an RLPStream
//            void streamRLP(aux::RLPStream& _s) const;

            // @returns the RLP serialisation of this message
//            aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

            // @returns the corresponding entry
            entry get_entry() const;

            // @returns a pretty-printed string representation of message structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const online_signal &signal);

        private:
            // Construct online signal object from rlp serialisation
//            void populate(aux::RLP const& _online_signal);

            // populate online signal data from entry
            void populate(const entry& e);

            // device id
            aux::bytes m_device_id;

            // bytes consist of first byte of ordered messages hash
            aux::bytes m_hash_prefix_bytes;

            // friend info payload, used to exchange friends on multi-device
            aux::bytes m_friend_info;

            // payload: immutable data info, including hash, end point
            immutable_data_info m_payload;
        };
    }
}

#endif //LIBTAU_ONLINE_SIGNAL_HPP
