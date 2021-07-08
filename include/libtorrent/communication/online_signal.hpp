/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_ONLINE_SIGNAL_HPP
#define LIBTAU_ONLINE_SIGNAL_HPP


#include <libtorrent/aux_/common.h>
#include <libtorrent/aux_/rlp.h>

#include <utility>
#include "libtorrent/aux_/export.hpp"

namespace libtorrent {
    namespace communication {

	    // The ``online_signal`` class represents
        // one type of mutable wrapper,
        // is used to publish online info in XX channel
        struct TORRENT_EXPORT online_signal {

            // @param _rlp rlp encode ref
            explicit online_signal(aux::bytesConstRef _rlp);

            // @param _rlp rlp encode
            explicit online_signal(aux::bytes const& _rlp): online_signal(&_rlp) {}

            // construct online signal
            online_signal(aux::bytes mDeviceId, aux::bytes mHashPrefixBytes, uint32_t mTimestamp,
                          aux::bytes mFriendInfo) : m_device_id(std::move(mDeviceId)),
                          m_hash_prefix_bytes(std::move(mHashPrefixBytes)),
                          m_timestamp(mTimestamp), m_friend_info(std::move(mFriendInfo)) {}

            // @returns device id
            aux::bytes device_id() const { return m_device_id; }

            // @returns hash prefix bytes
            aux::bytes hash_prefix_bytes() const { return m_hash_prefix_bytes; }

            // @returns timestamp
            uint32_t timestamp() const { return m_timestamp; }

            // @returns friend info bytes
            aux::bytes friend_info() const { return m_friend_info; }

            // Serialises this online signal to an RLPStream
            void streamRLP(aux::RLPStream& _s) const;

            // @returns the RLP serialisation of this message
            aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

        private:
            // Construct online signal object from rlp serialisation
            void populate(aux::RLP const& _online_signal);

            // device id
            aux::bytes m_device_id;

            // bytes consist of first byte of ordered messages hash
            aux::bytes m_hash_prefix_bytes;

            // online signal timestamp
            uint32_t m_timestamp;

            // friend info payload, used to exchange friends on multi-device
            aux::bytes m_friend_info;
        };
    }
}

#endif //LIBTAU_ONLINE_SIGNAL_HPP
