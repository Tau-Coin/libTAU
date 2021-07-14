/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/online_signal.hpp"

namespace libTAU { namespace communication {

        online_signal::online_signal(aux::bytesConstRef _rlp) {
            aux::RLP const rlp(_rlp);
            populate(rlp);
        }

        void online_signal::streamRLP(aux::RLPStream &_s) const {
            _s.appendList(4);
            _s << m_device_id << m_hash_prefix_bytes << m_timestamp << m_friend_info;
        }

        void online_signal::populate(const aux::RLP &_online_signal) {
            m_device_id = _online_signal[0].toBytes();
            m_hash_prefix_bytes = _online_signal[1].toBytes();
            m_timestamp = _online_signal[2].toInt<uint32_t>();
            m_friend_info = _online_signal[3].toBytes();
        }
}}
