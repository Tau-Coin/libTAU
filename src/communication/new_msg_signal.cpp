/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/new_msg_signal.hpp"

namespace libTAU { namespace communication {

    new_msg_signal::new_msg_signal(aux::bytesConstRef _rlp) {
        aux::RLP const rlp(_rlp);
        populate(rlp);
    }

    void new_msg_signal::streamRLP(aux::RLPStream &_s) const {
        _s << m_device_id << m_hash_prefix_bytes << m_timestamp;
    }

    void new_msg_signal::populate(const aux::RLP &_new_msg_signal) {
        m_device_id = _new_msg_signal[0].toBytes();
        m_hash_prefix_bytes = _new_msg_signal[1].toBytes();
        m_timestamp = _new_msg_signal[2].toInt<uint32_t>();
    }
}}