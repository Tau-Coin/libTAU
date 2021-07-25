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
        _s.appendList(4);
        _s << m_device_id << m_hash_prefix_bytes << m_timestamp;
        m_payload.streamRLP(_s);
    }

    void new_msg_signal::populate(const aux::RLP &_new_msg_signal) {
        m_device_id = _new_msg_signal[0].toBytes();
        m_hash_prefix_bytes = _new_msg_signal[1].toBytes();
        m_timestamp = _new_msg_signal[2].toInt<uint32_t>();
        m_payload = immutable_data_info(_new_msg_signal[3].toBytes());
    }

    std::string new_msg_signal::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const new_msg_signal &signal) {
        os << "m_device_id: " << aux::toHex(signal.m_device_id) << " m_hash_prefix_bytes: " << aux::toHex(signal.m_hash_prefix_bytes)
           << " m_timestamp: " << signal.m_timestamp << " m_payload: " << signal.m_payload;
        return os;
    }
}}