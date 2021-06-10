//
// Created by vincent on 2021/6/5.
//

#include "libtorrent/communication/new_msg_signal.hpp"

namespace libtorrent { namespace communication {

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