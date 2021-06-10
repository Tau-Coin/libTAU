//
// Created by vincent on 2021/6/7.
//

#include "libtorrent/communication/online_signal.hpp"

namespace libtorrent { namespace communication {

        online_signal::online_signal(aux::bytesConstRef _rlp) {
            aux::RLP const rlp(_rlp);
            populate(rlp);
        }

        void online_signal::streamRLP(aux::RLPStream &_s) const {
            _s << m_device_id << m_hash_prefix_bytes << m_timestamp << m_friend_info;
        }

        void online_signal::populate(const aux::RLP &_online_signal) {
            m_device_id = _online_signal[0].toBytes();
            m_hash_prefix_bytes = _online_signal[1].toBytes();
            m_timestamp = _online_signal[2].toInt<uint32_t>();
            m_friend_info = _online_signal[3].toBytes();
        }
}}
