//
// Created by vincent on 2021/6/7.
//

#include "libtorrent/communication/mutable_data_wrapper.hpp"

namespace libtorrent { namespace communication {

        mutable_data_wrapper::mutable_data_wrapper(aux::bytesConstRef _rlp) {
            aux::RLP const rlp(_rlp);
            populate(rlp);
        }

        void mutable_data_wrapper::streamRLP(aux::RLPStream &_s) const {
            _s << m_timestamp << static_cast<uint8_t>(m_type) << m_payload;
        }

        void mutable_data_wrapper::populate(const aux::RLP &_mutable_data_wrapper) {
            m_timestamp = _mutable_data_wrapper[0].toInt<uint32_t>();
            m_type = static_cast<mutable_data_type>(_mutable_data_wrapper[1].toInt<uint8_t>());
            m_payload = _mutable_data_wrapper[2].toBytes();
        }
}}