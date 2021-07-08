/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/mutable_data_wrapper.hpp"

#include <utility>

namespace libTAU { namespace communication {

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

        mutable_data_wrapper::mutable_data_wrapper(uint32_t mTimestamp, mutable_data_type mType,
                                                   aux::bytes mPayload) : m_timestamp(mTimestamp), m_type(mType),
                                                                                 m_payload(std::move(mPayload)) {}
    }}