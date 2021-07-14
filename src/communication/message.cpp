/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/message.hpp"

namespace libTAU {
    namespace communication {

        message::message(aux::bytesConstRef _rlp) {
            aux::RLP const rlp(_rlp);
            populate(rlp);
        }

        void message::streamRLP(aux::RLPStream &_s) const {
            _s.appendList(8);
            _s << static_cast<uint8_t>(m_version) << m_timestamp << m_sender << m_receiver << m_logic_msg_hash
               << m_nonce << static_cast<uint8_t>(m_type) << m_encrypted_content;
        }

        void message::populate(const aux::RLP &_msg) {
            m_version = static_cast<message_version>(_msg[0].toInt<uint8_t>());
            m_timestamp = _msg[1].toInt<uint32_t>();
            m_sender = _msg[2].toBytes();
            m_receiver = _msg[3].toBytes();
            m_logic_msg_hash = _msg[4].toBytes();
            m_nonce = _msg[5].toInt<aux::bigint>();
            m_type = static_cast<message_type>(_msg[6].toInt<uint8_t>());
            m_encrypted_content = _msg[7].toBytes();
        }

        sha256_hash message::sha256() const {
            auto data = rlp().data();
            char* p = reinterpret_cast<char*>(data);
            std::vector<char> buffer;
            buffer.insert(buffer.end(), p, p + strlen(p));
            return hasher256(buffer).final();
        }

        std::string message::to_string() const {
            return std::string();
        }
    }
}
