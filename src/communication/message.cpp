/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/message.hpp"

#include <utility>

namespace libTAU {
    namespace communication {

        message::message(aux::bytesConstRef _rlp) {
            if (!_rlp.empty()) {
                aux::RLP const rlp(_rlp);
                populate(rlp);

                std::vector<char> buffer;
                buffer.insert(buffer.end(), _rlp.begin(), _rlp.end());

                m_hash = hasher256(buffer).final();
            }
        }

        message::message(message_version mVersion, uint32_t mTimestamp, aux::bytes mSender,
                         aux::bytes mReceiver, aux::bytes mLogicMsgHash, aux::bigint mNonce,
                         message_type mType, aux::bytes mEncryptedContent) : m_version(mVersion),
                         m_timestamp(mTimestamp), m_sender(std::move(mSender)), m_receiver(std::move(mReceiver)),
                         m_logic_msg_hash(std::move(mLogicMsgHash)), m_nonce(std::move(mNonce)), m_type(mType),
                         m_encrypted_content(std::move(mEncryptedContent)) {
            auto data = rlp();
            std::vector<char> buffer;
            buffer.insert(buffer.end(), data.begin(), data.end());

            m_hash = hasher256(buffer).final();
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

//        sha256_hash message::sha256() {
//            if (m_hash.is_all_zeros()) {
//                auto data = rlp();
//                std::vector<char> buffer;
//                buffer.insert(buffer.end(), data.begin(), data.end());
//
//                m_hash = hasher256(buffer).final();
//            }
//
//            return m_hash;
//        }

        std::string message::to_string() const {
            return std::string();
        }
    }
}
