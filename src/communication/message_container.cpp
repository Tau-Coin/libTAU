/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/message_container.hpp"

namespace libTAU { namespace communication {

        message_container::message_container(aux::bytesConstRef _rlp) {
            aux::RLP const rlp(_rlp);
            populate(rlp);
        }

        message_container::message_container(std::vector<message> messages) {
            m_messages = std::move(messages);
        }

        void message_container::streamRLP(aux::RLPStream &_s) const {
            if (!m_messages.empty()) {
                _s.appendList(m_messages.size());

                for (auto const &msg: m_messages) {
                    aux::RLPStream msg_rlp;
                    msg.streamRLP(msg_rlp);
                    _s.appendRaw(msg_rlp.out());
                }
            }
        }

        void message_container::populate(const aux::RLP &_msg_container) {
            for (auto const& msg: _msg_container) {
                m_messages.emplace_back(msg.data());
            }
        }

        std::string message_container::to_string() const {
            std::ostringstream os;
            os << *this;
            return os.str();
        }

        std::ostream &operator<<(std::ostream &os, const message_container &container) {
            os << "m_messages: ";
            for (auto const& msg: container.m_messages) {
                os << " hash " + aux::toHex(msg.sha256().to_string());
            }
            return os;
        }
} }