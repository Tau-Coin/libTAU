/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libtorrent/communication/message_container.hpp"

namespace libtorrent { namespace communication {

        message_container::message_container(aux::bytesConstRef _rlp) {
            aux::RLP const rlp(_rlp);
            populate(rlp);
        }

        message_container::message_container(std::vector<message> messages) {
            m_messages = std::move(messages);
        }

        void message_container::streamRLP(aux::RLPStream &_s) const {
            for (auto const& msg: m_messages) {
                aux::RLPStream msg_rlp;
                msg.streamRLP(msg_rlp);
                _s.appendRaw(msg_rlp.out());
            }
        }

        void message_container::populate(const aux::RLP &_msg_container) {
            for (auto const& msg: _msg_container) {
                m_messages.push_back(message{msg.data()});
            }
        }
} }