/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/message_hash_list.hpp"

namespace libTAU {
    namespace communication {

        message_hash_list::message_hash_list(aux::bytesConstRef _rlp) {
            if (!_rlp.empty()) {
                aux::RLP const rlp(_rlp);
                populate(rlp);
            }
        }

        message_hash_list::message_hash_list(std::vector<aux::bytes> message_hash_list) {
            m_message_hash_list = std::move(message_hash_list);
        }

        void message_hash_list::streamRLP(aux::RLPStream &_s) const {
            if (!m_message_hash_list.empty()) {
                _s.appendList(m_message_hash_list.size());
                for (auto const &hash: m_message_hash_list) {
                    _s << hash;
                }
            }
        }

        void message_hash_list::populate(const aux::RLP &hash_list) {
            for (auto const& hash: hash_list) {
                m_message_hash_list.push_back(hash.toBytes());
            }
        }
    }
}
