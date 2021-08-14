/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/message_hash_list.hpp"

#include <utility>

namespace libTAU {
    namespace communication {

        message_hash_list::message_hash_list(std::string encode) {
            entry e = bdecode(encode);
            populate(e);
        }

        message_hash_list::message_hash_list(std::vector<aux::bytes> message_hash_list) {
            m_message_hash_list = std::move(message_hash_list);
        }

        std::string message_hash_list::encode() {
            entry::list_type l;
            if (!m_message_hash_list.empty()) {
                for (auto const &hash: m_message_hash_list) {
                    l.push_back(entry(std::string(hash.begin(), hash.end())));
                }
            }
            entry e(l);
            std::string encode;
            bencode(std::back_inserter(encode), e);

            return encode;
        }

        void message_hash_list::populate(const entry &e) {
            entry::list_type l = e.list();
            for (auto const& h: l) {
                auto hash = h.string();
                m_message_hash_list.emplace_back(hash.begin(), hash.end());
            }
        }

        std::string message_hash_list::to_string() const {
            std::ostringstream os;
            os << *this;
            return os.str();
        }

        std::ostream &operator<<(std::ostream &os, const message_hash_list &list) {
            os << "m_message_hash_list: ";
            for (auto const& hash: list.m_message_hash_list) {
                os << " hash " + aux::toHex(hash);
            }
            return os;
        }
    }
}
