/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/message_wrapper.hpp"

namespace libTAU::communication {
    message_wrapper::message_wrapper(const entry &e) {
        populate(e);
    }

    entry message_wrapper::get_entry() const {
        entry e(entry::dictionary_t);

        // previous hash
        e["h"] = entry(m_previous_hash.to_string());
        if (!m_message.empty()) {
            // message
            e["m"] = m_message.get_entry();
        }

        return e;
    }

    void message_wrapper::populate(const entry &e) {
        // previous hash
        if (auto* i = const_cast<entry *>(e.find_key("h")))
        {
            auto previous_block_hash = i->string();
            m_previous_hash = sha1_hash(previous_block_hash.data());
        }
        // message
        if (auto* i = const_cast<entry *>(e.find_key("m")))
        {
            m_message = message(*i);
            m_hash = m_message.sha1();
        }
    }

    std::string message_wrapper::get_encode() const {
        std::string encode;
        auto e = get_entry();
        bencode(std::back_inserter(encode), e);

        return encode;
    }

    std::string message_wrapper::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const message_wrapper &wrapper) {
        os << "m_previous_hash: " << aux::toHex(wrapper.m_previous_hash) << " m_message: " << wrapper.m_message.to_string()
           << " m_hash: " << aux::toHex(wrapper.m_hash);
        return os;
    }
}
