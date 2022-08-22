/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/message.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/entry.hpp"

#include <utility>

namespace libTAU {
    namespace communication {

        message::message(entry e) {
            m_entry = std::move(e);

            populate(m_entry);

            std::string encode;
            bencode(std::back_inserter(encode), m_entry);
            m_hash = hasher(encode).final();
        }

        message::message(std::int64_t mTimestamp, dht::public_key mSender, dht::public_key mReceiver, aux::bytes mPayload) :
        m_timestamp(mTimestamp), m_sender(mSender),
        m_receiver(mReceiver), m_payload(std::move(mPayload)) {
            // timestamp
            auto timestamp = aux::toLittleEndianString(m_timestamp);
            m_entry["t"] = entry(timestamp);
            // sender
            m_entry["s"] = entry(std::string(m_sender.bytes.begin(), m_sender.bytes.end()));
            // receiver
            m_entry["r"] = entry(std::string(m_receiver.bytes.begin(), m_receiver.bytes.end()));
            // payload
            m_entry["p"] = entry(std::string(m_payload.begin(), m_payload.end()));

            std::string encode;
            bencode(std::back_inserter(encode), m_entry);
            m_hash = hasher(encode).final();
        }

        void message::populate(const entry &e) {
            // timestamp
            if (auto* i = const_cast<entry *>(e.find_key("t")))
            {
                auto timestamp = i->string();
                m_timestamp = aux::fromLittleEndianString<std::int64_t>(timestamp);
//                m_timestamp = i->integer();
            }
            // sender
            if (auto* i = const_cast<entry *>(e.find_key("s")))
            {
                auto sender = i->string();
                m_sender = dht::public_key(sender.data());
            }
            // receiver
            if (auto* i = const_cast<entry *>(e.find_key("r")))
            {
                auto receiver = i->string();
                m_receiver = dht::public_key(receiver.data());
            }
            // payload
            if (auto* i = const_cast<entry *>(e.find_key("p")))
            {
                auto payload = i->string();
                m_payload = aux::bytes(payload.begin(), payload.end());
            }
        }

        std::string message::encode() const {
            std::string encode;
            auto e = get_entry();
            bencode(std::back_inserter(encode), e);

            return encode;
        }

        std::string message::to_string() const {
            std::ostringstream os;
            os << *this;
            return os.str();
        }

        std::ostream &operator<<(std::ostream &os, const message &message) {
            os << "message m_hash: " << aux::toHex(message.m_hash.to_string()) << " m_timestamp: "
               << message.m_timestamp << " m_sender: " << aux::toHex(message.m_sender.bytes) << " m_receiver: "
               << aux::toHex(message.m_receiver.bytes) << " m_payload: " << aux::toHex(message.m_payload);
            return os;
        }
    }
}
