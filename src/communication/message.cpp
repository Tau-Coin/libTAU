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
            entry::list_type lst;
            // timestamp
            auto timestamp = aux::int64ToLittleEndianString(m_timestamp);
            lst.push_back(timestamp);
            // sender
            lst.push_back(std::string(m_sender.bytes.begin(), m_sender.bytes.end()));
            // receiver
            lst.push_back(std::string(m_receiver.bytes.begin(), m_receiver.bytes.end()));
            // payload
            lst.push_back(std::string(m_payload.begin(), m_payload.end()));
            m_entry = lst;

            std::string encode;
            bencode(std::back_inserter(encode), m_entry);
            m_hash = hasher(encode).final();
        }

        void message::populate(const entry &e) {
            auto const& lst = e.list();

            if (lst.size() != 4)
                return;

            // balance
            m_timestamp = aux::int64FromLittleEndianString(lst[0].string());
            // sender
            m_sender = dht::public_key(lst[1].string().data());
            // receiver
            m_receiver = dht::public_key(lst[2].string().data());
            // payload
            auto payload = lst[3].string();
            m_payload = aux::bytes(payload.begin(), payload.end());
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
