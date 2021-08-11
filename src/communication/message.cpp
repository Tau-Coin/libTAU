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

//        namespace {
//            sha256_hash bencode_hash(aux::bytes rlp) {
//                std::string s;
//                s.insert(s.end(), rlp.begin(), rlp.end());
//                entry e = s;
//
//                std::string buffer;
//                // bencode要发布的mutable data
//                bencode(std::back_inserter(buffer), e);
//
//                return dht::item_target_id(buffer);
//            }
//
//            sha256_hash bencode_hash(const entry& e) {
//                std::string buffer;
//                // bencode要发布的mutable data
//                bencode(std::back_inserter(buffer), e);
//
//                return dht::item_target_id(buffer);
//            }
//        }

        message::message(entry e) {
            m_entry = std::move(e);

            populate(m_entry);

            // timestamp
//            if (auto* i = const_cast<entry *>(m_entry.find_key("time")))
//            {
//                m_timestamp = i->integer();
//            }


            bencode(std::back_inserter(m_encode), m_entry);
            m_hash = dht::item_target_id(m_encode);
        }

        message::message(uint32_t mTimestamp, aux::bytes mSender, aux::bytes mReceiver, aux::bytes mPayload) :
        m_timestamp(mTimestamp), m_sender(std::move(mSender)),
        m_receiver(std::move(mReceiver)), m_payload(std::move(mPayload)) {
            // timestamp
            m_entry["t"] = entry(m_timestamp);
            // sender
            m_entry["s"] = entry(std::string(m_sender.begin(), m_sender.end()));
            // receiver
            m_entry["r"] = entry(std::string(m_receiver.begin(), m_receiver.end()));
            // payload
            m_entry["p"] = entry(std::string(m_payload.begin(), m_payload.end()));

            bencode(std::back_inserter(m_encode), m_entry);
            m_hash = dht::item_target_id(m_encode);
        }

        entry message::get_entry() const {
            return m_entry;
        }

        void message::populate(const entry &e) {
            // timestamp
            if (auto* i = const_cast<entry *>(e.find_key("t")))
            {
                m_timestamp = i->integer();
            }
            // sender
            if (auto* i = const_cast<entry *>(e.find_key("s")))
            {
                auto sender = i->string();
                m_sender = aux::bytes(sender.begin(), sender.end());
            }
            // receiver
            if (auto* i = const_cast<entry *>(e.find_key("r")))
            {
                auto receiver = i->string();
                m_receiver = aux::bytes(receiver.begin(), receiver.end());
            }
            // payload
            if (auto* i = const_cast<entry *>(e.find_key("p")))
            {
                auto payload = i->string();
                m_payload = aux::bytes(payload.begin(), payload.end());
            }
        }

//        void message::streamRLP(aux::RLPStream &_s) const {
//            _s.appendList(8);
//            _s << static_cast<uint8_t>(m_version) << m_timestamp << m_sender << m_receiver << m_logic_msg_hash
//               << m_nonce << static_cast<uint8_t>(m_type) << m_encrypted_content;
//        }
//
//        void message::populate(const aux::RLP &_msg) {
//            m_version = static_cast<message_version>(_msg[0].toInt<uint8_t>());
//            m_timestamp = _msg[1].toInt<uint32_t>();
//            m_sender = _msg[2].toBytes();
//            m_receiver = _msg[3].toBytes();
//            m_logic_msg_hash = _msg[4].toBytes();
//            m_nonce = _msg[5].toInt<aux::bigint>();
//            m_type = static_cast<message_type>(_msg[6].toInt<uint8_t>());
//            m_encrypted_content = _msg[7].toBytes();
//        }

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
            std::ostringstream os;
            os << *this;
            return os.str();
        }

        std::ostream &operator<<(std::ostream &os, const message &message) {
            os << "message hash: " << aux::toHex(message.m_hash.to_string()) << " message: "
            << message.m_entry.to_string(true);

            return os;
        }
//        std::ostream &operator<<(std::ostream &os, const message &message) {
//            os << "m_version: " << message.m_version << " m_timestamp: " << message.m_timestamp << " m_sender: "
//               << aux::toHex(message.m_sender) << " m_receiver: " << aux::toHex(message.m_receiver) << " m_logic_msg_hash: "
//               << aux::toHex(message.m_logic_msg_hash) << " m_nonce: " << message.m_nonce << " m_type: " << message.m_type
//               << " m_encrypted_content: " << aux::toHex(message.m_encrypted_content) << " m_hash: "
//               << aux::toHex(message.m_hash.to_string());
//            return os;
//        }
    }
}
