/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/online_signal.hpp"

namespace libTAU { namespace communication {

        const std::int64_t online_signal::protocol_id = 0;

        online_signal::online_signal(const entry &e) {
            populate(e);
        }

        entry online_signal::get_entry() const {
            entry e(entry::dictionary_t);
            // protocol id
            e["pid"] = entry(protocol_id);
            // timestamp
            e["t"] = entry(m_timestamp);
            // device id
            e["d"] = entry(std::string(m_device_id.begin(), m_device_id.end()));
            // hash prefix bytes
            e["h"] = entry(std::string(m_hash_prefix_bytes.begin(), m_hash_prefix_bytes.end()));
            // payload
            if (!m_payload.empty()) {
                e["v"] = m_payload.get_entry();
            }
            // friend info
            if (!m_friend_info.empty()) {
                e["f"] = entry(std::string(m_friend_info.begin(), m_friend_info.end()));
            }

            return e;
        }

        void online_signal::populate(const entry &e) {
            // timestamp
            if (auto* i = const_cast<entry *>(e.find_key("t")))
            {
                m_timestamp = i->integer();
            }
            // device id
            if (auto* i = const_cast<entry *>(e.find_key("d")))
            {
                std::string device_id = i->string();
                m_device_id = aux::bytes(device_id.begin(), device_id.end());
            }
            // hash prefix bytes
            if (auto* i = const_cast<entry *>(e.find_key("h")))
            {
                std::string hash_prefix_array = i->string();
                m_hash_prefix_bytes = aux::bytes(hash_prefix_array.begin(), hash_prefix_array.end());
            }
            // payload
            if (auto* i = const_cast<entry *>(e.find_key("v")))
            {
                m_payload = immutable_data_info(*i);
            }
            // friend info
            if (auto* i = const_cast<entry *>(e.find_key("f")))
            {
                std::string friend_info = i->string();
                m_friend_info = aux::bytes(friend_info.begin(), friend_info.end());
            }
        }

        std::string online_signal::to_string() const {
            std::ostringstream os;
            os << *this;
            return os.str();
        }

        std::ostream &operator<<(std::ostream &os, const online_signal &signal) {
            os << "m_timestamp: " << signal.m_timestamp << " m_device_id: " << aux::toHex(signal.m_device_id)
               << " m_hash_prefix_bytes: " << aux::toHex(signal.m_hash_prefix_bytes)
               << " m_payload: " << signal.m_payload << " m_friend_info: " << aux::toHex(signal.m_friend_info);
            return os;
        }
}}
