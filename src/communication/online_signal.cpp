/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/online_signal.hpp"

namespace libTAU { namespace communication {

        online_signal::online_signal(aux::bytesConstRef _rlp) {
            aux::RLP const rlp(_rlp);
            populate(rlp);
        }

        online_signal::online_signal(const entry &e) {
            populate(e);
        }

        entry online_signal::get_entry() const {
            entry e(entry::dictionary_t);
            // device id
            e["d"] = entry(std::string(m_device_id.begin(), m_device_id.end()));
            // hash prefix bytes
            e["h"] = entry(std::string(m_hash_prefix_bytes.begin(), m_hash_prefix_bytes.end()));
            // timestamp
            e["t"] = entry(m_timestamp);
            // friend info
            e["f"] = entry(std::string(m_friend_info.begin(), m_friend_info.end()));
            // payload
            e["v"] = m_payload.get_entry();

            return e;
        }

        void online_signal::streamRLP(aux::RLPStream &_s) const {
            _s.appendList(5);
            _s << m_device_id << m_hash_prefix_bytes << m_timestamp << m_friend_info <<  m_payload.rlp();
        }

        void online_signal::populate(const entry &e) {
//            if (entry* i = e.find_key("t"))
//            {
//                m_timestamp = i->integer();
//            }
        }

        void online_signal::populate(const aux::RLP &_online_signal) {
            m_device_id = _online_signal[0].toBytes();
            m_hash_prefix_bytes = _online_signal[1].toBytes();
            m_timestamp = _online_signal[2].toInt<uint32_t>();
            m_friend_info = _online_signal[3].toBytes();
            m_payload = immutable_data_info(_online_signal[4].toBytes());
        }

        std::string online_signal::to_string() const {
            std::ostringstream os;
            os << *this;
            return os.str();
        }

        std::ostream &operator<<(std::ostream &os, const online_signal &signal) {
            os << "m_device_id: " << aux::toHex(signal.m_device_id) << " m_hash_prefix_bytes: "
               << aux::toHex(signal.m_hash_prefix_bytes) << " m_timestamp: " << signal.m_timestamp << " m_friend_info: "
               << aux::toHex(signal.m_friend_info) << " m_payload: " << signal.m_payload;
            return os;
        }
}}
