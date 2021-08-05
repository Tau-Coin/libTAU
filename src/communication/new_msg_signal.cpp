/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/new_msg_signal.hpp"

namespace libTAU::communication {

//    new_msg_signal::new_msg_signal(aux::bytesConstRef _rlp) {
//        aux::RLP const rlp(_rlp);
//        populate(rlp);
//    }

    new_msg_signal::new_msg_signal(const entry &e) {
        populate(e);
    }

    entry new_msg_signal::get_entry() const {
        entry e(entry::dictionary_t);
        // device id
        e["d"] = entry(std::string(m_device_id.begin(), m_device_id.end()));
        // hash prefix bytes
        e["h"] = entry(std::string(m_hash_prefix_bytes.begin(), m_hash_prefix_bytes.end()));
        // timestamp
        e["t"] = entry(m_timestamp);
        // payload
        e["v"] = m_payload.get_entry();

        return e;
    }

//    void new_msg_signal::streamRLP(aux::RLPStream &_s) const {
//        _s.appendList(4);
//        _s << m_device_id << m_hash_prefix_bytes << m_timestamp << m_payload.rlp();
//    }
//
//    void new_msg_signal::populate(const aux::RLP &_new_msg_signal) {
//        m_device_id = _new_msg_signal[0].toBytes();
//        m_hash_prefix_bytes = _new_msg_signal[1].toBytes();
//        m_timestamp = _new_msg_signal[2].toInt<uint32_t>();
//        m_payload = immutable_data_info(_new_msg_signal[3].toBytes());
//    }

    void new_msg_signal::populate(const entry &e) {
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
        // timestamp
        if (auto* i = const_cast<entry *>(e.find_key("t")))
        {
            m_timestamp = i->integer();
        }
        // payload
        if (auto* i = const_cast<entry *>(e.find_key("v")))
        {
            m_payload = immutable_data_info(*i);
        }
    }

    std::string new_msg_signal::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const new_msg_signal &signal) {
        os << "m_device_id: " << aux::toHex(signal.m_device_id) << " m_hash_prefix_bytes: " << aux::toHex(signal.m_hash_prefix_bytes)
           << " m_timestamp: " << signal.m_timestamp << " m_payload: " << signal.m_payload;
        return os;
    }
}