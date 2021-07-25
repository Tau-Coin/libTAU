/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/immutable_data_info.hpp"

namespace libTAU::communication {
    immutable_data_info::immutable_data_info(aux::bytesConstRef _rlp) {
        if (!_rlp.empty()) {
            aux::RLP const rlp(_rlp);
            populate(rlp);
        }
    }

    void immutable_data_info::streamRLP(aux::RLPStream &_s) const {
        if (!m_target.is_all_zeros() && !m_entries.empty()) {
            auto size = m_entries.size();
            _s.appendList(size + 1);

            _s << m_target.to_string();

            for (const auto& e: m_entries) {
                _s.appendList(4);
                // 1. public key
                _s << e.id.to_string() ;

                // 2. ipv4/ipv6 flag
                bool flag = e.addr().is_v4();
                _s << static_cast<uint8_t>(flag);

                // 3. ip
                if (flag) {
                    _s << e.addr().to_v4().to_bytes();
                } else {
                    _s << e.addr().to_v6().to_bytes();
                }

                // 4. port(2 bytes)
                _s << e.port();
            }
        } else {
            _s << aux::bytes();
        }
    }

    void immutable_data_info::populate(const aux::RLP &encode) {
        auto size = encode.size();
        if (size > 1) {
            auto target = encode[0].toString();
            m_target = sha256_hash(target.c_str());

            for (auto i = 1; i < size; i++) {
                // 1. public key
                auto id = encode[i][0].toString();
                sha256_hash pubkey(id.c_str());

                // 2. ipv4/ipv6 flag
                bool flag = static_cast<bool>(encode[i][1].toInt<uint8_t>());

                // 3. ip
                auto ip = encode[i][2].toString();
                address addr;
                if (flag) {
                    addr = make_address_v4(ip);
                } else {
                    addr = make_address_v6(ip);
                }

                // 4. port
                auto port = encode[i][3].toInt<uint16_t>();

                m_entries.push_back(dht::node_entry(pubkey, {addr, port}));
            }
        }
    }

    std::string immutable_data_info::to_string() const {
        std::ostringstream os;
        os << *this;
        return os.str();
    }

    std::ostream &operator<<(std::ostream &os, const immutable_data_info &info) {
        os << "m_target: " << aux::toHex(info.m_target) << " m_entries: ";
        for (auto const& e: info.m_entries) {
            os << " public key: " << aux::toHex(e.id) << " address: " << e.addr().to_string() << " port: " << e.port();
        }
        return os;
    }
}