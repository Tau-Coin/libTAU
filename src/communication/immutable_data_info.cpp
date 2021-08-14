/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/immutable_data_info.hpp"

namespace libTAU::communication {
    immutable_data_info::immutable_data_info(const entry& e) {
        populate(e);
    }

    entry immutable_data_info::get_entry() const {
        entry e(entry::dictionary_t);
        if (!m_target.is_all_zeros() && !m_entries.empty()) {
            // target
            e["t"] = m_target.to_string();

            // node entries
            entry::list_type l;
            for (const auto& n: m_entries) {
                entry ne(entry::dictionary_t);

                // id
                ne["i"] = entry(n.id.to_string());

                // address
                if (n.addr().is_v4()) {
                    // ipv4
                    address_v4::bytes_type b = n.addr().to_v4().to_bytes();
                    ne["4"] = entry(std::string(b.begin(), b.end()));
                } else {
                    // ipv6
                    address_v6::bytes_type b = n.addr().to_v6().to_bytes();
                    ne["6"] = entry(std::string(b.begin(), b.end()));
                }

                // port
                ne["p"] = entry(n.port());

                l.push_back(ne);
            }
            e["n"] = l;
        }

        return e;
    }

    void immutable_data_info::populate(const entry &e) {
        // target
        if (auto* i = const_cast<entry *>(e.find_key("t")))
        {
            std::string target = i->string();
            m_target = sha256_hash(target.c_str());
        }
        // node entries
        if (auto* i = const_cast<entry *>(e.find_key("n")))
        {
            entry::list_type node_entries = i->list();
            for (const auto& n: node_entries) {
                // id
                if (auto* ptr = const_cast<entry *>(n.find_key("i")))
                {
                    std::string id = ptr->string();
                    sha256_hash pubkey(id.c_str());

                    // ip
                    if (auto* ipv4_ptr = const_cast<entry *>(n.find_key("4"))) {
                        // make ipv4
                        std::string ipv4 = ipv4_ptr->string();
                        address_v4::bytes_type b;
                        memcpy(&b[0], ipv4.c_str(), b.size());
                        address addr = make_address_v4(b);

                        // port
                        if (auto* p = const_cast<entry *>(n.find_key("p")))
                        {
                            u_int16_t port = p->integer();

                            m_entries.push_back(dht::node_entry(pubkey, {addr, port}));
                        }
                    } else if (auto* ipv6_ptr = const_cast<entry *>(n.find_key("6"))) {
                        // make ipv6
                        std::string ipv6 = ipv6_ptr->string();
                        address_v6::bytes_type b;
                        memcpy(&b[0], ipv6.c_str(), b.size());
                        address addr = make_address_v6(b);

                        // port
                        if (auto* p = const_cast<entry *>(n.find_key("p")))
                        {
                            u_int16_t port = p->integer();

                            m_entries.push_back(dht::node_entry(pubkey, {addr, port}));
                        }
                    }
                }
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