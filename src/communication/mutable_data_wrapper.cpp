/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#include "libTAU/communication/mutable_data_wrapper.hpp"

#include <utility>

namespace libTAU { namespace communication {

        mutable_data_wrapper::mutable_data_wrapper(const entry &e) {
            populate(e);
        }

        entry mutable_data_wrapper::get_entry() const {
            entry e(entry::dictionary_t);
            // timestamp
            e["t"] = entry(m_timestamp);
            // signal
            switch (m_type) {
                case ONLINE_SIGNAL: {
                    e["o"] = m_payload;
                    break;
                }
                case NEW_MSG_SIGNAL: {
                    e["n"] = m_payload;
                    break;
                }
                default:
                    break;
            }

            return e;
        }

        void mutable_data_wrapper::populate(const entry &e) {
            // timestamp
            if (auto* i = const_cast<entry *>(e.find_key("t")))
            {
                m_timestamp = i->integer();
            }
            // check if online signal
            if (auto* i = const_cast<entry *>(e.find_key("o")))
            {
                m_type = ONLINE_SIGNAL;
                m_payload = *i;
            }
            // check if new message signal
            if (auto* i = const_cast<entry *>(e.find_key("n")))
            {
                m_type = NEW_MSG_SIGNAL;
                m_payload = *i;
            }
        }

        std::string mutable_data_wrapper::to_string() const {
            std::ostringstream os;
            os << *this;
            return os.str();
        }

        std::ostream &operator<<(std::ostream &os, const mutable_data_wrapper &wrapper) {
            os << "m_timestamp: " << wrapper.m_timestamp << " m_type: " << wrapper.m_type << " m_payload: "
               << wrapper.m_payload.to_string(true);
            return os;
        }
}}