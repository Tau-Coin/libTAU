/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MUTABLE_DATA_WRAPPER_HPP
#define LIBTAU_MUTABLE_DATA_WRAPPER_HPP

#include <utility>
#include <ostream>
#include "libTAU/aux_/export.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"


namespace libTAU {
    namespace communication {

        enum mutable_data_type {
            ONLINE_SIGNAL,
            NEW_MSG_SIGNAL,
            UNKNOWN
        };

        // The ``mutable_data_wrapper`` class represents
        // wrap all mutable data including message container,
        // online signal, new message signal.
        class TORRENT_EXPORT mutable_data_wrapper {

        public:
            // @param Construct with entry
            explicit mutable_data_wrapper(const entry& e);

            mutable_data_wrapper(std::int64_t mTimestamp, mutable_data_type mType, entry mPayload)
                    : m_timestamp(mTimestamp), m_type(mType), m_payload(std::move(mPayload)) {}

            // @returns timestamp
            std::int64_t timestamp() const { return m_timestamp; }

            // @returns type
            mutable_data_type type() const { return m_type; }

            // @returns payload
            entry payload() const { return m_payload; }

            // @returns the corresponding entry
            entry get_entry() const;

            // @returns a pretty-printed string representation of message structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const mutable_data_wrapper &wrapper);

        private:
            // populate wrapper data from entry
            void populate(const entry& e);

            // mutable data timestamp
            std::int64_t m_timestamp;

            // mutable data type
            mutable_data_type m_type;

            // payload
            entry m_payload;
        };
    }
}


#endif //LIBTAU_MUTABLE_DATA_WRAPPER_HPP
