/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MUTABLE_DATA_WRAPPER_HPP
#define LIBTAU_MUTABLE_DATA_WRAPPER_HPP


#include <libTAU/aux_/common.h>
#include <libTAU/aux_/rlp.h>

#include <utility>
#include <ostream>
#include "libTAU/aux_/export.hpp"
#include "libTAU/entry.hpp"


namespace libTAU {
    namespace communication {

        enum mutable_data_type {
            MESSAGE,
            MESSAGE_CONTAINER,
            ONLINE_SIGNAL,
            NEW_MSG_SIGNAL,
            UNKNOWN
        };

        // The ``mutable_data_wrapper`` class represents
        // wrap all mutable data including message container,
        // online signal, new message signal.
        class TORRENT_EXPORT mutable_data_wrapper {

        public:

            // @param _rlp rlp encode
            explicit mutable_data_wrapper(aux::bytesConstRef _rlp);

            // @param Construct with entry
            explicit mutable_data_wrapper(const entry& e);

            // @param _rlp rlp encode
            explicit mutable_data_wrapper(aux::bytes const& _rlp): mutable_data_wrapper(&_rlp) {}

            mutable_data_wrapper(uint32_t mTimestamp, mutable_data_type mType, aux::bytes mPayload)
                    : m_timestamp(mTimestamp), m_type(mType), m_payload(std::move(mPayload)) {}

            // @returns timestamp
            uint32_t timestamp() const { return m_timestamp; }

            // @returns type
            mutable_data_type type() const { return m_type; }

            // @returns payload
            aux::bytes payload() const { return m_payload; }

            // Serialises this mutable data wrapper to an RLPStream
            void streamRLP(aux::RLPStream& _s) const;

            // @returns the RLP serialisation of this mutable data wrapper
            aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

            // @returns the corresponding entry
            entry get_entry() const;

            // @returns a pretty-printed string representation of message structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const mutable_data_wrapper &wrapper);

        private:
            // Construct mutable data wrapper object from rlp serialisation
            void populate(aux::RLP const& _mutable_data_wrapper);

            // mutable data timestamp
            uint32_t m_timestamp;

            // mutable data type
            mutable_data_type m_type;

            // payload
            aux::bytes m_payload;
            entry m_payload1;
        };
    }
}


#endif //LIBTAU_MUTABLE_DATA_WRAPPER_HPP
