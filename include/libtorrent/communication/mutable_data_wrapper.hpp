//
// mutable data wrapper
// wrap all mutable data including message container,
// online signal, new message signal.
//

#ifndef LIBTAU_MUTABLE_DATA_WRAPPER_HPP
#define LIBTAU_MUTABLE_DATA_WRAPPER_HPP


#include <libtorrent/aux_/common.h>
#include <libtorrent/aux_/rlp.h>


namespace libtorrent {
    namespace communication {

        enum mutable_data_type {
            MESSAGE_CONTAINER,
            ONLINE_SIGNAL,
            NEW_MSG_SIGNAL,
            UNKNOWN
        };

        class mutable_data_wrapper {
        public:
            mutable_data_wrapper(aux::bytesConstRef _rlp);

            uint32_t timestamp() const {
                return m_timestamp;
            }

            mutable_data_type type() const {
                return m_type;
            }

            aux::bytes payload() const {
                return m_payload;
            }

            // Serialises this mutable data wrapper to an RLPStream
            void streamRLP(aux::RLPStream& _s) const;

            // @returns the RLP serialisation of this mutable data wrapper
            aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

        private:
            // Construct mutable data wrapper object from rlp serialisation
            void populate(aux::RLP const& _mutable_data_wrapper);

            // mutable data timestamp
            uint32_t m_timestamp;
            // mutable data type
            mutable_data_type m_type;
            // payload
            aux::bytes m_payload;
        };
    }
}


#endif //LIBTAU_MUTABLE_DATA_WRAPPER_HPP
