//
// message struct
//

#ifndef LIBTAU_MESSAGE_HPP
#define LIBTAU_MESSAGE_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include "libtorrent/sha1_hash.hpp"
#include "libtorrent/hasher.hpp"
#include <libtorrent/aux_/common.h>
#include <libtorrent/aux_/rlp.h>

namespace libtorrent {
    namespace communication {

        enum message_version {
            // current version
            VERSION_1,
            // unsupported version
            UNSUPPORTED_VERSION
        };

        enum message_type {
            // message type is text
            TEXT,
            // message type is picture
            PICTURE,
            // unsupported message type
            UNSUPPORTED_TYPE
        };

        class message {
        public:
            message(aux::bytesConstRef _rlp);

            message_version version() const {
                return m_version;
            }

            uint32_t timestamp() const {
                return m_timestamp;
            }

            const aux::bytes &sender() const {
                return m_sender;
            }

            const aux::bytes &receiver() const {
                return m_receiver;
            }

            const aux::bytes &logic_msg_hash() const {
                return m_logic_msg_hash;
            }

            const aux::bigint &nonce() const {
                return m_nonce;
            }

            message_type type() const {
                return m_type;
            }

            const aux::bytes &encrypted_content() const {
                return m_encrypted_content;
            }

            // Serialises this message to an RLPStream
            void streamRLP(aux::RLPStream& _s) const;

            // @returns the RLP serialisation of this message
            aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

            // @returns the SHA256 hash of the RLP serialisation of this message
            sha256_hash sha256() const;

        private:
            // Construct message object from rlp serialisation
            void populate(aux::RLP const& _msg);

            // message version
            message_version m_version;
            // message timestamp
            uint32_t m_timestamp;
            // message sender
            aux::bytes m_sender;
            // message receiver
            aux::bytes m_receiver;
            // logic message hash
            aux::bytes m_logic_msg_hash;
            // nonce is used to indicate the position of the message in a large segmented message
            aux::bigint m_nonce;
            // message type
            message_type m_type;
            // encrypted content
            aux::bytes m_encrypted_content;
        };
    }
}

#endif //LIBTAU_MESSAGE_HPP
