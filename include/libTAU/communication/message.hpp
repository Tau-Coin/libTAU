/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MESSAGE_HPP
#define LIBTAU_MESSAGE_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <utility>
#include "libTAU/sha1_hash.hpp"
#include "libTAU/hasher.hpp"
#include <libTAU/aux_/common.h>
#include <libTAU/aux_/rlp.h>

namespace libTAU {
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

        // The ``message`` class shows message struct
        class TORRENT_EXPORT message {

        public:
            message() = default;

            // @param _rlp rlp encode
            explicit message(aux::bytesConstRef _rlp);

            // @param _rlp rlp encode
            explicit message(aux::bytes const& _rlp): message(&_rlp) {}

            message(message_version mVersion, uint32_t mTimestamp, aux::bytes mSender,
                    aux::bytes mReceiver, aux::bytes mLogicMsgHash, aux::bigint mNonce,
                    message_type mType, aux::bytes mEncryptedContent);

            // @returns message version
            message_version version() const { return m_version; }

            // @returns message timestamp
            uint32_t timestamp() const { return m_timestamp; }

            // @returns message sender
            const aux::bytes &sender() const { return m_sender; }

            // @returns message receiver
            const aux::bytes &receiver() const { return m_receiver; }

            // @returns message logic msg hash
            const aux::bytes &logic_msg_hash() const { return m_logic_msg_hash; }

            // @returns message nonce
            const aux::bigint &nonce() const { return m_nonce; }

            // @returns message type
            message_type type() const { return m_type; }

            // @returns encrypted content
            const aux::bytes &encrypted_content() const { return m_encrypted_content; }

            // Serialises this message to an RLPStream
            void streamRLP(aux::RLPStream& _s) const;

            // @returns the RLP serialisation of this message
            aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

            // @returns the SHA256 hash of the RLP serialisation of this message
            sha256_hash sha256() const { return m_hash; }

            // @returns a pretty-printed string representation of message structure
            std::string to_string() const;

            bool operator==(const message &rhs) const {
                return m_hash == rhs.m_hash;
            }

            bool operator!=(const message &rhs) const {
                return !(rhs == *this);
            }

            bool operator<(const message &rhs) const {
                return m_hash < rhs.m_hash;
            }

            bool operator>(const message &rhs) const {
                return rhs < *this;
            }

            bool operator<=(const message &rhs) const {
                return !(rhs < *this);
            }

            bool operator>=(const message &rhs) const {
                return !(*this < rhs);
            }


        private:
            // Construct message object from rlp serialisation
            void populate(aux::RLP const& _msg);

            // message version
            message_version m_version;

            // message timestamp
            uint32_t m_timestamp{};

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

            // sha256 hash
            sha256_hash m_hash;
        };
    }
}

#endif //LIBTAU_MESSAGE_HPP
