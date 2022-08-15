/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MESSAGE_HPP
#define LIBTAU_MESSAGE_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <ostream>
#include <utility>
#include "libTAU/sha1_hash.hpp"
#include "libTAU/hasher.hpp"
#include <libTAU/aux_/common.h>
#include "libTAU/aux_/common_data.h"
#include <libTAU/kademlia/types.hpp>
#include "libTAU/entry.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"

namespace libTAU {
    namespace communication {

        // The ``message`` class shows message struct
        class TORRENT_EXPORT message {

        public:
            message() = default;

            // @param Construct with entry
            explicit message(entry e);

            // @param Construct with bencode
            explicit message(std::string encode): message(bdecode(encode)) {}

            message(std::int64_t mTimestamp, dht::public_key mSender, dht::public_key mReceiver, aux::bytes mPayload);

            message(int64_t mTimestamp, const dht::public_key &mSender, const dht::public_key &mReceiver,
                    aux::bytes mPayload, const sha1_hash &mHash) : m_timestamp(mTimestamp), m_sender(mSender),
                    m_receiver(mReceiver), m_payload(std::move(mPayload)), m_hash(mHash) {}

            // @returns message timestamp
            std::int64_t timestamp() const { return m_timestamp; }

            // @returns sender
            const dht::public_key &sender() const { return m_sender; }

            // @returns receiver
            const dht::public_key &receiver() const { return m_receiver; }

            // @returns payload
            const aux::bytes &payload() const { return m_payload; }

            // @returns the corresponding entry
            const entry &get_entry() const { return m_entry; }

            // @returns the message bencode
            std::string encode() const;

            // @returns the SHA1 hash of this message
            const sha1_hash &sha1() const { return m_hash; }

            // @returns a pretty-printed string representation of message structure
            std::string to_string() const;

            // check if this message is null
            bool empty() const { return m_hash.is_all_zeros(); }

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

            friend std::ostream &operator<<(std::ostream &os, const message &message);

        private:
            // populate message data from entry
            void populate(const entry& e);

            // message timestamp
            std::int64_t m_timestamp{};

            // message sender
            dht::public_key m_sender;

            // message receiver
            dht::public_key m_receiver;

            // payload
            aux::bytes m_payload;

            // message entry
            entry m_entry;

            // encode
//            std::string m_encode;

            // sha1 hash
            sha1_hash m_hash;
        };

//        struct message_hasher
//        {
//            size_t operator()(const message &m) const noexcept
//            {
//                return std::hash<sha256_hash>{}(m.sha256());
//            }
//        };
    }
}

#endif //LIBTAU_MESSAGE_HPP
