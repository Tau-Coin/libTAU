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
#include <ostream>
#include "libTAU/entry.hpp"

namespace libTAU {
    namespace communication {

        // The ``message`` class shows message struct
        class TORRENT_EXPORT message {

        public:
            message() = default;

            // @param Construct with entry
            explicit message(entry e);

            // @returns message timestamp
            uint32_t timestamp() const { return m_timestamp; }

            // @returns the corresponding entry
            entry get_entry() const;

            // @return message bencode size
            size_t bencode_size() const;

            // @returns the SHA256 hash of the RLP serialisation of this message
            sha256_hash sha256() const { return m_hash; }

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
            // message timestamp
            uint32_t m_timestamp{};

            // message sender
            aux::bytes m_sender;

            // message receiver
            aux::bytes m_receiver;

            // message entry
            entry m_entry;

            // sha256 hash
            sha256_hash m_hash;
        };

        struct message_hasher
        {
            size_t operator()(const message &m) const noexcept
            {
                return std::hash<sha256_hash>{}(m.sha256());
            }
        };
    }
}

#endif //LIBTAU_MESSAGE_HPP
