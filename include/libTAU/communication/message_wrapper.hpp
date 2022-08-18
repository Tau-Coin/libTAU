/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MESSAGE_WRAPPER_HPP
#define LIBTAU_MESSAGE_WRAPPER_HPP


#include <utility>

#include "libTAU/communication/message.hpp"


namespace libTAU {
    namespace communication {
        class message_wrapper {
        public:
            message_wrapper() = default;

            // @param Construct with entry
            explicit message_wrapper(const entry& e);

            // @param Construct with bencode
            explicit message_wrapper(std::string encode): message_wrapper(bdecode(encode)) {}

            explicit message_wrapper(message mMessage) : m_message(std::move(mMessage)), m_hash(m_message.sha1()) {}

            message_wrapper(const sha1_hash &mPreviousHash, message mMessage) : m_previous_hash(mPreviousHash),
                            m_message(std::move(mMessage)), m_hash(m_message.sha1()) {}

            const sha1_hash &previousHash() const { return m_previous_hash; }

            const message &msg() const { return m_message; }

            const sha1_hash &sha1() const { return m_hash; }

            bool empty() const { return m_hash.is_all_zeros(); }

            entry get_entry() const;

            std::string get_encode() const;

            bool operator<(const message_wrapper &rhs) const {
                return m_hash < rhs.m_hash;
            }

            bool operator>(const message_wrapper &rhs) const {
                return rhs < *this;
            }

            bool operator<=(const message_wrapper &rhs) const {
                return !(rhs < *this);
            }

            bool operator>=(const message_wrapper &rhs) const {
                return !(*this < rhs);
            }

            // @returns a pretty-printed string representation of tx structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const message_wrapper &wrapper);

        private:
            // populate data from entry
            void populate(const entry& e);

            sha1_hash m_previous_hash;

            message m_message;

            sha1_hash m_hash;
        };
    }
}


#endif //LIBTAU_MESSAGE_WRAPPER_HPP
