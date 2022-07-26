/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_TRANSACTION_WRAPPER_HPP
#define LIBTAU_TRANSACTION_WRAPPER_HPP

#include <utility>
#include <ostream>

#include "libTAU/blockchain/transaction.hpp"

namespace libTAU {
    namespace blockchain {
        class transaction_wrapper {
        public:
            transaction_wrapper() = default;

            // @param Construct with entry
            explicit transaction_wrapper(const entry& e);

            // @param Construct with bencode
            explicit transaction_wrapper(std::string encode): transaction_wrapper(bdecode(encode)) {}

            explicit transaction_wrapper(transaction mTx) : m_tx(std::move(mTx)), m_hash(m_tx.sha1()) {}

            transaction_wrapper(const sha1_hash &mPreviousHash, transaction mTx) :
                    m_previous_hash(mPreviousHash), m_tx(std::move(mTx)), m_hash(m_tx.sha1()) {}

            const sha1_hash &previousHash() const { return m_previous_hash; }

            const transaction &tx() const { return m_tx; }

            const sha1_hash &sha1() const { return m_hash; }

            bool empty() const { return m_hash.is_all_zeros(); }

            entry get_entry() const;

            std::string get_encode() const;

            bool operator<(const transaction_wrapper &rhs) const {
                return m_hash < rhs.m_hash;
            }

            bool operator>(const transaction_wrapper &rhs) const {
                return rhs < *this;
            }

            bool operator<=(const transaction_wrapper &rhs) const {
                return !(rhs < *this);
            }

            bool operator>=(const transaction_wrapper &rhs) const {
                return !(*this < rhs);
            }

            // @returns a pretty-printed string representation of tx structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const transaction_wrapper &wrapper);

        private:
            // populate data from entry
            void populate(const entry& e);

            sha1_hash m_previous_hash;

            transaction m_tx;

            sha1_hash m_hash;
        };
    }
}


#endif //LIBTAU_TRANSACTION_WRAPPER_HPP
