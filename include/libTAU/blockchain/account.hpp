/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_ACCOUNT_HPP
#define LIBTAU_ACCOUNT_HPP

#include <ostream>
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/export.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/kademlia/types.hpp"

namespace libTAU {
    namespace blockchain {
        class TORRENT_EXPORT account {
        public:
			account() = default;

            explicit account(const entry& e);

            // @param Construct with bencode
            explicit account(std::string encode): account(bdecode(encode)) {}

            explicit account(const dht::public_key &mPeer) : m_peer(mPeer) {}

//            explicit account(int64_t mBalance) : m_balance(mBalance) {}

//            account(int64_t mBalance, int64_t mNonce) : m_balance(mBalance), m_nonce(mNonce) {}

            account(const dht::public_key &mPeer, int64_t mBalance, int64_t mNonce, int64_t mPower) : m_peer(mPeer),
                                                                                                      m_balance(mBalance),
                                                                                                      m_nonce(mNonce),
                                                                                                      m_power(mPower) {}

//            account(int64_t mBalance, int64_t mNonce, int64_t mEffectivePower, int64_t mBlockNumber) :
//                m_balance(mBalance), m_nonce(mNonce), m_effective_power(mEffectivePower), m_block_number(mBlockNumber) {}

//            bool empty() const { return m_balance == 0 && m_nonce == 0; }

            const dht::public_key &peer() const { return m_peer; }

            void set_balance(int64_t mBalance) { m_balance = mBalance; }

            int64_t balance() const { return m_balance; }

            // add
            void add_balance(int64_t mBalance) { m_balance += mBalance; }

            // subtract
            void subtract_balance(int64_t mBalance) { m_balance -= mBalance; }

            int64_t nonce() const { return m_nonce; }

            void increase_nonce() { m_nonce++; }

            void decrease_nonce() { m_nonce--; }

            void set_nonce(int64_t mNonce) { m_nonce = mNonce; }

            void set_power(int64_t mPower) { m_power = mPower; }

            int64_t power() const { return m_power; }

            void increase_power() { m_power++; }

            void decrease_power() { m_power--; }

//            int64_t block_number() const { return m_block_number; }

            bool operator<(const account &rhs) const {
                return m_peer < rhs.m_peer;
            }

            bool operator>(const account &rhs) const {
                return rhs < *this;
            }

            bool operator<=(const account &rhs) const {
                return !(rhs < *this);
            }

            bool operator>=(const account &rhs) const {
                return !(*this < rhs);
            }

            // @returns the corresponding entry
            entry get_entry() const;

            // @returns a pretty-printed string representation of block structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const account &account);

        private:

            // populate message data from entry
            void populate(const entry& e);

            dht::public_key m_peer;

            // balance
            std::int64_t m_balance{};

            // nonce
            std::int64_t m_nonce{};

            // power
            std::int64_t m_power{};

//            // block number
//            std::int64_t m_block_number{};
        };
    }
}


#endif //LIBTAU_ACCOUNT_HPP
