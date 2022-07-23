/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_STATE_ARRAY_HPP
#define LIBTAU_STATE_ARRAY_HPP

#include <utility>

#include "libTAU/aux_/common_data.h"
#include "libTAU/blockchain/account.hpp"
#include "libTAU/hasher.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/sha1_hash.hpp"

namespace libTAU {
    namespace blockchain {
        class state_array {
        public:
            state_array() = default;

            // @param Construct with entry
            explicit state_array(const entry& e);

            // @param Construct with bencode
            explicit state_array(std::string encode): state_array(bdecode(encode)) {}

            explicit state_array(std::vector<account> mStateArray) : m_state_array(std::move(mStateArray)) {
                auto encode = get_encode();
                m_hash = hasher(encode).final();
            }

            void setStateArray(const std::vector<account> &mStateArray) { m_state_array = mStateArray; }

            const std::vector<account> &StateArray() const { return m_state_array; }

            // @returns the SHA1 hash of this block
            const sha1_hash &sha1() const { return m_hash; }

            bool empty() const { return m_state_array.empty(); }

            entry get_entry() const;

            std::string get_encode() const;

            // @returns a pretty-printed string representation of block structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const state_array &stateArray);

        private:
            // populate state array from entry
            void populate(const entry& e);

            std::vector<account> m_state_array;

            // sha1 hash
            sha1_hash m_hash;
        };
    }
}


#endif //LIBTAU_STATE_ARRAY_HPP
