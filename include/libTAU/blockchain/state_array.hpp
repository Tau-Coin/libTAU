/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_STATE_ARRAY_HPP
#define LIBTAU_STATE_ARRAY_HPP

#include <utility>

#include "libTAU/blockchain/account.hpp"

namespace libTAU {
    namespace blockchain {
        class state_array {
        public:
            // @param Construct with entry
            explicit state_array(const entry& e);

            // @param Construct with bencode
            explicit state_array(std::string encode): state_array(bdecode(encode)) {}

            explicit state_array(std::vector<account> mStateArray) : m_state_array(std::move(mStateArray)) {}

            const std::vector<account> &StateArray() const { return m_state_array; }

            entry get_entry() const;

            std::string get_encode() const;

            // @returns a pretty-printed string representation of block structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const state_array &stateArray);

        private:
            // populate state array from entry
            void populate(const entry& e);

            std::vector<account> m_state_array;
        };
    }
}


#endif //LIBTAU_STATE_ARRAY_HPP
