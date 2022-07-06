/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_HASH_ARRAY_HPP
#define LIBTAU_HASH_ARRAY_HPP

#include <utility>

#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"
#include "libTAU/entry.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/sha1_hash.hpp"

namespace libTAU {
    namespace blockchain {
        class hash_array {
        public:
            // @param Construct with entry
            explicit hash_array(const entry& e);

            // @param Construct with bencode
            explicit hash_array(std::string encode): hash_array(bdecode(encode)) {}

            explicit hash_array(std::vector<sha256_hash> mHashArray) : m_hash_array(std::move(mHashArray)) {}

            const std::vector<sha256_hash> &HashArray() const { return m_hash_array; }

            entry get_entry() const;

            std::string get_encode() const;

            // @returns a pretty-printed string representation of block structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const hash_array &hashArray);

        private:
            // populate block data from entry
            void populate(const entry& e);

            // hash
            std::vector<sha256_hash> m_hash_array;
        };
    }
}


#endif //LIBTAU_HASH_ARRAY_HPP
