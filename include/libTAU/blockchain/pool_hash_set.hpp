/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_POOL_HASH_SET_HPP
#define LIBTAU_POOL_HASH_SET_HPP


#include <utility>

#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"
#include "libTAU/hasher.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/sha1_hash.hpp"


namespace libTAU {
    namespace blockchain {
        class pool_hash_set {
        public:
            // @param Construct with entry
            explicit pool_hash_set(const entry &e);

            // @param Construct with bencode
            explicit pool_hash_set(std::string encode) : pool_hash_set(bdecode(encode)) {}

            explicit pool_hash_set(std::set<sha1_hash> mPoolHashSet) : m_pool_hash_set(std::move(mPoolHashSet)) {
                auto encode = get_encode();
                m_hash = hasher(encode).final();
            }

            const std::set<sha1_hash> &PoolHashSet() const { return m_pool_hash_set; }

            // @returns the SHA1 hash of this block
            const sha1_hash &sha1() const { return m_hash; }

            bool empty() const { return m_pool_hash_set.empty(); }

            entry get_entry() const;

            std::string get_encode() const;

            // @returns a pretty-printed string representation of block structure
            std::string to_string() const;

            friend std::ostream &operator<<(std::ostream &os, const pool_hash_set &hashArray);

        private:
            // populate hash array from entry
            void populate(const entry &e);

            // pool hash set
            std::set<sha1_hash> m_pool_hash_set;

            // sha1 hash
            sha1_hash m_hash;
        };
    }
}


#endif //LIBTAU_POOL_HASH_SET_HPP
