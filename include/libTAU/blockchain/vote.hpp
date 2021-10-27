/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_VOTE_HPP
#define LIBTAU_VOTE_HPP


#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/sha1_hash.hpp"
#include "libTAU/kademlia/item.hpp"
#include "libTAU/kademlia/types.hpp"


namespace libTAU::blockchain {
    class vote {
    public:
        vote() = default;

        // @param Construct with entry
        explicit vote(const entry& e);

        // @param Construct with bencode
        explicit vote(std::string encode): vote(bdecode(encode)) {}

        const sha256_hash &block_hash() const { return m_block_hash; }

        int64_t block_number() const { return m_block_number; }

        int count() const { return m_count; }

        void vote_up() { m_count++; }

        bool empty() { return m_block_hash.is_all_zeros(); }

        entry get_entry() const;

        std::string get_encode() const;

        bool operator==(const vote &rhs) const {
            return m_block_hash == rhs.m_block_hash &&
                   m_block_number == rhs.m_block_number;
        }

        bool operator!=(const vote &rhs) const {
            return !(rhs == *this);
        }

        bool operator<(const vote &rhs) const {
            return m_count < rhs.m_count;
        }

        bool operator>(const vote &rhs) const {
            return rhs < *this;
        }

        bool operator<=(const vote &rhs) const {
            return !(rhs < *this);
        }

        bool operator>=(const vote &rhs) const {
            return !(*this < rhs);
        }

    private:
        // populate block chain signal info from entry
        void populate(const entry& e);

        sha256_hash m_block_hash;

        std::int64_t m_block_number{};

        int m_count = 1;
    };
}


#endif //LIBTAU_VOTE_HPP
