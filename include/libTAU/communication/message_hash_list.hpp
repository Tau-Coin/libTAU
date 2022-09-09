/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MESSAGE_HASH_LIST_HPP
#define LIBTAU_MESSAGE_HASH_LIST_HPP


#include <ostream>
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/common_data.h"
#include "libTAU/aux_/export.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"
#include "libTAU/sha1_hash.hpp"
#include "libTAU/hasher.hpp"

namespace libTAU::communication {

    // The ``message_hash_list`` class is a list, encode/decode message hash list
    class TORRENT_EXPORT message_hash_list {
    public:

        // @param Construct with entry
        explicit message_hash_list(const entry& e);

        // @param Construct with bencode
        explicit message_hash_list(std::string encode): message_hash_list(bdecode(encode)) {}

        explicit message_hash_list(std::vector<sha1_hash> message_hash_list);

        // @returns all message hash in this container
        std::vector<sha1_hash> hash_list() const { return m_message_hash_list; }

        entry get_entry() const;

        // @returns the SHA1 hash
        sha1_hash sha1();

        // @returns the bencode
        std::string encode();

        // @returns a pretty-printed string representation of message structure
        std::string to_string() const;

        friend std::ostream &operator<<(std::ostream &os, const message_hash_list &list);

    private:
        // populate hash list data from entry
        void populate(const entry& e);

        // message hash list
        std::vector<sha1_hash> m_message_hash_list;
    };
}


#endif //LIBTAU_MESSAGE_HASH_LIST_HPP
