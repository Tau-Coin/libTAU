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
#include "libTAU/aux_/rlp.h"
#include "libTAU/aux_/export.hpp"
#include "libTAU/entry.hpp"
#include "libTAU/bencode.hpp"
#include "libTAU/bdecode.hpp"

namespace libTAU::communication {

    // The ``message_hash_list`` class is a list, encode/decode message hash list
    class TORRENT_EXPORT message_hash_list {
    public:

        // @param Construct with bencode
        explicit message_hash_list(std::string encode);

//        // @param _rlp rlp encode
//        explicit message_hash_list(aux::bytesConstRef _rlp);
//
//        // @param _rlp rlp encode
//        explicit message_hash_list(aux::bytes const& _rlp): message_hash_list(&_rlp) {}

        explicit message_hash_list(std::vector<aux::bytes> message_hash_list);

        // @returns all message hash in this container
        std::vector<aux::bytes> hash_list() const { return m_message_hash_list; }

//        // Serialises this message hash list to an RLPStream
//        void streamRLP(aux::RLPStream& _s) const;
//
//        // @returns the RLP serialisation of this message hash list
//        aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

        // @returns the bencode
        std::string encode();

        // @returns a pretty-printed string representation of message structure
        std::string to_string() const;

        friend std::ostream &operator<<(std::ostream &os, const message_hash_list &list);

    private:
        // populate hash list data from entry
        void populate(const entry& e);

//        // Construct message hash list object from rlp serialisation
//        void populate(aux::RLP const& hash_list);

        // message hash list
        std::vector<aux::bytes> m_message_hash_list;
    };
}


#endif //LIBTAU_MESSAGE_HASH_LIST_HPP
