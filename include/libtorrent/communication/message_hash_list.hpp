/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MESSAGE_HASH_LIST_HPP
#define LIBTAU_MESSAGE_HASH_LIST_HPP


#include "libtorrent/aux_/common.h"
#include "libtorrent/aux_/rlp.h"
#include "libtorrent/aux_/export.hpp"

namespace libtorrent {
    namespace communication {

        // The ``message_hash_list`` class is a list, encode/decode message hash list
        class TORRENT_EXPORT message_hash_list {

                public:
                explicit message_hash_list(aux::bytesConstRef _rlp);

                explicit message_hash_list(std::vector<aux::bytes> message_hash_list);

                // @returns all message hash in this container
                std::vector<aux::bytes> hash_list() const { return m_message_hash_list; }

                // Serialises this message hash list to an RLPStream
                void streamRLP(aux::RLPStream& _s) const;

                // @returns the RLP serialisation of this message hash list
                aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

                private:
                // Construct message hash list object from rlp serialisation
                void populate(aux::RLP const& hash_list);

                // message hash list
                std::vector<aux::bytes> m_message_hash_list;
        };
    }
}


#endif //LIBTAU_MESSAGE_HASH_LIST_HPP
