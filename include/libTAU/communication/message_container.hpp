/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_MESSAGE_CONTAINER_HPP
#define LIBTAU_MESSAGE_CONTAINER_HPP

#include <ostream>
#include "libTAU/aux_/common.h"
#include "libTAU/aux_/rlp.h"
#include "libTAU/aux_/export.hpp"
#include "libTAU/communication/message.hpp"

namespace libTAU {
    namespace communication {

        // The ``message_container`` class represents
        // one type of mutable wrapper,
        // is used to put multiple messages together
//        class TORRENT_EXPORT message_container {
//
//        public:
//            explicit message_container(aux::bytesConstRef _rlp);
//
//            explicit message_container(std::vector<message> messages);
//
//            // @returns all messages in this container
//            std::vector<message> messages() const { return m_messages; }
//
//            // Serialises this message container to an RLPStream
//            void streamRLP(aux::RLPStream& _s) const;
//
//            // @returns the RLP serialisation of this message container
//            aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }
//
//            // @returns a pretty-printed string representation of message structure
//            std::string to_string() const;
//
//            friend std::ostream &operator<<(std::ostream &os, const message_container &container);
//
//        private:
//            // Construct message container object from rlp serialisation
//            void populate(aux::RLP const& _msg_container);
//
//            // messages in message container
//            std::vector<message> m_messages;
//        };
    }
}


#endif //LIBTAU_MESSAGE_CONTAINER_HPP
