//
// message container
// one type of mutable wrapper,
// is used to put multiple messages together
//

#ifndef LIBTAU_MESSAGE_CONTAINER_HPP
#define LIBTAU_MESSAGE_CONTAINER_HPP

#include <libtorrent/aux_/common.h>
#include <libtorrent/aux_/rlp.h>
#include <libtorrent/communication/message.hpp>

namespace libtorrent {
    namespace communication {
        class message_container {
        public:
            message_container(aux::bytesConstRef _rlp);

            std::vector<message> messages() const {
                return m_messages;
            }

            // Serialises this message container to an RLPStream
            void streamRLP(aux::RLPStream& _s) const;

            // @returns the RLP serialisation of this message container
            aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

        private:
            // Construct message container object from rlp serialisation
            void populate(aux::RLP const& _msg_container);

            // messages in message container
            std::vector<message> m_messages;
        };
    }
}


#endif //LIBTAU_MESSAGE_CONTAINER_HPP
