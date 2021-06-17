/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_ONLINE_SIGNAL_HPP
#define LIBTAU_ONLINE_SIGNAL_HPP

// OVERVIEW
//
// 对整个文件的说明，可能有多个类
// 目前只有一个online_signal类

#include <libtorrent/aux_/common.h>
#include <libtorrent/aux_/rlp.h>

namespace libtorrent {
    namespace communication {

	    // The ``online_signal`` class represents 在线信号
        // 对类的说明
        // T------_EXPORT 需要，否则该类不会导出，整个导出文件都有影响
        // online signal
        // one type of mutable wrapper,
        // is used to publish online info in XX channel
        struct TORRENT_EXPORT online_signal {
            
            // 构造函数，可以显示注释
            online_signal(aux::bytesConstRef _rlp);

            // 移动设备ID, 写一行, 否则不导出, 可以加inline关键字
            inline aux::bytes device_id() const { return m_device_id; }

            inline aux::bytes hash_prefix_bytes() const { return m_hash_prefix_bytes; }

            inline uint32_t timestamp() const { return m_timestamp; }

            inline aux::bytes friend_info() const { return m_friend_info; }

            // Serialises this online signal to an RLPStream
            void streamRLP(aux::RLPStream& _s) const;

            // @returns the RLP serialisation of this message
            aux::bytes rlp() const { aux::RLPStream s; streamRLP(s); return s.out(); }

        private:
            // 私有变量目前网页不导出
            // Construct online signal object from rlp serialisation
            void populate(aux::RLP const& _online_signal);

            // device id
            aux::bytes m_device_id;

            // bytes consist of first byte of ordered messages hash
            aux::bytes m_hash_prefix_bytes;

            // online signal timestamp
            uint32_t m_timestamp;

            // friend info payload, used to exchange friends on multi-device
            aux::bytes m_friend_info;
        };
    }
}

#endif //LIBTAU_ONLINE_SIGNAL_HPP
