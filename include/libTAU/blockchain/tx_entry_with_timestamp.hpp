/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_TX_ENTRY_WITH_TIMESTAMP_HPP
#define LIBTAU_TX_ENTRY_WITH_TIMESTAMP_HPP


#include <libTAU/sha1_hash.hpp>

namespace libTAU::blockchain {
    class tx_entry_with_timestamp {
    public:
        tx_entry_with_timestamp(const sha1_hash &mTxid, int64_t mTimestamp) : m_txid(mTxid), m_timestamp(mTimestamp) {}

        const sha1_hash &txid() const { return m_txid; }

        void set_txid(const sha1_hash &mTxid) { m_txid = mTxid; }

        int64_t timestamp() const { return m_timestamp; }

        void set_timestamp(int64_t mTimestamp) { m_timestamp = mTimestamp; }

        bool operator==(const tx_entry_with_timestamp &rhs) const {
            return m_txid == rhs.m_txid;
        }

        bool operator!=(const tx_entry_with_timestamp &rhs) const {
            return !(rhs == *this);
        }

        bool operator<(const tx_entry_with_timestamp &rhs) const {
            if (m_timestamp < rhs.m_timestamp)
                return true;
            if (rhs.m_timestamp < m_timestamp)
                return false;

            return m_txid < rhs.m_txid;
        }

        bool operator>(const tx_entry_with_timestamp &rhs) const {
            return rhs < *this;
        }

        bool operator<=(const tx_entry_with_timestamp &rhs) const {
            return !(rhs < *this);
        }

        bool operator>=(const tx_entry_with_timestamp &rhs) const {
            return !(*this < rhs);
        }

    private:
        sha1_hash m_txid;

        std::int64_t m_timestamp;
    };
}

#endif //LIBTAU_TX_ENTRY_WITH_TIMESTAMP_HPP
