/*
Copyright (c) 2021, TaiXiang Cui
All rights reserved.

You may use, distribute and modify this code under the terms of the BSD license,
see LICENSE file.
*/

#ifndef LIBTAU_TX_ENTRY_WITH_FEE_HPP
#define LIBTAU_TX_ENTRY_WITH_FEE_HPP


#include <libTAU/sha1_hash.hpp>

namespace libTAU::blockchain {
    class tx_entry_with_fee {
    public:
        tx_entry_with_fee(const sha1_hash &mTxid, int64_t mFee) : m_txid(mTxid), m_fee(mFee) {}

        const sha1_hash &txid() const { return m_txid; }

        void set_txid(const sha1_hash &mTxid) { m_txid = mTxid; }

        int64_t fee() const { return m_fee; }

        void set_fee(int64_t mFee) { m_fee = mFee; }

        bool operator==(const tx_entry_with_fee &rhs) const {
            return m_txid == rhs.m_txid;
        }

        bool operator!=(const tx_entry_with_fee &rhs) const {
            return !(rhs == *this);
        }

        bool operator<(const tx_entry_with_fee &rhs) const {
            if (m_fee < rhs.m_fee)
                return true;
            if (rhs.m_fee < m_fee)
                return false;

            return m_txid < rhs.m_txid;
        }

        bool operator>(const tx_entry_with_fee &rhs) const {
            return rhs < *this;
        }

        bool operator<=(const tx_entry_with_fee &rhs) const {
            return !(rhs < *this);
        }

        bool operator>=(const tx_entry_with_fee &rhs) const {
            return !(*this < rhs);
        }

    private:
        sha1_hash m_txid;

        std::int64_t m_fee;
    };
}

#endif //LIBTAU_TX_ENTRY_WITH_FEE_HPP
