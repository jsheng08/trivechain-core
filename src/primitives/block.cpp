// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "streams.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "crypto/hash_algos.h"

static const uint32_t X16R_ACTIVATION_TIME = 1555872222;
static const uint32_t MAINNET_X16RV2_ACTIVATION_TIME = 1569945600;

uint256 CBlockHeader::GetHash() const
{
    std::vector<unsigned char> vch(80);
    CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, vch, 0);
    ss << *this;
    
    if (nTime > MAINNET_X16RV2_ACTIVATION_TIME) {
        return HashX16RV2((const char *)vch.data(), (const char *)vch.data() + vch.size(), hashPrevBlock);
    } else if (nTime > X16R_ACTIVATION_TIME) {
        return HashX16R((const char *)vch.data(), (const char *)vch.data() + vch.size(), hashPrevBlock);
    }
    return HashX11((const char *)vch.data(), (const char *)vch.data() + vch.size());
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}