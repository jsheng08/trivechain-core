// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2020 The Trivechain Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include "arith_uint256.h"

#include <assert.h>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateDevNetGenesisBlock(const uint256 &prevBlockHash, const std::string& devNetName, uint32_t nTime, uint32_t nNonce, uint32_t nBits, const CAmount& genesisReward)
{
    assert(!devNetName.empty());

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    // put height (BIP34) and devnet name into coinbase
    txNew.vin[0].scriptSig = CScript() << 1 << std::vector<unsigned char>(devNetName.begin(), devNetName.end());
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = CScript() << OP_RETURN;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = 4;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock = prevBlockHash;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "1 Mar 2018 Astronomers detect signal of Universes first stars";
    const CScript genesisOutputScript = CScript() << ParseHex("a8a308a009e3b0fa6a1b55eea6c7e8b00a0221fab0ab7934f7e4c0132c134d857c4088ad4dd0f549c92a6dcdd2a1288237f5de1d66b605d2529a7cc1c3ad963bf7") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

static CBlock CreateTestnetGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "14 Oct 2019 MaGIC with MBA has Launched Blockchain Researcher Lab Program in Malaysia";
    const CScript genesisOutputScript = CScript() << ParseHex("a8a308a009e3b0fa6a1b55eea6c7e8b00a0221fab0ab7934f7e4c0132c134d857c4088ad4dd0f549c92a6dcdd2a1288237f5de1d66b605d2529a7cc1c3ad963bf7") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int64_t nWindowSize, int64_t nThreshold)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
    if (nWindowSize != -1) {
            consensus.vDeployments[d].nWindowSize = nWindowSize;
    }
    if (nThreshold != -1) {
            consensus.vDeployments[d].nThreshold = nThreshold;
    }
}

void CChainParams::UpdateDIP3Parameters(int nActivationHeight, int nEnforcementHeight)
{
    consensus.DIP0003Height = nActivationHeight;
    consensus.DIP0003EnforcementHeight = nEnforcementHeight;
}

void CChainParams::UpdateBudgetParameters(int nMasternodePaymentsStartBlock, int nBudgetPaymentsStartBlock, int nSuperblockStartBlock)
{
    consensus.nMasternodePaymentsStartBlock = nMasternodePaymentsStartBlock;
    consensus.nBudgetPaymentsStartBlock = nBudgetPaymentsStartBlock;
    consensus.nSuperblockStartBlock = nSuperblockStartBlock;
}

void CChainParams::UpdateSubsidyAndDiffParams(int nMinimumDifficultyBlocks, int nHighSubsidyBlocks, int nHighSubsidyFactor)
{
    consensus.nMinimumDifficultyBlocks = nMinimumDifficultyBlocks;
    consensus.nHighSubsidyBlocks = nHighSubsidyBlocks;
    consensus.nHighSubsidyFactor = nHighSubsidyFactor;
}

void CChainParams::UpdateLLMQChainLocks(Consensus::LLMQType llmqType) {
    consensus.llmqTypeChainLocks = llmqType;
}

static CBlock FindDevNetGenesisBlock(const Consensus::Params& params, const CBlock &prevBlock, const CAmount& reward)
{
    std::string devNetName = GetDevNetName();
    assert(!devNetName.empty());

    CBlock block = CreateDevNetGenesisBlock(prevBlock.GetHash(), devNetName.c_str(), prevBlock.nTime + 1, 0, prevBlock.nBits, reward);

    arith_uint256 bnTarget;
    bnTarget.SetCompact(block.nBits);

    for (uint32_t nNonce = 0; nNonce < UINT32_MAX; nNonce++) {
        block.nNonce = nNonce;

        uint256 hash = block.GetHash();
        if (UintToArith256(hash) <= bnTarget)
            return block;
    }

    // This is very unlikely to happen as we start the devnet with a very low difficulty. In many cases even the first
    // iteration of the above loop will give a result already
    error("FindDevNetGenesisBlock: could not find devnet genesis block for %s", devNetName);
    assert(false);
}

// this one is for testing only
static Consensus::LLMQParams llmq5_60 = {
        .type = Consensus::LLMQ_5_60,
        .name = "llmq_5_60",
        .size = 5,
        .minSize = 3,
        .threshold = 3,

        .dkgInterval = 24, // one DKG per hour
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 18,
        .dkgBadVotesThreshold = 8,

        .signingActiveQuorumCount = 2, // just a few ones to allow easier testing

        .keepOldConnections = 3,
};

static Consensus::LLMQParams llmq25_60 = {
        .type = Consensus::LLMQ_25_60,
        .name = "llmq_25_60",
        .size = 25,
        .minSize = 20,
        .threshold = 15,

        .dkgInterval = 60, // one DKG per hour
        .dkgPhaseBlocks = 5,
        .dkgMiningWindowStart = 25, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 45,
        .dkgBadVotesThreshold = 20,

        .signingActiveQuorumCount = 24, // a full day worth of LLMQs

        .keepOldConnections = 25,
};

static Consensus::LLMQParams llmq100_60 = {
        .type = Consensus::LLMQ_100_60,
        .name = "llmq_100_60",
        .size = 100,
        .minSize = 75,
        .threshold = 60,

        .dkgInterval = 60 * 12, // one DKG every 12 hours
        .dkgPhaseBlocks = 10,
        .dkgMiningWindowStart = 50, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 70,
        .dkgBadVotesThreshold = 75,

        .signingActiveQuorumCount = 4, // two days worth of LLMQs

        .keepOldConnections = 5,
};

// Used for deployment and min-proto-version signalling, so it needs a higher threshold
static Consensus::LLMQParams llmq100_85 = {
        .type = Consensus::LLMQ_100_85,
        .name = "llmq_100_85",
        .size = 100,
        .minSize = 87,
        .threshold = 85,

        .dkgInterval = 60 * 24, // one DKG every 24 hours
        .dkgPhaseBlocks = 10,
        .dkgMiningWindowStart = 50, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 120, // give it a larger mining window to make sure it is mined
        .dkgBadVotesThreshold = 75,

        .signingActiveQuorumCount = 4, // four days worth of LLMQs

        .keepOldConnections = 5,
};


/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */


class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 525600;
        consensus.nMasternodePaymentsStartBlock = 1000; 
        consensus.nMasternodePaymentsIncreaseBlock = 445500; // Masternode payment in Trivechain is fixed at 40% before this block height
        consensus.nMasternodePaymentsIncreasePeriod = 0; // Masternode payment in Trivechain is fixed at 40% once it started and only made changes once
        consensus.nDirectSendConfirmationsRequired = 15;
        consensus.nDirectSendKeepLock = 60;

        consensus.nBudgetPaymentsStartBlock = 2; // actual historical value
        consensus.nBudgetPaymentsCycleBlocks = 43800; // ~(60*24*30), actual number of blocks per month is 525600 / 12 = 43800
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nSuperblockStartBlock = 1000;
        consensus.nSuperblockStartHash = uint256S("000001b7f95252a24eb674bb1fd7b511c057fb57a75b8e3ae303d0dd57116fdd");
        consensus.nSuperblockCycle = 43800; // ~(60*24*30), actual number of blocks per month is 525600 / 12 = 43800
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.BIP34Height = 951;
        consensus.BIP34Hash = uint256S("000007d91d1254d60e2dd1ae580383070a4ddffa4c64c2eeb4a2f9ecc0414343");
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 450000;
        consensus.DIP0001Height = 450000;
        consensus.DIP0003Height = 445500;
        consensus.DIP0003EnforcementHeight = 700000;
        consensus.DIP0003EnforcementHash = uint256S("00000000965564301349fb5141f6d1f5340d1d91b645cbb62f7e2dc87eb1522f");
        consensus.powLimit = uint256S("00000fffff000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Adjustment using 24 hour
        consensus.nPowTargetSpacing = 60; // Trivechain: 1 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1368; // 95% of 1440
        consensus.nMinerConfirmationWindow = 1440; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1486252800; // Feb 5th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517788800; // Feb 5th, 2018

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1508025600; //  October 15, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1539561600; // October 15, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 50;

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 1569945600; // October 1, 2019 4:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 1601568000; // October 1, 2020 4:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThreshold = 50; 

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 1569945600; // October 1, 2019 4:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 1601568000; // October 1, 2020 4:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThreshold = 50; 

        // Deployment of DIP0008
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = 1569945600; // October 1, 2019 4:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = 1601568000; // October 1, 2020 4:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nThreshold = 50; 

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000005f4ec84fea4acd76a"); // 694146

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000000245b0dc83cd117509af94d0196474d99f4215ed1924a93e1cf5b04d"); //694000
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xdd;
        pchMessageStart[1] = 0xba;
        pchMessageStart[2] = 0xbc;
        pchMessageStart[3] = 0x7e;
        nDefaultPort = 9999;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1519872632, 1542867, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000008ad295e16d2a5456aef65cb1c28139835aba6a340d0be0fb8ca2b2e9e26"));
        assert(genesis.hashMerkleRoot == uint256S("0x72c0f9b5871b31ead65a1a21a2d769f74c674e954fb4d4baeeac0e23b37699c8"));

        vSeeds.emplace_back("dnsseed.trivechain.com", true);

        // Trivechain addresses start with 'T'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        // Trivechain script addresses start with '8'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,18);
        // Trivechain private keys start with 'X'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,204);
        // Trivechain BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        // Trivechain BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // Trivechain BIP44 coin type is '1'
        nExtCoinType = 1;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_25_60] = llmq25_60;
        consensus.llmqs[Consensus::LLMQ_100_60] = llmq100_60;
        consensus.llmqs[Consensus::LLMQ_100_85] = llmq100_85;
        consensus.llmqTypeChainLocks = Consensus::LLMQ_100_60;
        consensus.llmqTypeDirectSend = Consensus::LLMQ_25_60;

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fRequireRoutableExternalIP = true;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = false;

        nPoolMinParticipants = 3;
        nPoolMaxParticipants = 5;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        vSporkAddresses = {"TFBQSoycHWzibVEBh6hFkEQ8WCbpyVWzUH"};
        nMinSporkKeys = 1;
        fBIP9CheckMasternodesUpgraded = true;

        checkpointData = (CCheckpointData) {
            {
                {   1500, uint256S("0x0000019499f2569d0c4c99a171a94294f8111036fc3331a85e1d09320f586684")},
                {   5000, uint256S("0x000002bcecf140a86b1db138706636e58b09b6271066110369cb4b2c168b0262")},
                {  50000, uint256S("0x00000000000012dcd42042070a4e106e577394760f7663ebfc130c348766acea")},
                { 100000, uint256S("0x0000000000015c62c9a493529215f3f0c3e9e01a45c14063671340558dce34d4")},
                { 150000, uint256S("0x000000000000a5a404d4b403401c61159df545da193fe002115d7f799e2b85fe")},
                { 200000, uint256S("0x00000000000df26f68d1a64d69ef250797d773b0c6e00fa399ee3cec059541e7")},
                { 226650, uint256S("0x0000000000012c3d19793ebb8fe56bf3644529b159fbee8b7a8ab21ff463f4eb")},
                { 288000, uint256S("0x00000000029c6f80395cbec98682c8fba0f13d47b7089607637173ff7f65f65b")},
                { 350000, uint256S("0x00000000335cfe6e42e70756bd9925b927d38309caabf8ac67e969799cb24b42")},           
                { 450000, uint256S("0x0000000003283dab0bc51f7616666e7885b58cdbb619221faebcb55b5fe7c46a")},           
                { 463985, uint256S("0x0000000004bb95c07ce12675f74434eaeda033634f0ff84e25a3d26806eb670f")},
                { 694000, uint256S("0x000000000245b0dc83cd117509af94d0196474d99f4215ed1924a93e1cf5b04d")},
            }
        };

        chainTxData = ChainTxData{
            1585821596, // * UNIX timestamp of last known number of transactions (Block 1173619)
            1205409,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.01        // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Testnet
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 525600;
        consensus.nMasternodePaymentsStartBlock = 50000; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 0;
        consensus.nMasternodePaymentsIncreasePeriod = 0;
        consensus.nDirectSendConfirmationsRequired = 2;
        consensus.nDirectSendKeepLock = 15;
        consensus.nBudgetPaymentsStartBlock = 100000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 100001; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockStartHash = uint256(); // do not check this on testnet
        consensus.nSuperblockCycle = 60; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("000000037630bd6a36eecdca97076c339cce00a3b2ac72cefe1a50265f837afa");
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.DIP0001Height = 1;
        consensus.DIP0003Height = 1;
        consensus.DIP0003EnforcementHeight = 1;
        consensus.DIP0003EnforcementHash = uint256S("000000037630bd6a36eecdca97076c339cce00a3b2ac72cefe1a50265f837afa");
        consensus.powLimit = uint256S("0000ffffff000000000000000000000000000000000000000000000000000000"); // ~uint256(0) >> 20
        consensus.nPowTargetTimespan = 2 * 60 * 60; // Trivechain: 2 hours
        consensus.nPowTargetSpacing = 60; // Trivechain: 1 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 90; // 75% for testchains
        consensus.nMinerConfirmationWindow = 120; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1506556800; // September 28th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1538092800; // September 28th, 2018

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1505692800; // Sep 18th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1537228800; // Sep 18th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 5; // 50% of 100

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 1544655600; // Dec 13th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 1576191600; // Dec 13th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThreshold = 5; // 50% of 100

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 1544655600; // Dec 13th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 1576191600; // Dec 13th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThreshold = 5; // 50% of 100

        // Deployment of DIP0008
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = 1553126400; // Mar 21st, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = 1584748800; // Mar 21st, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nWindowSize = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nThreshold = 5; // 50% of 100

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("000000000000000000000000000000000000000000000000000000769a821391"); // 500000

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("000006556abd1f9c7c6d158027f24a5362794115acdd9393eb2404259b3fb2e9"); // 500000

        pchMessageStart[0] = 0xcc;
        pchMessageStart[1] = 0xa2;
        pchMessageStart[2] = 0xba;
        pchMessageStart[3] = 0x0a;
        nDefaultPort = 19999;
        nPruneAfterHeight = 1000;

        genesis = CreateTestnetGenesisBlock(1571739000, 338132, 0x1e0ffff0, 4, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000288fe5535c740c1418c70a6da3affa7c858ea6de8852a568ed24d5328d5"));
        assert(genesis.hashMerkleRoot == uint256S("0x1a0fcbc4f780019418d47b90a3a17c1ccee58f1d5b8aa28400658c6f45561ebf"));

        vFixedSeeds.clear();
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("dnsseed.trvc.dev", true);

        // Testnet Trivechain addresses start with 't'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,127);
        // Testnet Trivechain script addresses start with 's'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet Trivechain BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Testnet Trivechain BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Testnet Trivechain BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_25_60] = llmq25_60;
        consensus.llmqs[Consensus::LLMQ_100_60] = llmq100_60;
        consensus.llmqs[Consensus::LLMQ_100_85] = llmq100_85;
        consensus.llmqTypeChainLocks = Consensus::LLMQ_25_60;
        consensus.llmqTypeDirectSend = Consensus::LLMQ_25_60;

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fRequireRoutableExternalIP = true;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = false;
        fAllowMultiplePorts = true;

        nPoolMinParticipants = 1;
        nPoolMaxParticipants = 5;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        vSporkAddresses = {"tRaXPu5bovE5bXx7fgZ5ANsmACdra86PPm"};
        nMinSporkKeys = 1;
        fBIP9CheckMasternodesUpgraded = true;

        checkpointData = (CCheckpointData) {
            {
                {   5000, uint256S("0x000000130f14dac7114fe6b9c0a06d4d9d1f7f906ddd836d5cf90d659aa9a1be")},
                {  10000, uint256S("0x0000000a69a5753fa586bb611b1e8588738a347a2c5eacd8089cab7b1bce6973")},
                {  50000, uint256S("0x0000016e0eef3df96c689e123b87789d7284a831c8e1a4098af4a120e404f47d")},
                { 100000, uint256S("0x0000016ee96319fa80c994568a99e0deb01638071c87a492b88f033ba1fcaca7")},
                { 200000, uint256S("0x0000012e214a3c09e5927ea6f0d40f375f269711ee5c979c96f173b5579ff0ba")},
                { 300000, uint256S("0x000006055a3171513b42d5d46498945dde109c9bae079b32cdf7e8f14f27bc82")},
                { 400000, uint256S("0x00000307acf685ebf598354b27ef2af8e8373024d598c4bd25dc107fe858a1b6")},
                { 500000, uint256S("0x000006556abd1f9c7c6d158027f24a5362794115acdd9393eb2404259b3fb2e9")},
            }
        };

        chainTxData = ChainTxData{
            1574164251, // * UNIX timestamp of last known number of transactions (Block 213054)
            1733259,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.01        // * estimated number of transactions per second after that timestamp
        };

    }
};

/**
 * Devnet
 */
class CDevNetParams : public CChainParams {
public:
    CDevNetParams() {
        strNetworkID = "dev";
        consensus.nSubsidyHalvingInterval = 210240;
        consensus.nMasternodePaymentsStartBlock = 4010; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 4030;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nDirectSendConfirmationsRequired = 2;
        consensus.nDirectSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 4100;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 4200; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockStartHash = uint256(); // do not check this on devnet
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on devnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 1; // BIP34 activated immediately on devnet
        consensus.BIP65Height = 1; // BIP65 activated immediately on devnet
        consensus.BIP66Height = 1; // BIP66 activated immediately on devnet
        consensus.DIP0001Height = 2; // DIP0001 activated immediately on devnet
        consensus.DIP0003Height = 2; // DIP0003 activated immediately on devnet
        consensus.DIP0003EnforcementHeight = 2; // DIP0003 activated immediately on devnet
        consensus.DIP0003EnforcementHash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Trivechain: 1 day
        consensus.nPowTargetSpacing = 60; // Trivechain: 1 minute
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1506556800; // September 28th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1538092800; // September 28th, 2018

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1505692800; // Sep 18th, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1537228800; // Sep 18th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 50; // 50% of 100

        // Deployment of BIP147
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 1517792400; // Feb 5th, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 1549328400; // Feb 5th, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nThreshold = 50; // 50% of 100

        // Deployment of DIP0003
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 1535752800; // Sep 1st, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 1567288800; // Sep 1st, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nThreshold = 50; // 50% of 100

        // Deployment of DIP0008
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = 1553126400; // Mar 21st, 2019
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = 1584748800; // Mar 21st, 2020
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nThreshold = 50; // 50% of 100

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xcc;
        pchMessageStart[1] = 0xa2;
        pchMessageStart[2] = 0xba;
        pchMessageStart[3] = 0x0a;
        nDefaultPort = 19799;
        nPruneAfterHeight = 1000;

        genesis = CreateTestnetGenesisBlock(1571739000, 338132, 0x1e0ffff0, 4, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000288fe5535c740c1418c70a6da3affa7c858ea6de8852a568ed24d5328d5"));
        assert(genesis.hashMerkleRoot == uint256S("0x1a0fcbc4f780019418d47b90a3a17c1ccee58f1d5b8aa28400658c6f45561ebf"));

        devnetGenesis = FindDevNetGenesisBlock(consensus, genesis, 50 * COIN);
        consensus.hashDevnetGenesisBlock = devnetGenesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();

        // Testnet Trivechain addresses start with 't'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,127);
        // Testnet Trivechain script addresses start with 's'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125);
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet Trivechain BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Testnet Trivechain BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Testnet Trivechain BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_25_60] = llmq25_60;
        consensus.llmqs[Consensus::LLMQ_100_60] = llmq100_60;
        consensus.llmqs[Consensus::LLMQ_100_85] = llmq100_85;
        consensus.llmqTypeChainLocks = Consensus::LLMQ_25_60;
        consensus.llmqTypeDirectSend = Consensus::LLMQ_25_60;

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;

        nPoolMinParticipants = 3;
        nPoolMaxParticipants = 5;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        vSporkAddresses = {"tRaXPu5bovE5bXx7fgZ5ANsmACdra86PPm"};
        nMinSporkKeys = 1;
        // devnets are started with no blocks and no MN, so we can't check for upgraded MN (as there are none)
        fBIP9CheckMasternodesUpgraded = false;

        checkpointData = (CCheckpointData) {
            {
                { 0, uint256S("0x00000288fe5535c740c1418c70a6da3affa7c858ea6de8852a568ed24d5328d5")},
                { 1, devnetGenesis.GetHash() },
            }
        };

        chainTxData = ChainTxData{
            devnetGenesis.GetBlockTime(), // * UNIX timestamp of devnet genesis block
            2,                            // * we only have 2 coinbase transactions when a devnet is started up
            0.01                          // * estimated number of transactions per second
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMasternodePaymentsStartBlock = 240;
        consensus.nMasternodePaymentsIncreaseBlock = 350;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nDirectSendConfirmationsRequired = 2;
        consensus.nDirectSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nSuperblockStartBlock = 1500;
        consensus.nSuperblockStartHash = uint256(); // do not check this on regtest
        consensus.nSuperblockCycle = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.DIP0001Height = 2000;
        consensus.DIP0003Height = 432;
        consensus.DIP0003EnforcementHeight = 500;
        consensus.DIP0003EnforcementHash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // ~uint256(0) >> 1
        consensus.nPowTargetTimespan = 24 * 60 * 60; // Trivechain: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // Trivechain: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_BIP147].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].bit = 3;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0003].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].bit = 4;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0008].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfc;
        pchMessageStart[1] = 0xc1;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0xdc;
        nDefaultPort = 19899;
        nPruneAfterHeight = 1000;

        genesis = CreateTestnetGenesisBlock(1571739000, 338132, 0x1e0ffff0, 4, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000288fe5535c740c1418c70a6da3affa7c858ea6de8852a568ed24d5328d5"));
        assert(genesis.hashMerkleRoot == uint256S("0x1a0fcbc4f780019418d47b90a3a17c1ccee58f1d5b8aa28400658c6f45561ebf"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fRequireRoutableExternalIP = false;
        fMineBlocksOnDemand = true;
        fAllowMultipleAddressesFromGroup = true;
        fAllowMultiplePorts = true;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        nPoolMinParticipants = 3;
        nPoolMaxParticipants = 5;

        // privKey: cQMhEEoYK2GvP2QMvGTW9eKTw8owVVEykrAzqnHVGSXm1Hh3bw4T
        vSporkAddresses = {"tAnat6oTARQTTo6uhKMABfp8q8iuE3DeHL"};
        nMinSporkKeys = 1;
        // regtest usually has no masternodes in most tests, so don't check for upgraged MNs
        fBIP9CheckMasternodesUpgraded = false;

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("0x00000288fe5535c740c1418c70a6da3affa7c858ea6de8852a568ed24d5328d5")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // Regtest Trivechain addresses start with 't'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,127);
        // Regtest Trivechain script addresses start with 's'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125);
        // Regtest private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Regtest Trivechain BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        // Regtest Trivechain BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Regtest Trivechain BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_5_60] = llmq5_60;
        consensus.llmqs[Consensus::LLMQ_25_60] = llmq25_60;
        consensus.llmqTypeChainLocks = Consensus::LLMQ_5_60;
        consensus.llmqTypeDirectSend = Consensus::LLMQ_5_60;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::DEVNET) {
        return std::unique_ptr<CChainParams>(new CDevNetParams());
    } else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int64_t nWindowSize, int64_t nThreshold)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout, nWindowSize, nThreshold);
}

void UpdateDIP3Parameters(int nActivationHeight, int nEnforcementHeight)
{
    globalChainParams->UpdateDIP3Parameters(nActivationHeight, nEnforcementHeight);
}

void UpdateBudgetParameters(int nMasternodePaymentsStartBlock, int nBudgetPaymentsStartBlock, int nSuperblockStartBlock)
{
    globalChainParams->UpdateBudgetParameters(nMasternodePaymentsStartBlock, nBudgetPaymentsStartBlock, nSuperblockStartBlock);
}

void UpdateDevnetSubsidyAndDiffParams(int nMinimumDifficultyBlocks, int nHighSubsidyBlocks, int nHighSubsidyFactor)
{
    globalChainParams->UpdateSubsidyAndDiffParams(nMinimumDifficultyBlocks, nHighSubsidyBlocks, nHighSubsidyFactor);
}

void UpdateDevnetLLMQChainLocks(Consensus::LLMQType llmqType)
{
    globalChainParams->UpdateLLMQChainLocks(llmqType);
}
