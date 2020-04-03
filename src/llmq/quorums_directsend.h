// Copyright (c) 2019-2020 The Trivechain Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TRIVECHAIN_QUORUMS_DIRECTSEND_H
#define TRIVECHAIN_QUORUMS_DIRECTSEND_H

#include "quorums_signing.h"

#include "coins.h"
#include "unordered_lru_cache.h"
#include "primitives/transaction.h"

#include <unordered_map>
#include <unordered_set>

namespace llmq
{

class CDirectSendLock
{
public:
    std::vector<COutPoint> inputs;
    uint256 txid;
    CBLSLazySignature sig;

public:
    ADD_SERIALIZE_METHODS

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(inputs);
        READWRITE(txid);
        READWRITE(sig);
    }

    uint256 GetRequestId() const;
};

typedef std::shared_ptr<CDirectSendLock> CDirectSendLockPtr;

class CDirectSendDb
{
private:
    CDBWrapper& db;

    unordered_lru_cache<uint256, CDirectSendLockPtr, StaticSaltedHasher, 10000> islockCache;
    unordered_lru_cache<uint256, uint256, StaticSaltedHasher, 10000> txidCache;
    unordered_lru_cache<COutPoint, uint256, SaltedOutpointHasher, 10000> outpointCache;

public:
    CDirectSendDb(CDBWrapper& _db) : db(_db) {}

    void WriteNewDirectSendLock(const uint256& hash, const CDirectSendLock& islock);
    void RemoveDirectSendLock(CDBBatch& batch, const uint256& hash, CDirectSendLockPtr islock);

    void WriteDirectSendLockMined(const uint256& hash, int nHeight);
    void RemoveDirectSendLockMined(const uint256& hash, int nHeight);
    void WriteDirectSendLockArchived(CDBBatch& batch, const uint256& hash, int nHeight);
    std::unordered_map<uint256, CDirectSendLockPtr> RemoveConfirmedDirectSendLocks(int nUntilHeight);
    void RemoveArchivedDirectSendLocks(int nUntilHeight);
    bool HasArchivedDirectSendLock(const uint256& islockHash);
    size_t GetDirectSendLockCount();

    CDirectSendLockPtr GetDirectSendLockByHash(const uint256& hash);
    uint256 GetDirectSendLockHashByTxid(const uint256& txid);
    CDirectSendLockPtr GetDirectSendLockByTxid(const uint256& txid);
    CDirectSendLockPtr GetDirectSendLockByInput(const COutPoint& outpoint);

    std::vector<uint256> GetDirectSendLocksByParent(const uint256& parent);
    std::vector<uint256> RemoveChainedDirectSendLocks(const uint256& islockHash, const uint256& txid, int nHeight);
};

class CDirectSendManager : public CRecoveredSigsListener
{
private:
    CCriticalSection cs;
    CDirectSendDb db;

    std::thread workThread;
    CThreadInterrupt workInterrupt;

    /**
     * Request ids of inputs that we signed. Used to determine if a recovered signature belongs to an
     * in-progress input lock.
     */
    std::unordered_set<uint256, StaticSaltedHasher> inputRequestIds;

    /**
     * These are the islocks that are currently in the middle of being created. Entries are created when we observed
     * recovered signatures for all inputs of a TX. At the same time, we initiate signing of our sigshare for the islock.
     * When the recovered sig for the islock later arrives, we can finish the islock and propagate it.
     */
    std::unordered_map<uint256, CDirectSendLock, StaticSaltedHasher> creatingDirectSendLocks;
    // maps from txid to the in-progress islock
    std::unordered_map<uint256, CDirectSendLock*, StaticSaltedHasher> txToCreatingDirectSendLocks;

    // Incoming and not verified yet
    std::unordered_map<uint256, std::pair<NodeId, CDirectSendLock>> pendingDirectSendLocks;

    // TXs which are neither IS locked nor ChainLocked. We use this to determine for which TXs we need to retry IS locking
    // of child TXs
    struct NonLockedTxInfo {
        const CBlockIndex* pindexMined{nullptr};
        CTransactionRef tx;
        std::unordered_set<uint256, StaticSaltedHasher> children;
    };
    std::unordered_map<uint256, NonLockedTxInfo, StaticSaltedHasher> nonLockedTxs;
    std::unordered_map<COutPoint, uint256, SaltedOutpointHasher> nonLockedTxsByOutpoints;

    std::unordered_set<uint256, StaticSaltedHasher> pendingRetryTxs;

public:
    CDirectSendManager(CDBWrapper& _llmqDb);
    ~CDirectSendManager();

    void Start();
    void Stop();
    void InterruptWorkerThread();

public:
    bool ProcessTx(const CTransaction& tx, bool allowReSigning, const Consensus::Params& params);
    bool CheckCanLock(const CTransaction& tx, bool printDebug, const Consensus::Params& params);
    bool CheckCanLock(const COutPoint& outpoint, bool printDebug, const uint256& txHash, CAmount* retValue, const Consensus::Params& params);
    bool IsLocked(const uint256& txHash);
    bool IsConflicted(const CTransaction& tx);
    CDirectSendLockPtr GetConflictingLock(const CTransaction& tx);

    virtual void HandleNewRecoveredSig(const CRecoveredSig& recoveredSig);
    void HandleNewInputLockRecoveredSig(const CRecoveredSig& recoveredSig, const uint256& txid);
    void HandleNewDirectSendLockRecoveredSig(const CRecoveredSig& recoveredSig);

    void TrySignDirectSendLock(const CTransaction& tx);

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);
    void ProcessMessageDirectSendLock(CNode* pfrom, const CDirectSendLock& islock, CConnman& connman);
    bool PreVerifyDirectSendLock(NodeId nodeId, const CDirectSendLock& islock, bool& retBan);
    bool ProcessPendingDirectSendLocks();
    std::unordered_set<uint256> ProcessPendingDirectSendLocks(int signHeight, const std::unordered_map<uint256, std::pair<NodeId, CDirectSendLock>>& pend, bool ban);
    void ProcessDirectSendLock(NodeId from, const uint256& hash, const CDirectSendLock& islock);
    void UpdateWalletTransaction(const CTransactionRef& tx, const CDirectSendLock& islock);

    void ProcessNewTransaction(const CTransactionRef& tx, const CBlockIndex* pindex, bool allowReSigning);
    void TransactionAddedToMempool(const CTransactionRef& tx);
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindex, const std::vector<CTransactionRef>& vtxConflicted);
    void BlockDisconnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexDisconnected);

    void AddNonLockedTx(const CTransactionRef& tx, const CBlockIndex* pindexMined);
    void RemoveNonLockedTx(const uint256& txid, bool retryChildren);
    void RemoveConflictedTx(const CTransaction& tx);
    void TruncateRecoveredSigsForInputs(const CDirectSendLock& islock);

    void NotifyChainLock(const CBlockIndex* pindexChainLock);
    void UpdatedBlockTip(const CBlockIndex* pindexNew);

    void HandleFullyConfirmedBlock(const CBlockIndex* pindex);

    void RemoveMempoolConflictsForLock(const uint256& hash, const CDirectSendLock& islock);
    void ResolveBlockConflicts(const uint256& islockHash, const CDirectSendLock& islock);
    void RemoveChainLockConflictingLock(const uint256& islockHash, const CDirectSendLock& islock);
    void AskNodesForLockedTx(const uint256& txid);
    bool ProcessPendingRetryLockTxs();

    bool AlreadyHave(const CInv& inv);
    bool GetDirectSendLockByHash(const uint256& hash, CDirectSendLock& ret);
    bool GetDirectSendLockHashByTxid(const uint256& txid, uint256& ret);

    size_t GetDirectSendLockCount();

    void WorkThreadMain();
};

extern CDirectSendManager* quorumDirectSendManager;

bool IsDirectSendEnabled();

} // namespace llmq

#endif//TRIVECHAIN_QUORUMS_DIRECTSEND_H
