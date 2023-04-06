#ifndef __CA_GLOBAL_H__
#define __CA_GLOBAL_H__
#include <unordered_set>

#include "common/global.h"
#include "proto/ca_protomsg.pb.h"


namespace global {

namespace ca {

extern const std::string kInitAccountBase58Addr ;
extern const std::string kGenesisBlockRaw ;
extern const uint64_t kGenesisTime;
extern const std::string kConfigJson ;

extern const int kConsensus ;



extern std::mutex kBonusMutex;
extern std::mutex kInvestMutex;
extern std::mutex kBlockBroadcastMutex;

extern const uint64_t kDecimalNum;
extern const double kFixDoubleMinPrecision ;
extern const uint64_t kTotalAwardAmount;
extern const uint64_t kM2 ;
extern const uint64_t kMinStakeAmt ;
extern const uint64_t kMinInvestAmt;
extern const std::string kGenesisSign ;
extern const std::string kTxSign ;
extern const std::string kGasSign;
extern const std::string kBurnSign ;
extern const std::string kVirtualStakeAddr ;
extern const std::string kVirtualInvestAddr;
extern const std::string kVirtualBurnGasAddr ;
extern const uint64_t kUpperBlockHeight ;
extern const uint64_t kLowerBlockHeight ;
extern const std::string kStakeTypeNet ;
extern const std::string kInvestTypeNormal;
extern const uint64_t kMinUnstakeHeight ;
extern const uint64_t kMaxBlockSize ;
extern const std::string kVirtualDeployContractAddr;

extern const int KSign_node_threshold ;
extern const int kNeed_node_threshold ;

extern const uint64_t kMaxSendSize ;
extern const int TxTimeoutMin ;
extern const uint64_t kVerifyRange ;

extern const int KPackNodeThreshold;

enum class StakeType { kStakeType_Unknown = 0, kStakeType_Node = 1 };

enum class TxType {
  kTxTypeGenesis = -1,
  kTxTypeUnknown,
  kTxTypeTx,
  kTxTypeStake,
  kTxTypeUnstake,
  kTxTypeInvest,
  kTxTypeDisinvest,
  kTxTypeDeclaration,
  kTxTypeDeployContract,
  kTxTypeCallContract,
  kTxTypeBonus = 99
};

enum class SaveType { SyncNormal, SyncFromZero, Broadcast, Unknow };

enum class BlockObtainMean { Normal, ByPreHash, ByUtxo };
extern const uint64_t sum_hash_range ;

extern int TxNumber ;
} // namespace ca
} // namespace global

#endif