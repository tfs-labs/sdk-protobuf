#ifndef __CA_TRANSACTION__
#define __CA_TRANSACTION__

#include "ca_global.h"
#include "ca_txhelper.h"
#include "proto/block.pb.h"
#include "proto/ca_protomsg.pb.h"
#include "proto/interface.pb.h"
#include "proto/transaction.pb.h"
#include "utils/base58.h"

#include <map>
#include <memory>
#include <net/if.h>
#include <regex>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "ca/ca_txhelper.h"

typedef enum emTransactionType {
  kTransactionType_Unknown = -1,
  kTransactionType_Genesis = 0,
  kTransactionType_Tx,
  kTransactionType_Gas,
  kTransactionType_Burn,
} TransactionType;

TransactionType GetTransactionType(const CTransaction &tx);

int AddBlockSign(CBlock &block);

int VerifyBlockSign(const CBlock &block);

int GetBlockPackager(std::string &packager, const std::string &hash_utxo,
                     Vrf &info, const std::shared_ptr<GetSDKAck> &SDKAckMsg,
                     int tx_id);

int SearchStake(const std::string &address, uint64_t &stakeamount,
                global::ca::StakeType stakeType,
                const std::shared_ptr<GetSDKAck> &SDKAckMsg);

int IsQualifiedToUnstake(const std::string &fromAddr,
                         const std::string &utxo_hash, uint64_t &staked_amount,
                         const std::shared_ptr<GetSDKAck> &SDKAckMsg);

int CheckInvestQualification(const std::string &fromAddr,
                             const std::string &toAddr, uint64_t invest_amount);

int CheckInvestQualification(const std::string &fromAddr,
                             const std::string &toAddr, uint64_t invest_amount,
                             const std::shared_ptr<GetSDKAck> &SDKAckMsg);

int IsQualifiedToDisinvest(const std::string &fromAddr,
                           const std::string &toAddr,
                           const std::string &utxo_hash,
                           uint64_t &invested_amount);

int IsQualifiedToDisinvest(const std::string &fromAddr,
                           const std::string &toAddr,
                           const std::string &utxo_hash,
                           uint64_t &invested_amount,
                           const std::shared_ptr<GetSDKAck> &SDKAckMsg);

bool IsMoreThan30DaysForUnstake(const std::string &utxo,
                                const CTransaction &StakeTx);

bool IsMoreThan1DayForDivest(const std::string &utxo,
                             const CTransaction &InvestedTx);
int VerifyBonusAddr(const std::string &BonusAddr,
                    const std::shared_ptr<GetSDKAck> &SDKAckMsg);
int GetInvestmentAmountAndDuration(
    const std::string &bonusAddr, const uint64_t &cur_time,
    const uint64_t &zero_time,
    std::map<std::string, std::pair<uint64_t, uint64_t>> &mpInvestAddr2Amount,
    const std::shared_ptr<GetSDKAck> &SDKAckMsg);
int GetTotalCirculationYesterday(const uint64_t &cur_time,
                                 uint64_t &TotalCirculation,
                                 const std::shared_ptr<GetSDKAck> &SDKAckMsg);
int GetTotalInvestmentYesterday(const uint64_t &cur_time, uint64_t &Totalinvest,
                                const std::shared_ptr<GetSDKAck> &SDKAckMsg);

int CalculateGas(const CTransaction &tx, uint64_t &gas);
int GenerateGas(const CTransaction &tx,
                const std::map<std::string, int64_t> &toAddr, uint64_t &gas);
int PreCalcGas(CTransaction &tx);

void setVrf(Vrf &dest, const std::string &proof, const std::string &pub,
            const std::string &data);

int getVrfdata(const Vrf &vrf, std::string &hash, int &range,
               double &percentage);
int getVrfdata(const Vrf &vrf, std::string &hash, int &range);

#endif
