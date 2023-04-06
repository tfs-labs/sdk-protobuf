#ifndef TFS_CA_ALGORITHM_H_
#define TFS_CA_ALGORITHM_H_

#include "ca_global.h"
#include "proto/block.pb.h"
#include "proto/sdk.pb.h"

namespace ca_algorithm {

int64_t GetPledgeTimeByAddr(const std::string &addr,
                            global::ca::StakeType stakeType,
                            const std::shared_ptr<GetSDKAck> &SDKAckMsg);

std::string CalcBlockHash(CBlock block);

std::string CalcBlockMerkle(CBlock cblock);

int GetTxSignAddr(const CTransaction &tx,
                  std::vector<std::string> &tx_sign_addr);
int GetSignTxSignAddr(const CTransaction &tx,
                      std::vector<std::string> &sign_addrs);
int GetBurnTxAddr(const CTransaction &tx, std::vector<std::string> &sign_addrs);
int DoubleSpendCheck(const CTransaction &tx,
                     bool turn_on_missing_block_protocol,
                     std::string *missing_utxo = nullptr);

int VerifyCacheTranscation(const CTransaction &tx);

int VerifyTransactionTx(const CTransaction &tx, uint64_t tx_height,
                        bool turn_on_missing_block_protocol = false,
                        bool verify_abnormal = true);

int MemVerifyBlock(const CBlock &block);

int VerifyBlock(const CBlock &block,
                bool turn_on_missing_block_protocol = false,
                bool verify_abnormal = true);

int CalcBonusValue(uint64_t &cur_time, const std::string &bonusAddr,
                   std::map<std::string, uint64_t> &vlaues,
                   const std::shared_ptr<GetSDKAck> &SDKAckMsg);
int CalcBonusValue();

int GetInflationRate(const uint64_t &cur_time, const uint64_t &&StakeRate,
                     double &InflationRate);

uint64_t GetSumHashCeilingHeight(uint64_t height);
uint64_t GetSumHashFloorHeight(uint64_t height);

}; // namespace ca_algorithm

#endif
