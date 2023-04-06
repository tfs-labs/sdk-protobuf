#ifndef _TXHELPER_H_
#define _TXHELPER_H_

#include <algorithm>
#include <boost/functional/hash.hpp>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <vector>


#include "../proto/ca_protomsg.pb.h"
#include "../proto/sdk.pb.h"
#include "../proto/transaction.pb.h"
#include "ca_algorithm.h"

class VmInterface;
class TxHelper {
public:
  struct Utxo {
    std::uint64_t value;
    std::string addr;
    std::string hash;
    std::uint32_t n;
  };

  class UtxoCompare {
  public:
    bool operator()(const Utxo &utxo1, const Utxo &utxo2) const {
      return utxo1.value < utxo2.value;
    }
  };

  typedef enum emPledgeType {
    kPledgeType_Unknown = -1,
    kPledgeType_Node = 0,
  } PledgeType;

  typedef enum emInvestType {
    kInvestType_Unknown = -1,
    kInvestType_NetLicence = 0,
  } InvestType;

  enum vrfAgentType {
    vrfAgentType_defalut = 0,
    vrfAgentType_vrf,
    vrfAgentType_local,
    vrfAgentType_unknow,
  };

  static const uint32_t kMaxVinSize;

  TxHelper() = default;
  ~TxHelper() = default;

  static int Check(const std::vector<std::string> &fromAddr, uint64_t height);

  static int
  FindUtxo(const std::vector<std::string> &fromAddr,
           const uint64_t need_utxo_amount, uint64_t &total,
           std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> &setOutUtxos,
           const std::shared_ptr<GetSDKAck> &SDKAckMsg);

  static int CreateTxTransaction(const std::vector<std::string> &fromAddr,
                                 const std::map<std::string, int64_t> &toAddr,
                                 uint64_t height, CTransaction &outTx,
                                 TxHelper::vrfAgentType &type, Vrf &info_,
                                 const std::shared_ptr<GetSDKAck> &SDKAckMsg,
                                 int tx_id);

  static int CreateStakeTransaction(
      const std::string &vecfromAddr, uint64_t stake_amount, uint64_t height,
      TxHelper::PledgeType pledgeType, CTransaction &outTx,
      std::vector<TxHelper::Utxo> &outVin, TxHelper::vrfAgentType &type,
      Vrf &info_, const std::shared_ptr<GetSDKAck> &SDKAckMsg, int tx_id);

  static int CreatUnstakeTransaction(
      const std::string &vecfromAddr, const std::string &utxo_hash,
      uint64_t height, CTransaction &outTx, std::vector<TxHelper::Utxo> &outVin,
      TxHelper::vrfAgentType &type, Vrf &info_,
      const std::shared_ptr<GetSDKAck> &SDKAckMsg, int tx_id);

  static int CreateInvestTransaction(
      const std::string &vecfromAddr, const std::string &toAddr,
      uint64_t invest_amount, uint64_t height, TxHelper::InvestType investType,
      CTransaction &outTx, std::vector<TxHelper::Utxo> &outVin,
      TxHelper::vrfAgentType &type, Vrf &info_,
      const std::shared_ptr<GetSDKAck> &SDKAckMsg, int tx_id);

  static int CreateDisinvestTransaction(
      const std::string &vecfromAddr, const std::string &toAddr,
      const std::string &utxo_hash, uint64_t height, CTransaction &outTx,
      std::vector<TxHelper::Utxo> &outVin, TxHelper::vrfAgentType &type,
      Vrf &info_, const std::shared_ptr<GetSDKAck> &SDKAckMsg, int tx_id);

  static int CreateDeclareTransaction(
      const std::string &fromaddr, const std::string &toAddr, uint64_t amount,
      const std::string &multiSignPub,
      const std::vector<std::string> &signAddrList, uint64_t signThreshold,
      uint64_t height, CTransaction &outTx, TxHelper::vrfAgentType &type,
      Vrf &info_, int tx_id);

  static int CreateBonusTransaction(const std::string &vecfromAddr,
                                    uint64_t height, CTransaction &outTx,
                                    std::vector<TxHelper::Utxo> &outVin,
                                    TxHelper::vrfAgentType &type, Vrf &info_,
                                    const std::shared_ptr<GetSDKAck> &SDKAckMsg,
                                    uint64_t cur_time, int tx_id);

  static int SignTransaction(const std::vector<TxHelper::Utxo> &outVin,
                             CTransaction &tx, std::string &serTx,
                             std::string &encodeStrHash);

  static int AddMutilSign(const std::string &addr, CTransaction &tx);

  static int AddVerifySign(const std::string &addr, CTransaction &tx);

  static int Sign(const std::string &addr, const std::string &message,
                  std::string &signature, std::string &pub);

  static bool IsNeedAgent(const std::vector<std::string> &fromAddr);
  static bool IsNeedAgent(const CTransaction &tx);

  static bool checkTxTimeOut(const uint64_t &txTime, const uint64_t &timeout,
                             const uint64_t &pre_height,
                             const std::shared_ptr<GetSDKAck> &SDKAckMsg);

  static TxHelper::vrfAgentType
  GetVrfAgentType(const CTransaction &tx, uint64_t &pre_height,
                  const std::shared_ptr<GetSDKAck> &SDKAckMsg);

  static void GetTxStartIdentity(const std::vector<std::string> &fromaddr,
                                 const uint64_t &height,
                                 const uint64_t &current_time,
                                 TxHelper::vrfAgentType &type,
                                 const std::shared_ptr<GetSDKAck> &SDKAckMsg);
};

#endif
