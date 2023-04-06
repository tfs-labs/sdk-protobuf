#include "ca_transaction.h"

#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "proto/ca_protomsg.pb.h"
#include "utils/MagicSingleton.h"
//#include "utils/base64.h"
#include "utils/hexcode.h"
#include "utils/string_util.h"
#include "utils/time_util.h"
#include "utils/util2.h"
#include <algorithm>
#include <iostream>
#include <mutex>
#include <set>
#include <shared_mutex>
#include "../net/connect.h"
#include "../net/ip_port.h"
#include "../net/net_api.h"
#include "ca.h"
#include "ca/ca_algorithm.h"
#include "ca/ca_txhelper.h"
#include "ca_global.h"
#include "common/global.h"
#include "include/ScopeGuard.h"
#include "utils/Cycliclist.hpp"
#include "utils/EDManager.h"
#include "utils/VRF.hpp"
//#include "utils/base64_2.h"
#include "utils/console.h"
#include "utils/time_util.h"
#include "utils/tmplog.h"

using namespace std;

void setVrf(Vrf &dest, const std::string &proof, const std::string &pub,
            const std::string &data) {
  CSign *sign = dest.mutable_vrfsign();
  sign->set_pub(pub);
  sign->set_sign(proof);
  dest.set_data(data);
}

int getVrfdata(const Vrf &vrf, std::string &hash, int &range,
               double &percentage) {
  try {
    auto json = nlohmann::json::parse(vrf.data());
    hash = json["hash"];
    range = json["range"];
    percentage = json["percentage"];
  } catch (...) {

    return -1;
  }

  return 0;
}

int getVrfdata(const Vrf &vrf, std::string &hash, int &range) {
  try {
    auto json = nlohmann::json::parse(vrf.data());
    hash = json["hash"];
    range = json["range"];
  } catch (...) {

    return -1;
  }

  return 0;
}

TransactionType GetTransactionType(const CTransaction &tx) {
  if (tx.type() == global::ca::kGenesisSign) {
    return kTransactionType_Genesis;
  }
  if (tx.type() == global::ca::kTxSign) {
    return kTransactionType_Tx;
  }
  if (tx.type() == global::ca::kGasSign) {
    return kTransactionType_Gas;
  } else if (tx.type() == global::ca::kBurnSign) {
    return kTransactionType_Burn;
  }

  return kTransactionType_Unknown;
}

bool ContainSelfVerifySign(const CTransaction &tx) {
  bool isContainSelfVerifySign = false;

  if (tx.verifysign_size() == 0) {
    return isContainSelfVerifySign;
  }

  std::string defaultBase58Addr =
      MagicSingleton<EDManager>::GetInstance()->GetDefaultBase58Addr();
  int index = defaultBase58Addr != tx.identity() ? 0 : 1;

  for (; index != tx.verifysign_size(); index++) {
    const CSign &sign = tx.verifysign(index);
    if (defaultBase58Addr == GetBase58Addr(sign.pub())) {
      isContainSelfVerifySign = true;
      break;
    }
  }
  return isContainSelfVerifySign;
}

int GetBlockPackager(std::string &packager, const std::string &hash_utxo,
                     Vrf &info, const std::shared_ptr<GetSDKAck> &SDKAckMsg,
                     int tx_id) {

  std::vector<std::string> hashes;

  CBlock block;
  std::vector<CBlock> blocks;
  for (size_t i = 0; i < (size_t)SDKAckMsg->blocks_size(); ++i) {

    block.ParseFromString(SDKAckMsg->blocks(i));
    blocks.emplace_back(block);
  }

  std::sort(blocks.begin(), blocks.end(), [](const CBlock &x, const CBlock &y) {
    return x.time() < y.time();
  });

  if (blocks.size() == 0) {
    return -1037;
  }
  CBlock RandomBlock = blocks[0];
  std::string output, proof;
  ED defaultAccount;
  EVP_PKEY_free(defaultAccount.pkey);
  if (MagicSingleton<EDManager>::GetInstance()->GetDefaultAccount(
          defaultAccount) != 0) {
    return -3;
  }
  int ret = MagicSingleton<VRF>::GetInstance()->CreateVRF(
      defaultAccount.pkey, hash_utxo, output, proof);
  if (ret != 0) {
    std::cout << "error create:" << ret << std::endl;
    return -4;
  }

  std::vector<std::string> BlockSignInfo;
  for (int j = 2; j < 7; ++j) {
    BlockSignInfo.push_back(GetBase58Addr(RandomBlock.sign(j).pub()));
  }

  if (BlockSignInfo.size() < global::ca::KPackNodeThreshold) {
    return -5;
  }

  uint32_t rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(output, global::ca::KPackNodeThreshold);
  packager = BlockSignInfo[rand_num];

  for (int k = 0; k < SDKAckMsg->nodeinfo_size(); ++k) {
    SDKNodeInfo node = SDKAckMsg->nodeinfo(k);
    if (node.base58addr() == packager) {
      std::string ip = IpPort::ipsz(SDKAckMsg->nodeinfo(k).public_ip());
      std::cout << "11111public ip = "
                << IpPort::ipsz(SDKAckMsg->nodeinfo(k).public_ip())
                << std::endl;
      std::cout << "111111111public port = "
                << SDKAckMsg->nodeinfo(k).public_port() << std::endl;
      std::cout << "111111111public port = "
                << SDKAckMsg->nodeinfo(k).listen_port() << std::endl;

      MagicSingleton<Recver>::GetInstance()->connect(
          tx_id, ip, SDKAckMsg->nodeinfo(k).listen_port());

      sleep(1);
    }
  }
  std::string defaultbase58 =
      MagicSingleton<EDManager>::GetInstance()->GetDefaultBase58Addr();
  if (packager ==
      MagicSingleton<EDManager>::GetInstance()->GetDefaultBase58Addr()) {

    std::cout << "Packager cannot be the transaction initiator " << std::endl;
    return -6;
  }

  std::cout << "block rand_num: " << rand_num << std::endl;
  std::cout << "packager: " << packager << std::endl;
  nlohmann::json data_string;
  data_string["hash"] = RandomBlock.hash();
  data_string["range"] = 0;
  data_string["percentage"] = 0;
  setVrf(info, proof, defaultAccount.pubStr, data_string.dump());
  std::cout << "**********VRF Generated the number end**********************"
            << std::endl;

  return 0;
}

int IsQualifiedToUnstake(const std::string &fromAddr,
                         const std::string &utxo_hash, uint64_t &staked_amount,
                         const std::shared_ptr<GetSDKAck> &SDKAckMsg) {

  std::vector<std::string> addresses;

  for (int i = 0; i < SDKAckMsg->pledgeaddr_size(); ++i) {
    addresses.emplace_back(SDKAckMsg->pledgeaddr(i));
  }

  if (std::find(addresses.begin(), addresses.end(), fromAddr) ==
      addresses.end()) {

    return -2;
  }

  std::vector<std::string> utxos;
  for (int j = 0; j < SDKAckMsg->pledgeutxo_size(); ++j) {
    utxos.emplace_back(SDKAckMsg->pledgeutxo(j));
  }

  if (std::find(utxos.begin(), utxos.end(), utxo_hash) == utxos.end()) {

    return -4;
  }

  CTransaction StakeTx;
  for (const auto &item : SDKAckMsg->pledgetx()) {
    if (fromAddr == item.address()) {
      StakeTx.ParseFromString(item.tx());
    }
  }

  if (IsMoreThan30DaysForUnstake(utxo_hash, StakeTx) != true) {

    return -5;
  }

  for (int i = 0; i < StakeTx.utxo().vout_size(); i++) {
    if (StakeTx.utxo().vout(i).addr() == global::ca::kVirtualStakeAddr) {
      staked_amount = StakeTx.utxo().vout(i).value();
      break;
    }
  }

  if (staked_amount == 0) {

    return -8;
  }

  return 0;
}

int CheckInvestQualification(const std::string &fromAddr,
                             const std::string &toAddr, uint64_t invest_amount,
                             const std::shared_ptr<GetSDKAck> &SDKAckMsg) {

  std::vector<string> nodes;

  for (int i = 0; i < SDKAckMsg->bonusaddr_size(); ++i) {
    nodes.emplace_back(SDKAckMsg->bonusaddr(i));
  }
  if (!nodes.empty()) {

    return -1;
  }

  if (invest_amount <  global::ca::kMinInvestAmt) {

    return -2;
  }

  int64_t stake_time = ca_algorithm::GetPledgeTimeByAddr(
      toAddr, global::ca::StakeType::kStakeType_Node, SDKAckMsg);
  if (stake_time <= 0) {

    return -3;
  }

  std::vector<string> addresses;
  for (int j = 0; j < SDKAckMsg->investedaddr_size(); ++j) {
    addresses.emplace_back(SDKAckMsg->investedaddr(j));
  }

  if (addresses.size() + 1 > 999) {

    return -5;
  }

  uint64_t sum_invest_amount = 0;
  for (auto &address : addresses) {
    CTransaction tx;

    for (const auto &item : SDKAckMsg->bonustx()) {
      if (item.address() == address) {
        tx.ParseFromString(item.tx());
        for (auto &vout : tx.utxo().vout()) {
          if (vout.addr() == global::ca::kVirtualInvestAddr) {
            sum_invest_amount += vout.value();
            break;
          }
        }
      }
    }
  }

  if (sum_invest_amount + invest_amount > 65000ull * global::ca::kDecimalNum) {

    return -9;
  }
  return 0;
}

int IsQualifiedToDisinvest(const std::string &fromAddr,
                           const std::string &toAddr,
                           const std::string &utxo_hash,
                           uint64_t &invested_amount,
                           const std::shared_ptr<GetSDKAck> &SDKAckMsg) {

  std::vector<string> nodes;

  for (int i = 0; i < SDKAckMsg->bonusaddr_size(); ++i) {
    nodes.emplace_back(SDKAckMsg->bonusaddr(i));
  }

  if (std::find(nodes.begin(), nodes.end(), toAddr) == nodes.end()) {
    infoL("The account has not invested assets to node!");
    return -2;
  }

  std::vector<std::string> utxos;
  for (int j = 0; j < SDKAckMsg->bonusaddrinvestutxos_size(); ++j) {
    utxos.emplace_back(SDKAckMsg->bonusaddrinvestutxos(j));
  }

  if (std::find(utxos.begin(), utxos.end(), utxo_hash) == utxos.end()) {
    infoL("The utxo to divest is not in the utxos that have been invested!");
    return -4;
  }

  CTransaction InvestedTx;
  for (int k = 0; k < SDKAckMsg->bonustx_size(); ++k) {
    if (fromAddr == SDKAckMsg->bonustx(k).address()) {
      InvestedTx.ParseFromString(SDKAckMsg->bonustx(k).tx());
    }
  }

  if (IsMoreThan1DayForDivest(utxo_hash, InvestedTx) != true) {
    infoL("The invested utxo is not more than 1 day!");
    return -5;
  }

  nlohmann::json data_json = nlohmann::json::parse(InvestedTx.data());
  nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
  std::string invested_addr = tx_info["BonusAddr"].get<std::string>();
  if (toAddr != invested_addr) {
    infoL("The node to be divested is not invested!");
    return -8;
  }

  for (int i = 0; i < InvestedTx.utxo().vout_size(); i++) {
    if (InvestedTx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr) {
      invested_amount = InvestedTx.utxo().vout(i).value();
      break;
    }
  }

  if (invested_amount == 0) {
    infoL("The invested value is zero!");
    return -9;
  }
  return 0;
}

bool IsMoreThan30DaysForUnstake(const std::string &utxo,
                                const CTransaction &StakeTx) {

  uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
  uint64_t DAYS30 = (uint64_t)1000000 * 1;
  if (global::kBuildType == global::BuildType::kBuildType_Dev) {
    DAYS30 = (uint64_t)1000000 * 60;
  }

  return (nowTime - StakeTx.time()) >= DAYS30;
}

bool IsMoreThan1DayForDivest(const std::string &utxo,
                             const CTransaction &InvestedTx) {

  uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
  uint64_t DAY = (uint64_t)1000000 * 1;
  if (global::kBuildType == global::BuildType::kBuildType_Dev) {
    DAY = (uint64_t)1000000 * 60;
  }
  return (nowTime - InvestedTx.time()) >= DAY;
}

int VerifyBonusAddr(const std::string &BonusAddr,
                    const std::shared_ptr<GetSDKAck> &SDKAckMsg) {
  uint64_t invest_amount = 0;
  for (size_t i = 0; i < (size_t)SDKAckMsg->bonusamount_size(); ++i) {
    const SDKBonusamout item = SDKAckMsg->bonusamount(i);

    if (BonusAddr == item.address()) {
      invest_amount += item.invest_amount();
    }
  }

  return invest_amount >= global::ca::kMinInvestAmt ? 0 : -99;
}

int GetInvestmentAmountAndDuration(
    const std::string &bonusAddr, const uint64_t &cur_time,
    const uint64_t &zero_time,
    std::map<std::string, std::pair<uint64_t, uint64_t>> &mpInvestAddr2Amount,
    const std::shared_ptr<GetSDKAck> &SDKAckMsg) {

  std::string strTx;
  CTransaction tx;
  std::vector<string> addresses;

  time_t t = cur_time;
  t = t / 1000000;
  struct tm *tm = gmtime(&t);
  tm->tm_hour = 23;
  tm->tm_min = 59;
  tm->tm_sec = 59;
  uint64_t end_time = mktime(tm);
  end_time *= 1000000;

  uint64_t invest_amount = 0;
  uint64_t invest_amountDay = 0;

  for (int k = 0; k < SDKAckMsg->claiminvestedaddr_size(); ++k) {
    addresses.emplace_back(SDKAckMsg->claiminvestedaddr(k));
  }

  for (auto &address : addresses) {
    for (int k = 0; k < SDKAckMsg->claimbonustx_size(); ++k) {
      if (address == SDKAckMsg->claimbonustx(k).address()) {
        tx.ParseFromString(SDKAckMsg->claimbonustx(k).tx());
        if (tx.time() >= zero_time && tx.time() <= end_time) {
          for (int i = 0; i < tx.utxo().vout_size(); i++) {
            if (tx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr) {
              invest_amountDay += tx.utxo().vout(i).value();
              invest_amount += tx.utxo().vout(i).value();
              break;
            }
          }
        } else {
          for (int i = 0; i < tx.utxo().vout_size(); i++) {
            if (tx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr) {
              invest_amount += tx.utxo().vout(i).value();
              break;
            }
          }
          break;
        }
      }
    }

    invest_amount = (invest_amount - invest_amountDay);
    if (invest_amount == 0) {
      continue;
    }
    mpInvestAddr2Amount[address].first = invest_amount;
  }
  if (mpInvestAddr2Amount.empty()) {
    return -9;
  }
  return 0;
}

int GetTotalCirculationYesterday(const uint64_t &cur_time,
                                 uint64_t &TotalCirculation,
                                 const std::shared_ptr<GetSDKAck> &SDKAckMsg) {

  std::vector<std::string> utxos;
  std::string strTx;
  CTransaction tx;
  {
    std::lock_guard<std::mutex> lock(global::ca::kBonusMutex);
    TotalCirculation = SDKAckMsg->m2();

    uint64_t Period =
        MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
  }
  uint64_t Claim_Vout_amount = 0;
  uint64_t TotalClaimDay = 0;

  CTransaction Claimtx;
  for (int i = 0; i < SDKAckMsg->claimtx_size(); ++i) {

    {
      tx.ParseFromString(SDKAckMsg->claimtx(i).tx());
      uint64_t claim_amount = 0;
      if ((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx) {
        nlohmann::json data_json = nlohmann::json::parse(tx.data());
        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
        tx_info["BonusAmount"].get_to(claim_amount);
        TotalClaimDay += claim_amount;
      }
    }
  }

  if (global::kBuildType == global::BuildType::kBuildType_Dev) {
  }
  TotalCirculation -= TotalClaimDay;
  return 0;
}

int GetTotalInvestmentYesterday(const uint64_t &cur_time, uint64_t &Totalinvest,
                                const std::shared_ptr<GetSDKAck> &SDKAckMsg) {

  std::vector<std::string> utxos;
  std::string strTx;
  CTransaction tx;
  {
    std::lock_guard<std::mutex> lock(global::ca::kInvestMutex);
    Totalinvest = SDKAckMsg->totalinvest();

    uint64_t Period =
        MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
  }
  uint64_t Invest_Vout_amount = 0;
  uint64_t TotalInvestmentDay = 0;

  for (int i = 0; i < SDKAckMsg->claimbonustx_size(); ++i) {
    tx.ParseFromString(SDKAckMsg->claimbonustx(i).tx());
    for (auto &vout : tx.utxo().vout()) {
      if (vout.addr() == global::ca::kVirtualInvestAddr) {
        Invest_Vout_amount += vout.value();
        break;
      }
    }
    TotalInvestmentDay += Invest_Vout_amount;
  }

  if (global::kBuildType == global::BuildType::kBuildType_Dev) {
  }
  Totalinvest -= TotalInvestmentDay;
  return 0;
}

std::map<int32_t, std::string> GetMultiSignTxReqCode() {
  std::map<int32_t, std::string> errInfo = {
      std::make_pair(0, ""),  std::make_pair(-1, ""), std::make_pair(-2, ""),
      std::make_pair(-3, ""), std::make_pair(-4, ""), std::make_pair(-5, ""),
      std::make_pair(-6, ""),
  };

  return errInfo;
}

bool IsMultiSign(const CTransaction &tx) {
  global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();

  return tx.utxo().owner_size() == 1 &&
         (CheckBase58Addr(tx.utxo().owner(0),
                          Base58Ver::kBase58Ver_MultiSign) &&
          (tx.utxo().vin_size() == 1) &&
          global::ca::TxType::kTxTypeTx == tx_type);
}

int CalculateGas(const CTransaction &tx, uint64_t &gas) {

  TransactionType tx_type = GetTransactionType(tx);
  if (tx_type == kTransactionType_Genesis || tx_type == kTransactionType_Tx) {

    uint64_t utxo_size = 0;
    const CTxUtxo &utxo = tx.utxo();

    utxo_size += utxo.owner_size() * 34;

    for (auto &vin : utxo.vin()) {
      utxo_size += vin.prevout().size() * 64;
    }
    utxo_size += utxo.vout_size() * 34;

    gas += utxo_size;
    gas += tx.type().size() + tx.data().size() + tx.info().size();
    gas += tx.reserve0().size() + tx.reserve1().size();
  }

  gas *= 100;

  if (gas == 0) {

    return -1;
  }

  return 0;
}

int GenerateGas(const CTransaction &tx,
                const std::map<std::string, int64_t> &toAddr, uint64_t &gas) {

  uint64_t UtxoSize = 0;
  TransactionType tx_type = GetTransactionType(tx);
  if (tx_type == kTransactionType_Genesis || tx_type == kTransactionType_Tx) {

    uint64_t utxo_size = 0;
    const CTxUtxo &utxo = tx.utxo();

    utxo_size += utxo.owner_size() * 34;

    for (auto &vin : utxo.vin()) {
      utxo_size += vin.prevout().size() * 64;
      UtxoSize += vin.prevout().size();
    }

    utxo_size += toAddr.size() * 34;

    gas += utxo_size;
    gas += tx.type().size() + tx.data().size() + tx.info().size();
    gas += tx.reserve0().size() + tx.reserve1().size();
  }

  gas *= UtxoSize * 100;

  if (gas == 0) {

    return -1;
  }

  return 0;
}

int SearchStake(const std::string &address, uint64_t &stakeamount,
                global::ca::StakeType stakeType,
                const std::shared_ptr<GetSDKAck> &SDKAckMsg) {

  std::vector<string> rawtx;
  for (int i = 0; i < SDKAckMsg->pledgetx_size(); ++i) {
    rawtx.emplace_back(SDKAckMsg->pledgetx(i).tx());
  }

  uint64_t total = 0;
  for (auto &item : rawtx) {

    CTransaction utxoTx;
    utxoTx.ParseFromString(item);

    nlohmann::json data = nlohmann::json::parse(utxoTx.data());
    nlohmann::json txInfo = data["TxInfo"].get<nlohmann::json>();
    std::string txStakeTypeNet = txInfo["StakeType"].get<std::string>();

    if (stakeType == global::ca::StakeType::kStakeType_Node &&
        txStakeTypeNet != global::ca::kStakeTypeNet) {
      continue;
    }

    for (int i = 0; i < utxoTx.utxo().vout_size(); i++) {
      CTxOutput txout = utxoTx.utxo().vout(i);
      if (txout.addr() == global::ca::kVirtualStakeAddr) {
        total += txout.value();
      }
    }
  }
  stakeamount = total;
  return 0;
}