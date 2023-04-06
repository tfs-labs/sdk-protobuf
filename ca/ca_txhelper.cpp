


#include "ca_txhelper.h"
#include <cmath>

#include "../net/connect.h"
#include "../net/ip_port.h"
#include "../utils/EDManager.h"
#include "../utils/tmplog.h"
#include "ca_global.h"
#include "ca_transaction.h"
#include "net/net_api.h"
#include "utils/MagicSingleton.h"
#include "utils/console.h"
#include "utils/json.hpp"
#include "utils/string_util.h"
#include "utils/time_util.h"

using namespace std;

const uint32_t TxHelper::kMaxVinSize = 100;

int TxHelper::Check(const std::vector<std::string> &fromAddr, uint64_t height) {

  if (fromAddr.empty()) {

    return -1;
  }

  std::vector<std::string> tempfromAddr = fromAddr;
  std::sort(tempfromAddr.begin(), tempfromAddr.end());
  auto iter = std::unique(tempfromAddr.begin(), tempfromAddr.end());
  tempfromAddr.erase(iter, tempfromAddr.end());
  if (tempfromAddr.size() != fromAddr.size()) {

    return -2;
  }

  if (height == 0) {

    return -6;
  }
  return 0;
}

int TxHelper::FindUtxo(
    const std::vector<std::string> &fromAddr, const uint64_t need_utxo_amount,
    uint64_t &total,
    std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> &setOutUtxos,
    const std::shared_ptr<GetSDKAck> &SDKAckMsg) {

  std::vector<TxHelper::Utxo> Utxos;
  for (const auto &addr : fromAddr) {
    for (size_t i = 0; i < (size_t)SDKAckMsg->utxos_size(); ++i) {
      const SDKUtxo item = SDKAckMsg->utxos(i);
      if (addr == item.address()) {
        TxHelper::Utxo utxo;
        utxo.hash = item.hash();
        utxo.addr = item.address();
        utxo.value = item.value();
        utxo.n = 0;
        Utxos.push_back(utxo);
      }
    }
  }

  std::sort(Utxos.begin(), Utxos.end(),
            [](const TxHelper::Utxo &u1, const TxHelper::Utxo &u2) {
              return u1.value > u2.value;
            });

  total = 0;
  if (setOutUtxos.size() < need_utxo_amount) {

    auto it = Utxos.begin();
    while (it != Utxos.end()) {
      if (setOutUtxos.size() == need_utxo_amount) {
        break;
      }
      total += it->value;

      setOutUtxos.insert(*it);
      ++it;
    }
  }
  return 0;
}

int TxHelper::CreateTxTransaction(const std::vector<std::string> &fromAddr,
                                  const std::map<std::string, int64_t> &toAddr,
                                  uint64_t height, CTransaction &outTx,
                                  TxHelper::vrfAgentType &type, Vrf &info,
                                  const std::shared_ptr<GetSDKAck> &SDKAckMsg,
                                  int tx_id) {

  int ret = Check(fromAddr, height);
  if (ret != 0) {

    ret -= 100;
    return ret;
  }

  if (toAddr.empty()) {

    return -1;
  }

  for (auto &addr : toAddr) {
    if (!CheckBase58Addr(addr.first)) {
      return -2;
    }

    for (auto &from : fromAddr) {
      if (addr.first == from) {

        return -3;
      }
    }

    if (addr.second <= 0) {

      return -4;
    }
  }

  uint64_t amount = 0;
  for (auto &i : toAddr) {
    amount += i.second;
  }
  uint64_t expend = amount;

  uint64_t total = 0;
  std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
  ret =
      FindUtxo(fromAddr, TxHelper::kMaxVinSize, total, setOutUtxos, SDKAckMsg);
  if (ret != 0) {

    ret -= 200;
    return ret;
  }
  if (setOutUtxos.empty()) {

    return -5;
  }

  outTx.Clear();

  CTxUtxo *txUtxo = outTx.mutable_utxo();

  std::set<std::string> setTxowners;
  for (auto &utxo : setOutUtxos) {
    setTxowners.insert(utxo.addr);
  }

  if (setTxowners.empty()) {

    return -6;
  }

  uint32_t n = 0;
  for (auto &owner : setTxowners) {
    txUtxo->add_owner(owner);
    CTxInput *vin = txUtxo->add_vin();
    for (auto &utxo : setOutUtxos) {
      if (owner == utxo.addr) {
        CTxPrevOutput *prevOutput = vin->add_prevout();
        prevOutput->set_hash(utxo.hash);
        prevOutput->set_n(utxo.n);
      }
    }
    vin->set_sequence(n++);

    std::string serVinHash = getsha256hash(vin->SerializeAsString());
    std::string signature;
    std::string pub;
    if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0) {

      return -7;
    }

    CSign *vinSign = vin->mutable_vinsign();
    vinSign->set_sign(signature);
    vinSign->set_pub(pub);
  }

  outTx.set_data("");
  outTx.set_type(global::ca::kTxSign);

  uint64_t gas = 0;
  std::map<std::string, int64_t> targetAddrs = toAddr;
  targetAddrs.insert(make_pair(*fromAddr.rbegin(), total - expend));
  targetAddrs.insert(make_pair(global::ca::kVirtualBurnGasAddr, gas));
  if (GenerateGas(outTx, targetAddrs, gas) != 0) {

    return -8;
  }

  auto current_time =
      MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

  GetTxStartIdentity(fromAddr, height, current_time, type, SDKAckMsg);

  expend += gas;

  if (total < expend) {
    MagicSingleton<Recver>::GetInstance()->setData(
        tx_id, "Insufficient balance", -1033,
        (int)global::ca::TxType::kTxTypeTx);
    return -10;
  }

  for (auto &to : toAddr) {
    CTxOutput *vout = txUtxo->add_vout();
    vout->set_addr(to.first);
    vout->set_value(to.second);
  }
  CTxOutput *voutFromAddr = txUtxo->add_vout();
  voutFromAddr->set_addr(*fromAddr.rbegin());
  voutFromAddr->set_value(total - expend);

  CTxOutput *vout_burn = txUtxo->add_vout();
  vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
  vout_burn->set_value(gas);

  std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
  for (auto &owner : setTxowners) {
    if (TxHelper::AddMutilSign(owner, outTx) != 0) {

      return -11;
    }
  }

  outTx.set_time(current_time);
  outTx.set_version(0);
  outTx.set_consensus(global::ca::kConsensus);
  outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeTx);

  if (type == TxHelper::vrfAgentType_local) {
    std::vector<SDKNodeInfo> nodelist;
    for (int i = 0; i < SDKAckMsg->nodeinfo_size(); ++i) {
      SDKNodeInfo node = SDKAckMsg->nodeinfo(i);
      nodelist.emplace_back(node);
    }
    std::random_device device;
    std::mt19937 engine(device());
    std::uniform_int_distribution<size_t> dist(0, nodelist.size() - 1);
    size_t random = dist(engine);
    std::string base58 = nodelist.at(random).base58addr();

    outTx.set_identity(base58);
    std::string ip = IpPort::ipsz(nodelist.at(random).public_ip());

    std::cout << "ip = " << ip << std::endl;
    std::cout << "type = " << type << std::endl;
    std::cout << "base58addr = " << nodelist.at(random).base58addr()
              << std::endl;
    std::cout << "public ip = " << IpPort::ipsz(nodelist.at(random).public_ip())
              << std::endl;
    std::cout << "public port = " << nodelist.at(random).public_port()
              << std::endl;

    MagicSingleton<Recver>::GetInstance()->connect(
        tx_id, ip, nodelist.at(random).listen_port());
    sleep(1);
  } else {

    std::string allUtxos;
    for (auto &utxo : setOutUtxos) {
      allUtxos += utxo.hash;
    }

    allUtxos += std::to_string(current_time);

    std::string id;
    int ret = GetBlockPackager(id, allUtxos, info, SDKAckMsg, tx_id);
    if (ret != 0) {
      return ret;
    }
    outTx.set_identity(id);
    std::cout << "id = " << id << std::endl;
  }

  std::string txHash = getsha256hash(outTx.SerializeAsString());
  outTx.set_hash(txHash);
  MagicSingleton<Recver>::GetInstance()->setGasHashTime(tx_id, gas, txHash,
                                                        current_time);
  std::cout << "txHash:" << txHash << std::endl;
  return 0;
}

int TxHelper::CreateStakeTransaction(
    const std::string &fromAddr, uint64_t stake_amount, uint64_t height,
    TxHelper::PledgeType pledgeType, CTransaction &outTx,
    std::vector<TxHelper::Utxo> &outVin, TxHelper::vrfAgentType &type,
    Vrf &info_, const std::shared_ptr<GetSDKAck> &SDKAckMsg, int tx_id) {

  std::vector<std::string> vecfromAddr;
  vecfromAddr.push_back(fromAddr);
  int ret = Check(vecfromAddr, height);
  if (ret != 0) {

    ret -= 100;
    return ret;
  }

  if (!CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_Normal)) {

    return -1;
  }

  if (stake_amount == 0) {

    return -2;
  }

  if (stake_amount < global::ca::kMinStakeAmt) {
    std::cout << "The pledge amount must be greater than 2000 !" << std::endl;
    return -3;
  }

  std::string strStakeType;
  if (pledgeType == TxHelper::PledgeType::kPledgeType_Node) {
    strStakeType = global::ca::kStakeTypeNet;
  } else {

    return -4;
  }

  uint64_t expend = stake_amount;

  uint64_t total = 0;
  std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;

  ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize, total, setOutUtxos,
                 SDKAckMsg);
  if (ret != 0) {

    ret -= 200;
    return ret;
  }

  if (setOutUtxos.empty()) {

    return -6;
  }

  outTx.Clear();

  CTxUtxo *txUtxo = outTx.mutable_utxo();

  std::set<string> setTxowners;
  for (auto &utxo : setOutUtxos) {
    setTxowners.insert(utxo.addr);
  }

  if (setTxowners.size() != 1) {

    return -7;
  }

  for (auto &owner : setTxowners) {
    txUtxo->add_owner(owner);
    uint32_t n = 0;
    CTxInput *vin = txUtxo->add_vin();
    for (auto &utxo : setOutUtxos) {
      if (owner == utxo.addr) {
        CTxPrevOutput *prevOutput = vin->add_prevout();
        prevOutput->set_hash(utxo.hash);
        prevOutput->set_n(utxo.n);
      }
    }
    vin->set_sequence(n++);

    std::string serVinHash = getsha256hash(vin->SerializeAsString());
    std::string signature;
    std::string pub;
    if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0) {
      return -8;
    }

    CSign *vinSign = vin->mutable_vinsign();
    vinSign->set_sign(signature);
    vinSign->set_pub(pub);
  }

  nlohmann::json txInfo;
  txInfo["StakeType"] = strStakeType;
  txInfo["StakeAmount"] = stake_amount;

  nlohmann::json data;
  data["TxInfo"] = txInfo;
  outTx.set_data(data.dump());
  outTx.set_type(global::ca::kTxSign);

  uint64_t gas = 0;

  std::map<std::string, int64_t> toAddr;
  toAddr.insert(std::make_pair(global::ca::kVirtualStakeAddr, stake_amount));
  toAddr.insert(std::make_pair(fromAddr, total - expend));
  toAddr.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));

  if (GenerateGas(outTx, toAddr, gas) != 0) {

    return -9;
  }

  auto current_time =
      MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

  GetTxStartIdentity(vecfromAddr, height, current_time, type, SDKAckMsg);

  expend += gas;

  if (total < expend) {
    MagicSingleton<Recver>::GetInstance()->setData(
        tx_id, "Insufficient balance", -1033,
        (int)global::ca::TxType::kTxTypeStake);
    return -11;
  }

  CTxOutput *vout = txUtxo->add_vout();
  vout->set_addr(global::ca::kVirtualStakeAddr);
  vout->set_value(stake_amount);

  CTxOutput *voutFromAddr = txUtxo->add_vout();
  voutFromAddr->set_addr(fromAddr);
  voutFromAddr->set_value(total - expend);

  CTxOutput *vout_burn = txUtxo->add_vout();
  vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
  vout_burn->set_value(gas);

  std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
  for (auto &owner : setTxowners) {
    if (TxHelper::AddMutilSign(owner, outTx) != 0) {
      return -12;
    }
  }

  outTx.set_version(0);
  outTx.set_time(current_time);
  outTx.set_consensus(global::ca::kConsensus);
  outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeStake);

  if (type == TxHelper::vrfAgentType_local) {

    std::vector<SDKNodeInfo> nodelist;
    for (int i = 0; i < SDKAckMsg->nodeinfo_size(); ++i) {
      SDKNodeInfo node = SDKAckMsg->nodeinfo(i);
      nodelist.emplace_back(node);
    }
    std::random_device device;
    std::mt19937 engine(device());
    std::uniform_int_distribution<size_t> dist(0, nodelist.size() - 1);
    size_t random = dist(engine);
    std::string base58 = nodelist.at(random).base58addr();

    outTx.set_identity(base58);
    std::string ip = IpPort::ipsz(nodelist.at(random).public_ip());
    std::cout << "type = " << type << std::endl;
    std::cout << "base58addr = " << nodelist.at(random).base58addr()
              << std::endl;
    std::cout << "public ip = " << IpPort::ipsz(nodelist.at(random).public_ip())
              << std::endl;
    MagicSingleton<Recver>::GetInstance()->connect(
        tx_id, ip, nodelist.at(random).listen_port());

    sleep(1);
  } else {

    std::string allUtxos;
    for (auto &utxo : setOutUtxos) {
      allUtxos += utxo.hash;
    }
    allUtxos += std::to_string(current_time);

    std::string id;

    int ret = GetBlockPackager(id, allUtxos, info_, SDKAckMsg, tx_id);
    if (ret != 0) {
      return ret;
    }
    outTx.set_identity(id);
  }

  std::string txHash = getsha256hash(outTx.SerializeAsString());
  outTx.set_hash(txHash);
  MagicSingleton<Recver>::GetInstance()->setGasHashTime(tx_id, gas, txHash,
                                                        current_time);
  return 0;
}

int TxHelper::CreatUnstakeTransaction(
    const std::string &fromAddr, const std::string &utxo_hash, uint64_t height,
    CTransaction &outTx, std::vector<TxHelper::Utxo> &outVin,
    TxHelper::vrfAgentType &type, Vrf &info_,
    const std::shared_ptr<GetSDKAck> &SDKAckMsg, int tx_id) {

  std::vector<std::string> vecfromAddr;
  vecfromAddr.push_back(fromAddr);
  int ret = Check(vecfromAddr, height);
  if (ret != 0) {

    ret -= 100;
    return ret;
  }

  if (CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_MultiSign) == true) {

    return -1;
  }

  uint64_t stake_amount = 0;
  ret = IsQualifiedToUnstake(fromAddr, utxo_hash, stake_amount, SDKAckMsg);
  if (ret != 0) {

    ret -= 200;
    return ret;
  }

  uint64_t total = 0;
  std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;

       
	
	ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize - 1, total, setOutUtxos,SDKAckMsg);
        if (ret != 0) {

          ret -= 300;
          return ret;
        }

        if (setOutUtxos.empty()) {

          return -2;
        }

        outTx.Clear();

        CTxUtxo *txUtxo = outTx.mutable_utxo();

        std::set<string> setTxowners;
        for (auto &utxo : setOutUtxos) {
          setTxowners.insert(utxo.addr);
        }
        if (setTxowners.empty()) {

          return -3;
        }

        {

          txUtxo->add_owner(vecfromAddr.at(0));
          CTxInput *txin = txUtxo->add_vin();
          txin->set_sequence(0);
          CTxPrevOutput *prevout = txin->add_prevout();
          prevout->set_hash(utxo_hash);
          prevout->set_n(1);

          std::string serVinHash = getsha256hash(txin->SerializeAsString());
          std::string signature;
          std::string pub;
          if (TxHelper::Sign(fromAddr, serVinHash, signature, pub) != 0) {
            return -4;
          }

          CSign *vinSign = txin->mutable_vinsign();
          vinSign->set_sign(signature);
          vinSign->set_pub(pub);
        }

        for (auto &owner : setTxowners) {
          txUtxo->add_owner(owner);
          uint32_t n = 1;
          CTxInput *vin = txUtxo->add_vin();
          for (auto &utxo : setOutUtxos) {
            if (owner == utxo.addr) {
              CTxPrevOutput *prevOutput = vin->add_prevout();
              prevOutput->set_hash(utxo.hash);
              prevOutput->set_n(utxo.n);
            }
          }
          vin->set_sequence(n++);

          std::string serVinHash = getsha256hash(vin->SerializeAsString());
          std::string signature;
          std::string pub;
          if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0) {
            return -5;
          }

          CSign *vinSign = vin->mutable_vinsign();
          vinSign->set_sign(signature);
          vinSign->set_pub(pub);
        }

        nlohmann::json txInfo;
        txInfo["UnstakeUtxo"] = utxo_hash;

        nlohmann::json data;
        data["TxInfo"] = txInfo;
        outTx.set_data(data.dump());
        outTx.set_type(global::ca::kTxSign);
        outTx.set_version(0);

        uint64_t gas = 0;

        std::map<std::string, int64_t> toAddr;
        toAddr.insert(
            std::make_pair(global::ca::kVirtualStakeAddr, stake_amount));
        toAddr.insert(std::make_pair(fromAddr, total));
        toAddr.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));

        if (GenerateGas(outTx, toAddr, gas) != 0) {

          return -6;
        }

        auto current_time =
            MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

        GetTxStartIdentity(vecfromAddr, height, current_time, type, SDKAckMsg);
        if (type == TxHelper::vrfAgentType_unknow) {
          type = TxHelper::vrfAgentType_local;
        }

        uint64_t expend = gas;

        if (total < expend) {
          MagicSingleton<Recver>::GetInstance()->setData(
              tx_id, "Insufficient balance", -1033,
              (int)global::ca::TxType::kTxTypeUnstake);
          return -8;
        }

        CTxOutput *txoutToAddr = txUtxo->add_vout();
        txoutToAddr->set_addr(fromAddr);
        txoutToAddr->set_value(stake_amount);

        txoutToAddr = txUtxo->add_vout();
        txoutToAddr->set_addr(fromAddr);
        txoutToAddr->set_value(total - expend);

        CTxOutput *vout_burn = txUtxo->add_vout();
        vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
        vout_burn->set_value(gas);

        std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
        for (auto &owner : setTxowners) {
          if (TxHelper::AddMutilSign(owner, outTx) != 0) {
            return -9;
          }
        }

        outTx.set_time(current_time);

        outTx.set_version(0);
        outTx.set_consensus(global::ca::kConsensus);
        outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeUnstake);

        if (type == TxHelper::vrfAgentType_defalut ||
            type == TxHelper::vrfAgentType_local) {
          std::vector<SDKNodeInfo> nodelist;
          for (int i = 0; i < SDKAckMsg->nodeinfo_size(); ++i) {
            SDKNodeInfo node = SDKAckMsg->nodeinfo(i);
            nodelist.emplace_back(node);
          }
          std::random_device device;
          std::mt19937 engine(device());
          std::uniform_int_distribution<size_t> dist(0, nodelist.size() - 1);
          size_t random = dist(engine);
          std::string base58 = nodelist.at(random).base58addr();
          outTx.set_identity(base58);

          std::string ip = IpPort::ipsz(nodelist.at(random).public_ip());

          std::cout << "type = " << type << std::endl;
          std::cout << "base58addr = " << nodelist.at(random).base58addr()
                    << std::endl;
          std::cout << "public ip = "
                    << IpPort::ipsz(nodelist.at(random).public_ip())
                    << std::endl;

          MagicSingleton<Recver>::GetInstance()->connect(
              tx_id, ip, nodelist.at(random).listen_port());

          sleep(1);
        } else {

          std::string allUtxos = utxo_hash;
          for (auto &utxo : setOutUtxos) {
            allUtxos += utxo.hash;
          }
          allUtxos += std::to_string(current_time);

          std::string id;
          int ret = GetBlockPackager(id, allUtxos, info_, SDKAckMsg, tx_id);
          if (ret != 0) {
            return ret;
          }
          outTx.set_identity(id);
        }
        std::string txHash = getsha256hash(outTx.SerializeAsString());
        outTx.set_hash(txHash);
        MagicSingleton<Recver>::GetInstance()->setGasHashTime(
            tx_id, gas, txHash, current_time);
        return 0;
}

int TxHelper::CreateInvestTransaction(
    const std::string &fromAddr, const std::string &toAddr,
    uint64_t invest_amount, uint64_t height, TxHelper::InvestType investType,
    CTransaction &outTx, std::vector<TxHelper::Utxo> &outVin,
    TxHelper::vrfAgentType &type, Vrf &info_,
    const std::shared_ptr<GetSDKAck> &SDKAckMsg, int tx_id) {

        std::vector<std::string> vecfromAddr;
        vecfromAddr.push_back(fromAddr);
        int ret = Check(vecfromAddr, height);
        if (ret != 0) {

          ret -= 100;
          return ret;
        }

        if (CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_MultiSign) ==
            true) {

          return -1;
        }

        if (CheckBase58Addr(toAddr, Base58Ver::kBase58Ver_MultiSign) == true) {

          return -2;
        }

        if (invest_amount < global::ca::kMinInvestAmt) {

          return -3;
        }

        uint64_t stake_count = 0;

        ret = CheckInvestQualification(fromAddr, toAddr, invest_amount,
                                       SDKAckMsg);
        if (ret != 0) {

          ret -= 200;
          return ret;
        }
        std::string strinvestType;
        if (investType == TxHelper::InvestType::kInvestType_NetLicence) {
          strinvestType = global::ca::kInvestTypeNormal;
        } else {

          return -3;
        }

        uint64_t total = 0;
        uint64_t expend = invest_amount;

        std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
        ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize, total, setOutUtxos,
                       SDKAckMsg);
        if (ret != 0) {

          ret -= 300;
          return ret;
        }
        if (setOutUtxos.empty()) {

          return -4;
        }

        outTx.Clear();

        CTxUtxo *txUtxo = outTx.mutable_utxo();

        std::set<string> setTxowners;
        for (auto &utxo : setOutUtxos) {
          setTxowners.insert(utxo.addr);
        }
        if (setTxowners.empty()) {

          return -5;
        }

        for (auto &owner : setTxowners) {
          txUtxo->add_owner(owner);
          uint32_t n = 0;
          CTxInput *vin = txUtxo->add_vin();
          for (auto &utxo : setOutUtxos) {
            if (owner == utxo.addr) {
              CTxPrevOutput *prevOutput = vin->add_prevout();
              prevOutput->set_hash(utxo.hash);
              prevOutput->set_n(utxo.n);
            }
          }
          vin->set_sequence(n++);

          std::string serVinHash = getsha256hash(vin->SerializeAsString());
          std::string signature;
          std::string pub;
          if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0) {
            return -6;
          }

          CSign *vinSign = vin->mutable_vinsign();
          vinSign->set_sign(signature);
          vinSign->set_pub(pub);
        }

        nlohmann::json txInfo;
        txInfo["InvestType"] = strinvestType;
        txInfo["BonusAddr"] = toAddr;
        txInfo["InvestAmount"] = invest_amount;

        nlohmann::json data;
        data["TxInfo"] = txInfo;
        outTx.set_data(data.dump());
        outTx.set_type(global::ca::kTxSign);

        uint64_t gas = 0;

        std::map<std::string, int64_t> toAddrs;
        toAddrs.insert(
            std::make_pair(global::ca::kVirtualStakeAddr, invest_amount));
        toAddrs.insert(std::make_pair(fromAddr, total - expend));
        toAddrs.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));

        if (GenerateGas(outTx, toAddrs, gas) != 0) {
          std::cout << "GenerateGas gas = " << gas << std::endl;

          return -7;
        }

        auto current_time =
            MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

        GetTxStartIdentity(vecfromAddr, height, current_time, type, SDKAckMsg);

        expend += gas;

        if (total < expend) {
          MagicSingleton<Recver>::GetInstance()->setData(
              tx_id, "Insufficient balance", -1033,
              (int)global::ca::TxType::kTxTypeInvest);
          return -9;
        }

        CTxOutput *vout = txUtxo->add_vout();
        vout->set_addr(global::ca::kVirtualInvestAddr);
        vout->set_value(invest_amount);

        CTxOutput *voutFromAddr = txUtxo->add_vout();
        voutFromAddr->set_addr(fromAddr);
        voutFromAddr->set_value(total - expend);

        CTxOutput *vout_burn = txUtxo->add_vout();
        vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
        vout_burn->set_value(gas);

        std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
        for (auto &owner : setTxowners) {
          if (TxHelper::AddMutilSign(owner, outTx) != 0) {
            return -10;
          }
        }

        outTx.set_version(0);
        outTx.set_time(current_time);
        outTx.set_consensus(global::ca::kConsensus);
        outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeInvest);

        if (type == TxHelper::vrfAgentType_local) {
          std::vector<SDKNodeInfo> nodelist;
          for (int i = 0; i < SDKAckMsg->nodeinfo_size(); ++i) {
            SDKNodeInfo node = SDKAckMsg->nodeinfo(i);
            nodelist.emplace_back(node);
          }
          std::random_device device;
          std::mt19937 engine(device());
          std::uniform_int_distribution<size_t> dist(0, nodelist.size() - 1);
          size_t random = dist(engine);

          std::string base58 = nodelist.at(random).base58addr();
          outTx.set_identity(base58);
          string ip = IpPort::ipsz(nodelist.at(random).public_ip());

          std::cout << "type = " << type << std::endl;
          std::cout << "base58addr = " << nodelist.at(random).base58addr()
                    << std::endl;
          std::cout << "public ip = "
                    << IpPort::ipsz(nodelist.at(random).public_ip())
                    << std::endl;

          MagicSingleton<Recver>::GetInstance()->connect(
              tx_id, ip, nodelist.at(random).listen_port());

          sleep(1);
        } else {

          std::string allUtxos;
          for (auto &utxo : setOutUtxos) {
            allUtxos += utxo.hash;
          }
          allUtxos += std::to_string(current_time);

          std::string id;
          int ret = GetBlockPackager(id, allUtxos, info_, SDKAckMsg, tx_id);
          if (ret != 0) {
            return ret;
          }
          outTx.set_identity(id);
        }

        std::string txHash = getsha256hash(outTx.SerializeAsString());
        outTx.set_hash(txHash);
        MagicSingleton<Recver>::GetInstance()->setGasHashTime(
            tx_id, gas, txHash, current_time);
        return 0;
}

int TxHelper::CreateDisinvestTransaction(
    const std::string &fromAddr, const std::string &toAddr,
    const std::string &utxo_hash, uint64_t height, CTransaction &outTx,
    std::vector<TxHelper::Utxo> &outVin, TxHelper::vrfAgentType &type,
    Vrf &info_, const std::shared_ptr<GetSDKAck> &SDKAckMsg, int tx_id) {

        std::vector<std::string> vecfromAddr;
        vecfromAddr.push_back(fromAddr);
        int ret = Check(vecfromAddr, height);
        if (ret != 0) {

          ret -= 100;
          return ret;
        }

        if (CheckBase58Addr(fromAddr, Base58Ver::kBase58Ver_MultiSign) ==
            true) {

          return -1;
        }

        if (CheckBase58Addr(toAddr, Base58Ver::kBase58Ver_MultiSign) == true) {

          return -2;
        }

        uint64_t invested_amount = 0;
        if (IsQualifiedToDisinvest(fromAddr, toAddr, utxo_hash, invested_amount,
                                   SDKAckMsg) != 0) {
          infoL("FromAddr is not qualified to divest!.");
          return -3;
        }

        uint64_t total = 0;
        std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;

        ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize - 1, total,
                       setOutUtxos, SDKAckMsg);
        if (ret != 0) {

          ret -= 300;
          return ret;
        }

        if (setOutUtxos.empty()) {

          return -4;
        }

        outTx.Clear();

        CTxUtxo *txUtxo = outTx.mutable_utxo();

        std::set<string> setTxowners;
        for (auto &utxo : setOutUtxos) {
          setTxowners.insert(utxo.addr);
        }
        if (setTxowners.empty()) {

          return -5;
        }

        {

          txUtxo->add_owner(vecfromAddr.at(0));
          CTxInput *txin = txUtxo->add_vin();
          txin->set_sequence(0);
          CTxPrevOutput *prevout = txin->add_prevout();
          prevout->set_hash(utxo_hash);
          prevout->set_n(1);

          std::string serVinHash = getsha256hash(txin->SerializeAsString());
          std::string signature;
          std::string pub;
          ret = TxHelper::Sign(fromAddr, serVinHash, signature, pub);
          if (ret != 0) {

            return -6;
          }

          CSign *vinSign = txin->mutable_vinsign();
          vinSign->set_sign(signature);
          vinSign->set_pub(pub);
        }

        for (auto &owner : setTxowners) {
          txUtxo->add_owner(owner);
          uint32_t n = 1;
          CTxInput *vin = txUtxo->add_vin();
          for (auto &utxo : setOutUtxos) {
            if (owner == utxo.addr) {
              CTxPrevOutput *prevOutput = vin->add_prevout();
              prevOutput->set_hash(utxo.hash);
              prevOutput->set_n(utxo.n);
            }
          }
          vin->set_sequence(n++);

          std::string serVinHash = getsha256hash(vin->SerializeAsString());
          std::string signature;
          std::string pub;
          if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0) {
            return -7;
          }

          CSign *vinSign = vin->mutable_vinsign();
          vinSign->set_sign(signature);
          vinSign->set_pub(pub);
        }

        nlohmann::json txInfo;
        txInfo["BonusAddr"] = toAddr;
        txInfo["DisinvestUtxo"] = utxo_hash;

        nlohmann::json data;
        data["TxInfo"] = txInfo;
        outTx.set_data(data.dump());
        outTx.set_type(global::ca::kTxSign);

        uint64_t gas = 0;

        std::map<std::string, int64_t> targetAddrs;
        targetAddrs.insert(
            std::make_pair(global::ca::kVirtualStakeAddr, invested_amount));
        targetAddrs.insert(std::make_pair(fromAddr, total));
        targetAddrs.insert(
            std::make_pair(global::ca::kVirtualBurnGasAddr, gas));

        if (GenerateGas(outTx, targetAddrs, gas) != 0) {

          return -8;
        }

        auto current_time =
            MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
        GetTxStartIdentity(vecfromAddr, height, current_time, type, SDKAckMsg);

        uint64_t expend = gas;

        if (total < expend) {
          MagicSingleton<Recver>::GetInstance()->setData(
              tx_id, "Insufficient balance", -1033,
              (int)global::ca::TxType::kTxTypeDisinvest);
          return -10;
        }

        CTxOutput *txoutToAddr = txUtxo->add_vout();
        txoutToAddr->set_addr(fromAddr);
        txoutToAddr->set_value(invested_amount);

        txoutToAddr = txUtxo->add_vout();
        txoutToAddr->set_addr(fromAddr);
        txoutToAddr->set_value(total - expend);

        CTxOutput *vout_burn = txUtxo->add_vout();
        vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
        vout_burn->set_value(gas);

        std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
        for (auto &owner : setTxowners) {
          if (TxHelper::AddMutilSign(owner, outTx) != 0) {
            return -11;
          }
        }

        outTx.set_time(current_time);
        outTx.set_version(0);

        outTx.set_consensus(global::ca::kConsensus);
        outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeDisinvest);

        if (type == TxHelper::vrfAgentType_defalut ||
            type == TxHelper::vrfAgentType_local) {
          std::vector<SDKNodeInfo> nodelist;
          for (int i = 0; i < SDKAckMsg->nodeinfo_size(); ++i) {
            SDKNodeInfo node = SDKAckMsg->nodeinfo(i);
            nodelist.emplace_back(node);
          }
          std::random_device device;
          std::mt19937 engine(device());
          std::uniform_int_distribution<size_t> dist(0, nodelist.size() - 1);
          size_t random = dist(engine);

          std::string base58 = nodelist.at(random).base58addr();
          outTx.set_identity(base58);
          string ip = IpPort::ipsz(nodelist.at(random).public_ip());

          std::cout << "type = " << type << std::endl;
          std::cout << "base58addr = " << nodelist.at(random).base58addr()
                    << std::endl;
          std::cout << "public ip = "
                    << IpPort::ipsz(nodelist.at(random).public_ip())
                    << std::endl;

          MagicSingleton<Recver>::GetInstance()->connect(
              tx_id, ip, nodelist.at(random).listen_port());

          sleep(1);
        } else {

          std::string allUtxos = utxo_hash;
          for (auto &utxo : setOutUtxos) {
            allUtxos += utxo.hash;
          }
          allUtxos += std::to_string(current_time);

          std::string id;
          int ret = GetBlockPackager(id, allUtxos, info_, SDKAckMsg, tx_id);
          if (ret != 0) {
            return ret;
          }
          outTx.set_identity(id);
        }

        std::string txHash = getsha256hash(outTx.SerializeAsString());
        outTx.set_hash(txHash);
        MagicSingleton<Recver>::GetInstance()->setGasHashTime(
            tx_id, gas, txHash, current_time);
        return 0;
}

int TxHelper::CreateBonusTransaction(
    const std::string &Addr, uint64_t height, CTransaction &outTx,
    std::vector<TxHelper::Utxo> &outVin, TxHelper::vrfAgentType &type,
    Vrf &info_, const std::shared_ptr<GetSDKAck> &SDKAckMsg, uint64_t cur_time,
    int tx_id) {
        std::vector<std::string> vecfromAddr;
        vecfromAddr.push_back(Addr);
        int ret = Check(vecfromAddr, height);
        if (ret != 0) {

          ret -= 100;
          return ret;
        }

        if (CheckBase58Addr(Addr, Base58Ver::kBase58Ver_MultiSign) == true) {

          return -1;
        }

        std::vector<std::string> utxos;

        uint64_t zero_time =
            MagicSingleton<TimeUtil>::GetInstance()->getMorningTime(cur_time) *
            1000000;

        if (cur_time < (zero_time + 60 * 60 * 1000000ul)) {
          std::cout << RED << "Claim after 1 a.m!" << RESET << std::endl;
          return -3;
        }

        CTransaction tx;
        for (int i = 0; i < SDKAckMsg->claimtx_size(); ++i) {
          Claimtx *claimtx = SDKAckMsg->mutable_claimtx(i);
          tx.ParseFromString(claimtx->tx());

          std::string ClaimAddr =
              GetBase58Addr(tx.utxo().vin(0).vinsign().pub());
          if (Addr == ClaimAddr) {
            std::cout << RED << "Application completed!" << RESET << std::endl;
            return -6;
          }
        }

        ret = VerifyBonusAddr(Addr, SDKAckMsg);
        if (ret < 0) {
          return -7;
        }

        std::map<std::string, uint64_t> CompanyDividend;

        ret = ca_algorithm::CalcBonusValue(cur_time, Addr, CompanyDividend,
                                           SDKAckMsg);
        if (ret < 0) {

          ret -= 300;
          return ret;
        }

        uint64_t expend = 0;
        uint64_t total = 0;
        std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
        ret = FindUtxo(vecfromAddr, TxHelper::kMaxVinSize - 1, total,
                       setOutUtxos, SDKAckMsg);
        if (ret != 0) {

          ret -= 200;
          return ret;
        }
        if (setOutUtxos.empty()) {

          return -8;
        }

        outTx.Clear();

        CTxUtxo *txUtxo = outTx.mutable_utxo();

        std::set<string> setTxowners;
        for (auto &utxo : setOutUtxos) {
          setTxowners.insert(utxo.addr);
        }
        if (setTxowners.empty()) {

          return -9;
        }

        for (auto &owner : setTxowners) {
          txUtxo->add_owner(owner);
          uint32_t n = 0;
          CTxInput *vin = txUtxo->add_vin();
          for (auto &utxo : setOutUtxos) {
            if (owner == utxo.addr) {
              CTxPrevOutput *prevOutput = vin->add_prevout();
              prevOutput->set_hash(utxo.hash);
              prevOutput->set_n(utxo.n);
            }
          }
          vin->set_sequence(n++);

          std::string serVinHash = getsha256hash(vin->SerializeAsString());
          std::string signature;
          std::string pub;
          if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0) {
            return -10;
          }

          CSign *vinSign = vin->mutable_vinsign();
          vinSign->set_sign(signature);
          vinSign->set_pub(pub);
        }

        uint64_t tempCosto = 0;
        uint64_t tempNodeDividend = 0;
        uint64_t tempTotalClaim = 0;
        for (auto Company : CompanyDividend) {
          tempCosto = Company.second * 0.05 + 0.5;
          tempNodeDividend += tempCosto;
          std::string addr = Company.first;
          uint64_t award = Company.second - tempCosto;
          tempTotalClaim += award;
        }
        tempTotalClaim += tempNodeDividend;

        nlohmann::json txInfo;
        txInfo["BonusAmount"] = tempTotalClaim;
        txInfo["BonusAddrList"] = CompanyDividend.size() + 1;

        nlohmann::json data;
        data["TxInfo"] = txInfo;
        outTx.set_data(data.dump());
        outTx.set_type(global::ca::kTxSign);

        uint64_t gas = 0;
        std::map<std::string, int64_t> toAddrs;
        for (const auto &item : CompanyDividend) {
          toAddrs.insert(make_pair(item.first, item.second));
        }
        toAddrs.insert(
            std::make_pair(global::ca::kVirtualStakeAddr, total - expend));
        toAddrs.insert(std::make_pair(global::ca::kVirtualBurnGasAddr, gas));

        if (GenerateGas(outTx, toAddrs, gas) != 0) {

          return -11;
        }

        auto current_time =
            MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
        GetTxStartIdentity(vecfromAddr, height, current_time, type, SDKAckMsg);
        if (type == TxHelper::vrfAgentType_unknow) {

          return -300;
        }

        expend += gas;

        if (total < expend) {
          MagicSingleton<Recver>::GetInstance()->setData(
              tx_id, "Insufficient balance", -1033,
              (int)global::ca::TxType::kTxTypeBonus);
          return -13;
        }

        outTx.set_time(current_time);
        outTx.set_version(0);

        outTx.set_consensus(global::ca::kConsensus);
        outTx.set_txtype((uint32_t)global::ca::TxType::kTxTypeBonus);

        uint64_t costo = 0;
        uint64_t NodeDividend = 0;
        uint64_t TotalClaim = 0;
        std::cout << YELLOW << "Claim Addr : Claim Amount" << RESET
                  << std::endl;
        for (auto Company : CompanyDividend) {
          costo = Company.second * 0.05 + 0.5;
          NodeDividend += costo;
          std::string addr = Company.first;
          uint64_t award = Company.second - costo;
          TotalClaim += award;
          CTxOutput *txoutToAddr = txUtxo->add_vout();
          txoutToAddr->set_addr(addr);
          txoutToAddr->set_value(award);
          std::cout << Company.first << ":" << Company.second << std::endl;
        }

        CTxOutput *txoutToAddr = txUtxo->add_vout();
        txoutToAddr->set_addr(Addr);
        txoutToAddr->set_value(total - expend + NodeDividend);

        CTxOutput *vout_burn = txUtxo->add_vout();
        vout_burn->set_addr(global::ca::kVirtualBurnGasAddr);
        vout_burn->set_value(gas);

        std::cout << Addr << ":" << NodeDividend << std::endl;
        TotalClaim += NodeDividend;
        if (TotalClaim == 0) {

          return -14;
        }

        std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
        for (auto &owner : setTxowners) {
          if (TxHelper::AddMutilSign(owner, outTx) != 0) {
            return -15;
          }
        }

        if (type == TxHelper::vrfAgentType_defalut ||
            type == TxHelper::vrfAgentType_local) {
          std::vector<SDKNodeInfo> nodelist;
          for (int i = 0; i < SDKAckMsg->nodeinfo_size(); ++i) {
            SDKNodeInfo node = SDKAckMsg->nodeinfo(i);
            nodelist.emplace_back(node);
          }
          std::random_device device;
          std::mt19937 engine(device());
          std::uniform_int_distribution<size_t> dist(0, nodelist.size() - 1);
          size_t random = dist(engine);

          std::string base58 = nodelist.at(random).base58addr();
          outTx.set_identity(base58);
          string ip = IpPort::ipsz(nodelist.at(random).public_ip());
          std::cout << "type = " << type << std::endl;
          std::cout << "base58addr = " << nodelist.at(random).base58addr()
                    << std::endl;
          std::cout << "public ip = "
                    << IpPort::ipsz(nodelist.at(random).public_ip())
                    << std::endl;
          std::cout << "public port = " << nodelist.at(random).public_port()
                    << std::endl;

          MagicSingleton<Recver>::GetInstance()->connect(
              tx_id, ip, nodelist.at(random).listen_port());

        } else {

          std::string allUtxos;
          for (auto &utxo : setOutUtxos) {
            allUtxos += utxo.hash;
          }
          allUtxos += std::to_string(current_time);

          std::string id;
          int ret = GetBlockPackager(id, allUtxos, info_, SDKAckMsg, tx_id);
          if (ret != 0) {
            return ret;
          }
          outTx.set_identity(id);
        }

        std::string txHash = getsha256hash(outTx.SerializeAsString());
        outTx.set_hash(txHash);
        MagicSingleton<Recver>::GetInstance()->setGasHashTime(
            tx_id, gas, txHash, current_time);
        return 0;
}

int TxHelper::AddMutilSign(const std::string &addr, CTransaction &tx) {
        if (!CheckBase58Addr(addr)) {
          return -1;
        }

        CTxUtxo *txUtxo = tx.mutable_utxo();
        CTxUtxo copyTxUtxo = *txUtxo;
        copyTxUtxo.clear_multisign();

        std::string serTxUtxo = getsha256hash(copyTxUtxo.SerializeAsString());
        std::string signature;
        std::string pub;
        if (TxHelper::Sign(addr, serTxUtxo, signature, pub) != 0) {
          return -2;
        }

        CSign *multiSign = txUtxo->add_multisign();
        multiSign->set_sign(signature);
        multiSign->set_pub(pub);

        return 0;
}

int TxHelper::AddVerifySign(const std::string &addr, CTransaction &tx) {
        if (!CheckBase58Addr(addr)) {

          return -1;
        }

        CTransaction copyTx = tx;

        copyTx.clear_hash();
        copyTx.clear_verifysign();

        std::string serTx = copyTx.SerializeAsString();
        if (serTx.empty()) {

          return -2;
        }

        std::string message = getsha256hash(serTx);

        std::string signature;
        std::string pub;
        if (TxHelper::Sign(addr, message, signature, pub) != 0) {

          return -3;
        }

        CSign *verifySign = tx.add_verifysign();
        verifySign->set_sign(signature);
        verifySign->set_pub(pub);

        return 0;
}

int TxHelper::Sign(const std::string &addr, const std::string &message,
                   std::string &signature, std::string &pub) {
        if (addr.empty() || message.empty()) {
          return -1;
        }

        ED account;
        EVP_PKEY_free(account.pkey);
        if (MagicSingleton<EDManager>::GetInstance()->FindAccount(
                addr, account) != 0) {

          std::cout << "account {} doesn't exist " << addr << std::endl;
          return -2;
        }

        if (!account.Sign(message, signature)) {
          return -3;
        }

        pub = account.pubStr;
        return 0;
}

bool TxHelper::IsNeedAgent(const std::vector<std::string> &fromAddr) {
        bool isNeedAgent = true;
        for (auto &owner : fromAddr) {

          if (owner == MagicSingleton<EDManager>::GetInstance()
                           ->GetDefaultBase58Addr()) {
            isNeedAgent = false;
          }
        }

        return isNeedAgent;
}

bool TxHelper::IsNeedAgent(const CTransaction &tx) {
        if (std::find(tx.utxo().owner().begin(), tx.utxo().owner().end(),
                      tx.identity()) == tx.utxo().owner().end()) {
          return true;
        }

        return false;
}

bool TxHelper::checkTxTimeOut(const uint64_t &txTime, const uint64_t &timeout,
                              const uint64_t &pre_height,
                              const std::shared_ptr<GetSDKAck> &SDKAckMsg) {
        if (txTime <= 0) {

          return false;
        }

        std::vector<CBlock> blocks;

        for (size_t i = 0; i < (size_t)SDKAckMsg->blocks_size(); ++i) {

          CBlock block;
          block.ParseFromString(SDKAckMsg->blocks(i));
          cout << "block hash = " << block.hash() << endl;
          blocks.emplace_back(block);
        }

        std::sort(blocks.begin(), blocks.end(),
                  [](const CBlock &x, const CBlock &y) {
                    return x.time() < y.time();
                  });
        CBlock result_block;
        if (blocks.size() != 0) {
          result_block = blocks[blocks.size() - 1];
        }
        if (result_block.time() <= 0) {

          return false;
        }

        uint64_t result_time = abs(int64_t(txTime - result_block.time()));
        if (result_time > timeout * 1000000) {

          return true;
        }
        return false;
}

TxHelper::vrfAgentType
TxHelper::GetVrfAgentType(const CTransaction &tx, uint64_t &pre_height,
                          const std::shared_ptr<GetSDKAck> &SDKAckMsg) {
        std::vector<std::string> owners(tx.utxo().owner().begin(),
                                        tx.utxo().owner().end());

        if (!TxHelper::checkTxTimeOut(tx.time(), global::ca::TxTimeoutMin,
                                      pre_height, SDKAckMsg)) {
          if (std::find(owners.begin(), owners.end(), tx.identity()) ==
              owners.end()) {
            return TxHelper::vrfAgentType::vrfAgentType_vrf;
          }
          return TxHelper::vrfAgentType::vrfAgentType_defalut;
        } else {

          if (std::find(owners.begin(), owners.end(), tx.identity()) ==
              owners.end()) {
            return TxHelper::vrfAgentType::vrfAgentType_local;
          }
        }
        return TxHelper::vrfAgentType::vrfAgentType_unknow;
}

void TxHelper::GetTxStartIdentity(const std::vector<std::string> &fromaddr,
                                  const uint64_t &height,
                                  const uint64_t &current_time,
                                  TxHelper::vrfAgentType &type,
                                  const std::shared_ptr<GetSDKAck> &SDKAckMsg) {

        uint64_t pre_height = height - 1;

        if (checkTxTimeOut(current_time, global::ca::TxTimeoutMin, pre_height,
                           SDKAckMsg) == true) {

          type = vrfAgentType_local;
          return;
        } else {
          type = vrfAgentType_vrf;
          return;
        }
}
