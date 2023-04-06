#include "ca_handle_event.h"
#include "../net/ip_port.h"
#include "../net/net_api.h"
#include "ca/ca_global.h"
#include "ca_txhelper.h"
#include "common/global.h"
#include "net/net_api.h"
#include "proto/common.pb.h"
#include "proto/interface.pb.h"
#include "utils/EDManager.h"
#include "utils/MagicSingleton.h"
#include "utils/base58.h"
#include "utils/hexcode.h"
#include "utils/string_util.h"
#include "utils/util.h"
#include <algorithm>
#include <boost/functional/hash.hpp>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <string>

#include "../ca/ca_transaction.h"
#include "Tdata.h"
#include "ca/ca_global.h"
#include "net/connect.h"
#include "proto/ca_protomsg.pb.h"
#include "proto/sdk.pb.h"
#include "proto/transaction.pb.h"
#include "transaction.pb.h"
#include "utils/EDManager.h"
#include "utils/ErrorMessage.h"
#include "utils/console.h"
#include "utils/json.hpp"
#include "utils/string_util.h"
#include "utils/time_util.h"
#include "utils/tmplog.h"

int HandleCaptureTheInvestment(
    const std::shared_ptr<GetRestInvestAmountAck> &ack, const MsgData &from) {
  int tx_id__t = from.Tx_ID;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(from.Tx_ID);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG("tx_id not found"));
    return 0;
  }
  uint64_t retv = ack->amount();
  if (ack->code() < 0) {
    retv = ack->code();
  }
  data_->CaptureTheInvestment = retv;
  return 0;
}

int HandleTxStatus(const std::shared_ptr<IsOnChainAck> &ack,
                   const MsgData &from) {
  int tx_id__t = from.Tx_ID;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(from.Tx_ID);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG("tx_id not found"));
    return 0;
  }
  int size_s = ack->percentage_size();

  for (int i = 0; i < size_s; i++) {
    auto isSuccess_ = ack->percentage(i);
    double code_ = 0;
    if (ack->code() < 0) {
      code_ = ack->code();
    } else {
      code_ = isSuccess_.rate();
    }
    data_->checkRet.push({isSuccess_.hash(), code_});
  }
  return 0;
}

int HandleTransactionTxMsgAck(const std::shared_ptr<TxMsgAck> &ack,
                              const MsgData &from) {
  std::cout << "TxMsgAck---->message = " << ack->message() << std::endl;
  std::cout << "TxMsgAck---->code" << ack->code() << std::endl;
  std::cout << "from.ip = " << from.ip << std::endl;
  std::cout << "from.port = " << from.port << std::endl;

  int tx_id = from.Tx_ID;

  CTransaction Tx;
  Tx.ParseFromString(ack->tx());
  std::cout << " MsgAck hash:" << Tx.hash() << std::endl;
  int type = Tx.txtype();
  std::cout << "Tx type:" << Tx.txtype() << std::endl;
  MagicSingleton<Recver>::GetInstance()->setData(tx_id, ack->message().data(),
                                                 ack->code(), type);

  return 0;
}

int HandleSdkTransaction(const std::shared_ptr<GetSDKAck> &ack,
                         const MsgData &from) {

  int tx_id__t = from.Tx_ID;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(from.Tx_ID);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return 0;
  }
  if (ack->type() == 1) {
    std::cout << "" << std::endl;

    std::cout << "*********************" << std::endl;
    std::cout << "str_fromAddr =" << data_->from_Addr.at(0) << std::endl;
    std::cout << "str_ToAddr =" << data_->str_ToAddr << std::endl;
    std::cout << "str_Amt =" << data_->str_Amt << std::endl;

    uint64_t amount =
        (std::stod(data_->str_Amt) + global::ca::kFixDoubleMinPrecision) *
        global::ca::kDecimalNum;
    std::map<std::string, int64_t> toAddrAmount;
    toAddrAmount[data_->str_ToAddr] = amount;

    uint64_t top = ack->height();
    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgent_flag;

    Vrf info_;
    int ret = TxHelper::CreateTxTransaction(data_->from_Addr, toAddrAmount,
                                            top + 1, outTx, isNeedAgent_flag,
                                            info_, ack, tx_id__t);
    if (ret != 0) {
      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          ret, MSG("CreateTxTransaction Fail"));
      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return ret;
    }

    std::string newbase58 = outTx.identity();
    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);

    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf) {
      Vrf *new_info = txMsg.mutable_vrfinfo();
      new_info->CopyFrom(info_);
    }

    std::string outdata;
    SendMessage(txMsg.SerializeAsString(), txMsg.GetDescriptor()->name(),
                outdata);

    int result = data_->netWork.send(outdata.data(), outdata.size());
    if (result < 0) {
      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          result, MSG(strerror(errno)));
      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return -1;
    }
    sleep(1);
    MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);

  } else if (ack->type() == 2) {
    TxHelper::PledgeType pledgeType = TxHelper::PledgeType::kPledgeType_Node;

    uint64_t stake_amount = std::stod(data_->str_Amt) * global::ca::kDecimalNum;
    uint64_t top = ack->height();

    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;

    int ret = TxHelper::CreateStakeTransaction(
        data_->from_Addr.at(0), stake_amount, top + 1, pledgeType, outTx,
        outVin, isNeedAgent_flag, info_, ack, tx_id__t);
    if (ret != 0) {
      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          ret, MSG("CreateStakeTransaction Fail"));

      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return ret;
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    std::string newbase58 = outTx.identity();
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf) {
      Vrf *new_info = txMsg.mutable_vrfinfo();
      new_info->CopyFrom(info_);
    }

    std::string outdata;
    SendMessage(txMsg.SerializeAsString(), txMsg.GetDescriptor()->name(),
                outdata);

    int result = data_->netWork.send(outdata.data(), outdata.size());
    if (result < 0) {

      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          result, MSG(strerror(errno)));
      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return -1;
    }
    sleep(1);
    MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);

  } else if (ack->type() == 3) {
    uint64_t top = ack->height();
    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;

    int ret = TxHelper::CreatUnstakeTransaction(
        data_->from_Addr.at(0), data_->str_utxo, top + 1, outTx, outVin,
        isNeedAgent_flag, info_, ack, tx_id__t);
    if (ret != 0) {
      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          ret, MSG("CreatUnstakeTransaction Fail"));
      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return ret;
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    std::string newbase58 = outTx.identity();
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf) {
      Vrf *new_info = txMsg.mutable_vrfinfo();
      new_info->CopyFrom(info_);
    }
    std::string outdata;
    SendMessage(txMsg.SerializeAsString(), txMsg.GetDescriptor()->name(),
                outdata);

    int result = data_->netWork.send(outdata.data(), outdata.size());
    if (result < 0) {
      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          -1, MSG(strerror(errno)));
      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return -1;
    }
    sleep(1);
    MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  } else if (ack->type() == 4) {
    TxHelper::InvestType investType =
        TxHelper::InvestType::kInvestType_NetLicence;
    uint64_t invest_amount =
        std::stod(data_->str_Amt) * global::ca::kDecimalNum;

    uint64_t top = ack->height();
    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;

    int ret = TxHelper::CreateInvestTransaction(
        data_->from_Addr.at(0), data_->str_ToAddr, invest_amount, top + 1,
        investType, outTx, outVin, isNeedAgent_flag, info_, ack, tx_id__t);
    if (ret != 0) {

      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          ret, MSG("CreateInvestTransaction Fail"));
      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return ret;
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    std::string newbase58 = outTx.identity();
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf) {
      Vrf *new_info = txMsg.mutable_vrfinfo();
      new_info->CopyFrom(info_);
    }
    std::string outdata;
    SendMessage(txMsg.SerializeAsString(), txMsg.GetDescriptor()->name(),
                outdata);

    auto iter = MagicSingleton<net>::GetInstance();
    int result = data_->netWork.send(outdata.data(), outdata.size());
    if (result < 0) {

      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          result, MSG(strerror(errno)));
      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return -1;
    }
    sleep(1);
    MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  } else if (ack->type() == 5) {
    uint64_t top = ack->height();
    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;

    int ret = TxHelper::CreateDisinvestTransaction(
        data_->from_Addr.at(0), data_->str_ToAddr, data_->str_utxo, top + 1,
        outTx, outVin, isNeedAgent_flag, info_, ack, tx_id__t);
    if (ret != 0) {
      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          ret, MSG("CreateDisinvestTransaction Fail"));
      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return ret;
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    std::string newbase58 = outTx.identity();
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf) {
      Vrf *new_info = txMsg.mutable_vrfinfo();
      new_info->CopyFrom(info_);
    }
    std::string outdata;
    SendMessage(txMsg.SerializeAsString(), txMsg.GetDescriptor()->name(),
                outdata);

    int result = data_->netWork.send(outdata.data(), outdata.size());
    if (result < 0) {
      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          result, MSG(strerror(errno)));
      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return -1;
    }
    sleep(2);
    MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  } else if (ack->type() == 6) {
    uint64_t top = ack->height();
    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;

    int ret = TxHelper::CreateBonusTransaction(
        data_->from_Addr.at(0), top + 1, outTx, outVin, isNeedAgent_flag, info_,
        ack, data_->cur_time, tx_id__t);
    if (ret != 0) {
      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          ret, MSG("CreateBonusTransaction Fail"));

      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return ret;
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    std::string newbase58 = outTx.identity();
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if (isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf) {
      Vrf *new_info = txMsg.mutable_vrfinfo();
      new_info->CopyFrom(info_);
    }
    std::string outdata;
    SendMessage(txMsg.SerializeAsString(), txMsg.GetDescriptor()->name(),
                outdata);

    int result = data_->netWork.send(outdata.data(), outdata.size());
    if (result < 0) {
      MagicSingleton<ErrorMessage>::GetInstance()->addError(
          result, MSG(strerror(errno)));
      MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
      return -1;
    }
    sleep(1);
    MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  }
  return 0;
}

int HandleGetUtxo(const std::shared_ptr<GetBalanceAck> &ack,
                  const MsgData &from) {
  int tx_id__t = from.Tx_ID;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(from.Tx_ID);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return 0;
  }
  std::string version = global::kVersion;
  std::string base58 =
      MagicSingleton<EDManager>::GetInstance()->GetDefaultBase58Addr();

  uint64_t balance = ack->balance();

  uint64_t blockHeight = ack->height();

  ca_console infoColor(kConsoleColor_Green, kConsoleColor_Black, true);
  double b = balance / double(100000000);
  std::cout << infoColor.color();
  std::cout << "***************************************************************"
               "******************"
            << std::endl;
  std::cout << "Version: " << version << std::endl;
  std::cout << "Base58: " << base58 << std::endl;
  std::cout << "Balance: " << std::setiosflags(std::ios::fixed)
            << std::setprecision(8) << b << std::endl;
  std::cout << "Block top: " << blockHeight << std::endl;
  std::cout << "***************************************************************"
               "******************"
            << std::endl;
  std::cout << infoColor.reset();
  std::cout << "from.ip = " << from.ip << std::endl;
  std::cout << "from.port = " << from.port << std::endl;

  return 0;
}

uint64_t pack_ip_port(uint32_t ip, uint16_t port) {
  uint64_t ret = port;
  ret = ret << 32 | ip;
  return ret;
}

std::pair<uint32_t, uint16_t> unpack_ip_port(uint64_t ip_and_port) {
  uint64_t tmp = ip_and_port;
  uint32_t ip = tmp << 32 >> 32;
  uint16_t port = ip_and_port >> 32;
  return std::pair<uint32_t, uint16_t>(ip, port);
}
