

#include "ca.h"
#include "unistd.h"
#include <array>
#include <fcntl.h>
#include <iomanip>
#include <map>
#include <random>
#include <shared_mutex>
#include <string>
#include <thread>

#include "ca_global.h"
#include "ca_handle_event.h"
#include "ca_transaction.h"
#include "ca_txhelper.h"
#include "common/global.h"
#include "proto/sdk.pb.h"
#include "utils/ErrorMessage.h"
#include "utils/MagicSingleton.h"
//#include "utils/base64_2.h"
#include "utils/bip39.h"
#include "utils/console.h"
#include "utils/hexcode.h"
#include "utils/qrcode.h"
#include "utils/string_util.h"
#include "utils/time_util.h"
#include "utils/util.h"

#include "../proto/sdk.pb.h"
#include "ca_protomsg.pb.h"
#include "utils/EDManager.h"

#include "Tdata.h"
#include "net/connect.h"
#include "net/dispatcher.h"
#include "net/net_api.h"

extern "C" {

static std::string ip;
static uint64_t port;

void InitStart() {
  MagicSingleton<ProtobufDispatcher>::GetInstance()->registerAll();
}

bool InitAccount(const char *path, int path_len) {
  std::string input_path(path, path_len);
  std::cout << "input_path = " << input_path << std::endl;
  if (!input_path.empty()) {
    MagicSingleton<Recver>::GetInstance()->set_accountpath(input_path.data());
  }
  MagicSingleton<EDManager>::GetInstance();
  return true;
}

bool handle_transaction(const char *FromAddr, int fromlen, const char *ToAddr,
                        int tolen, const char *Amt, int amtlen, int tx_id) {
  int tx_id__t = tx_id;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id__t);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return false;
  }
  std::string fromAddr(FromAddr, fromlen);
  std::string strToAddr(ToAddr, tolen);
  std::string strAmt(Amt, amtlen);
  std::vector<std::string> vecfromAddr;
  vecfromAddr.emplace_back(fromAddr);

  data_->from_Addr = vecfromAddr;

  data_->str_ToAddr = strToAddr;

  data_->str_Amt = strAmt;

  GetSDKReq sdkReq;
  sdkReq.set_version(global::kVersion);
  sdkReq.set_type(1);

  for (const auto &addr : vecfromAddr) {
    sdkReq.add_address(addr);
  }

  std::string outdata;
  SendMessage(sdkReq.SerializeAsString(), sdkReq.GetDescriptor()->name(),
              outdata);
  std::cout << "outdata = " << outdata << std::endl;

  int ret = data_->netWork.send(outdata.data(), outdata.size());
  if (ret < 0) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(ret,
                                                          MSG(strerror(errno)));
    MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
    return false;
  }

  sleep(1);

  MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  return true;
}

bool handle_stake(const char *FromAddr, int fromlen, const char *StakeFee,
                  int amtlen, int tx_id) {
  int tx_id__t = tx_id;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id__t);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return false;
  }
  std::string fromAddr(FromAddr, fromlen);
  std::string strStakeFee(StakeFee, amtlen);

  std::vector<std::string> vecfromAddr;
  vecfromAddr.emplace_back(fromAddr);

  data_->from_Addr = vecfromAddr;

  data_->str_Amt = strStakeFee;

  GetSDKReq sdkReq;
  sdkReq.set_version(global::kVersion);
  sdkReq.set_type(2);
  for (const auto &addr : vecfromAddr) {
    sdkReq.add_address(addr);
  }
  std::string outdata;
  SendMessage(sdkReq.SerializeAsString(), sdkReq.GetDescriptor()->name(),
              outdata);
  std::cout << "outdata = " << outdata << std::endl;

  int ret = data_->netWork.send(outdata.data(), outdata.size());
  if (ret < 0) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(ret,
                                                          MSG(strerror(errno)));
    MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
    return false;
  }
  sleep(1);

  MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  return true;
}

bool handle_unstake(const char *FromAddr, int fromlen, const char *UtxoHash,
                    int hashlen, int tx_id) {
  int tx_id__t = tx_id;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id__t);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return false;
  }
  std::string fromAddr(FromAddr, fromlen);
  std::string strUtxoHash(UtxoHash, hashlen);

  std::vector<std::string> vecfromAddr;
  vecfromAddr.emplace_back(fromAddr);

  data_->from_Addr = vecfromAddr;

  data_->str_utxo = strUtxoHash;

  GetSDKReq sdkReq;
  sdkReq.set_version(global::kVersion);
  sdkReq.set_type(3);

  for (auto &addr : vecfromAddr) {
    sdkReq.add_address(addr);
  }
  std::string outdata;
  SendMessage(sdkReq.SerializeAsString(), sdkReq.GetDescriptor()->name(),
              outdata);
  std::cout << "outdata = " << outdata << std::endl;

  int ret = data_->netWork.send(outdata.data(), outdata.size());
  if (ret < 0) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(ret,
                                                          MSG(strerror(errno)));
    MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
    return false;
  }
  sleep(1);

  MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  return true;
}

bool handle_invest(const char *FromAddr, int fromlen, const char *ToAddr,
                   int tolen, const char *Amt, int amtlen, int tx_id) {
  int tx_id__t = tx_id;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id__t);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return false;
  }
  std::string fromAddr(FromAddr, fromlen);
  std::string strToAddr(ToAddr, tolen);
  std::string strInvestFee(Amt, amtlen);

  std::vector<std::string> vecfromAddr;
  vecfromAddr.emplace_back(fromAddr);

  data_->from_Addr = vecfromAddr;

  data_->str_ToAddr = strToAddr;

  data_->str_Amt = strInvestFee;

  GetSDKReq sdkReq;
  sdkReq.set_version(global::kVersion);
  sdkReq.set_type(4);

  for (const auto &addr : vecfromAddr) {
    sdkReq.add_address(addr);
  }
  std::string outdata;
  SendMessage(sdkReq.SerializeAsString(), sdkReq.GetDescriptor()->name(),
              outdata);
  std::cout << "outdata = " << outdata << std::endl;

  int ret = data_->netWork.send(outdata.data(), outdata.size());
  if (ret < 0) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(ret,
                                                          MSG(strerror(errno)));
    MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
    return false;
  }
  sleep(1);

  MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  return true;
}

bool handle_disinvest(const char *FromAddr, int fromlen, const char *ToAddr,
                      int tolen, const char *UtxoHash, int hashlen, int tx_id) {
  int tx_id__t = tx_id;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id__t);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return false;
  }
  std::string fromAddr(FromAddr, fromlen);
  std::string strToAddr(ToAddr, tolen);
  std::string strUtxoHash(UtxoHash, hashlen);

  std::vector<std::string> vecfromAddr;
  vecfromAddr.emplace_back(fromAddr);

  data_->from_Addr = vecfromAddr;

  data_->str_ToAddr = strToAddr;

  data_->str_utxo = strUtxoHash;

  GetSDKReq sdkReq;
  sdkReq.set_version(global::kVersion);
  sdkReq.set_type(5);

  for (const auto &addr : vecfromAddr) {
    sdkReq.add_address(addr);
  }
  sdkReq.set_toaddr(strToAddr);
  std::string outdata;
  SendMessage(sdkReq.SerializeAsString(), sdkReq.GetDescriptor()->name(),
              outdata);
  std::cout << "outdata = " << outdata << std::endl;

  int ret = data_->netWork.send(outdata.data(), outdata.size());
  if (ret < 0) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(ret,
                                                          MSG(strerror(errno)));
    MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
    return false;
  }
  sleep(1);

  MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  return true;
}

bool handle_bonus(const char *FromAddr, int fromlen, int tx_id) {
  int tx_id__t = tx_id;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id__t);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return false;
  }
  std::string fromAddr(FromAddr, fromlen);
  std::vector<std::string> vecfromAddr;
  vecfromAddr.emplace_back(fromAddr);

  data_->from_Addr = vecfromAddr;

  GetSDKReq sdkReq;
  sdkReq.set_version(global::kVersion);
  sdkReq.set_type(6);

  for (const auto &addr : vecfromAddr) {
    sdkReq.add_address(addr);
  }
  uint64_t cur_time =
      MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
  sdkReq.set_time(cur_time);

  data_->cur_time = cur_time;
  std::string outdata;
  SendMessage(sdkReq.SerializeAsString(), sdkReq.GetDescriptor()->name(),
              outdata);
  std::cout << "outdata = " << outdata << std::endl;

  int ret = data_->netWork.send(outdata.data(), outdata.size());
  if (ret < 0) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(ret,
                                                          MSG(strerror(errno)));
    MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
    return false;
  }
  sleep(1);

  MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  return true;
}

bool require_balance_height(int tx_id) {
  int tx_id__t = tx_id;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id__t);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return false;
  }
  std::string version = global::kVersion;
  std::string defaultbase58 =
      MagicSingleton<EDManager>::GetInstance()->GetDefaultBase58Addr();
  GetBalanceReq BalanceReq;
  BalanceReq.set_version(global::kVersion);
  BalanceReq.set_address(defaultbase58);
  std::string outdata;
  SendMessage(BalanceReq.SerializeAsString(),
              BalanceReq.GetDescriptor()->name(), outdata);
  std::cout << "outdata = " << outdata << std::endl;

  int ret = data_->netWork.send(outdata.data(), outdata.size());
  if (ret < 0) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(ret,
                                                          MSG(strerror(errno)));
    MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
    return false;
  }
  usleep(30000);

  MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  return true;
}

void gen_key() {
  std::cout << "Please enter the number of accounts to be generated: ";
  int num = 0;
  std::cin >> num;
  if (num <= 0) {
    return;
  }

  std::cout << "please input Normal addr or MultiSign addr" << std::endl;
  std::cout << "0. Normal addr" << std::endl;
  std::cout << "1. MultiSign addr" << std::endl;

  int iVer = 0;
  std::cin >> iVer;

  Base58Ver ver;
  if (iVer == 0) {
    ver = Base58Ver::kBase58Ver_Normal;
  } else if (iVer == 1) {
    ver = Base58Ver::kBase58Ver_MultiSign;
  } else {
    std::cout << "error input" << std::endl;
    return;
  }

  for (int i = 0; i != num; ++i) {
    ED acc(ver);
    MagicSingleton<EDManager>::GetInstance()->AddAccount(acc);
    MagicSingleton<EDManager>::GetInstance()->SavePrivateKeyToFile(
        acc.base58Addr);
  }
}

void handle_AccountManger() {
  MagicSingleton<EDManager>::GetInstance()->PrintAllAccount();

  std::cout << std::endl << std::endl;
  while (true) {
    std::cout << "0.Exit" << std::endl;
    std::cout << "1. Set Defalut Account" << std::endl;
    std::cout << "2. Add Account" << std::endl;
    std::cout << "3. Remove " << std::endl;
    std::cout << "4. Import PrivateKey" << std::endl;
    std::cout << "5. Export PrivateKey" << std::endl;

    std::string strKey;
    std::cout << "Please input your choice: " << std::endl;
    std::cin >> strKey;
    std::regex pattern("^[0-6]$");
    if (!std::regex_match(strKey, pattern)) {
      std::cout << "Invalid input." << std::endl;
      continue;
    }
    int key = std::stoi(strKey);
    switch (key) {
    case 0:
      return;
    case 1:
      handle_SetdefaultAccount();
      break;
    case 2:
      gen_key();
      break;
    case 3: {
      std::string addr;
      std::cout << "Please enter the address you want to remove :" << std::endl;
      std::cin >> addr;

      if (MagicSingleton<EDManager>::GetInstance()->DeleteAccount(addr) != 0) {
        std::cout << "failed!" << std::endl;
      }
      break;
    }
    case 4: {
      std::string pri_key;
      std::cout << "Please input private key :" << std::endl;
      std::cin >> pri_key;

      if (MagicSingleton<EDManager>::GetInstance()->ImportPrivateKeyHex(
              pri_key) != 0) {
        std::cout << "Save PrivateKey failed!" << std::endl;
      }
      break;
    }
    case 5:
      handle_export_private_key();
      break;
    default:
      std::cout << "Invalid input." << std::endl;
      continue;
    }
  }
}

void handle_SetdefaultAccount() {
  std::string addr;
  std::cout << "Please enter the address you want to set :" << std::endl;
  std::cin >> addr;
  if (addr[0] == '3') {
    std::cout << "The Default account cannot be MultiSign Addr" << std::endl;
    return;
  }

  ED oldAccount;
  EVP_PKEY_free(oldAccount.pkey);
  if (MagicSingleton<EDManager>::GetInstance()->GetDefaultAccount(oldAccount) !=
      0) {

    return;
  }

  if (MagicSingleton<EDManager>::GetInstance()->SetDefaultAccount(addr) != 0) {

    return;
  }

  ED newAccount;
  EVP_PKEY_free(newAccount.pkey);
  if (MagicSingleton<EDManager>::GetInstance()->GetDefaultAccount(newAccount) !=
      0) {

    return;
  }

  if (!CheckBase58Addr(oldAccount.base58Addr, Base58Ver::kBase58Ver_Normal) ||
      !CheckBase58Addr(newAccount.base58Addr, Base58Ver::kBase58Ver_Normal)) {
    return;
  }
}

std::string readFileIntoString(std::string filename) {
  std::ifstream ifile(filename);
  std::ostringstream buf;
  char ch;
  while (buf && ifile.get(ch)) {
    buf.put(ch);
  }
  return buf.str();
}

void handle_export_private_key() {
  std::cout << std::endl << std::endl;

  std::string fileName("account_private_key.txt");
  std::ofstream file;
  file.open(fileName);
  std::string addr;
  std::cout << "please input the addr you want to export" << std::endl;
  std::cin >> addr;

  ED account;
  EVP_PKEY_free(account.pkey);
  MagicSingleton<EDManager>::GetInstance()->FindAccount(addr, account);

  file << "Please use Courier New font to view" << std::endl << std::endl;

  file << "Base58 addr: " << addr << std::endl;
  std::cout << "Base58 addr: " << addr << std::endl;

  char out_data[1024] = {0};
  int data_len = sizeof(out_data);
  mnemonic_from_data((const uint8_t *)account.priStr.c_str(),
                     account.priStr.size(), out_data, data_len);
  file << "Mnemonic: " << out_data << std::endl;
  std::cout << "Mnemonic: " << out_data << std::endl;

  std::string strPriHex = Str2Hex(account.priStr);
  file << "Private key: " << strPriHex << std::endl;
  std::cout << "Private key: " << strPriHex << std::endl;

  file << "QRCode:";
  std::cout << "QRCode:";

  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(5)];
  qrcode_initText(&qrcode, qrcodeData, 5, ECC_MEDIUM, strPriHex.c_str());

  file << std::endl << std::endl;
  std::cout << std::endl << std::endl;

  for (uint8_t y = 0; y < qrcode.size; y++) {
    file << "        ";
    std::cout << "        ";
    for (uint8_t x = 0; x < qrcode.size; x++) {
      file << (qrcode_getModule(&qrcode, x, y) ? "\u2588\u2588" : "  ");
      std::cout << (qrcode_getModule(&qrcode, x, y) ? "\u2588\u2588" : "  ");
    }

    file << std::endl;
    std::cout << std::endl;
  }

  file << std::endl
       << std::endl
       << std::endl
       << std::endl
       << std::endl
       << std::endl;
  std::cout << std::endl
            << std::endl
            << std::endl
            << std::endl
            << std::endl
            << std::endl;

  ca_console redColor(kConsoleColor_Red, kConsoleColor_Black, true);
  std::cout << redColor.color()
            << "You can also view above in file:" << fileName
            << " of current directory." << redColor.reset() << std::endl;
  return;
}

/**
 * @description: Registering Callbacks
 * @param {*}
 * @return {*}
 */
void RegisterCallback() {}

int checkNtpTime() {

  int64_t getNtpTime =
      MagicSingleton<TimeUtil>::GetInstance()->getNtpTimestamp();
  int64_t getLocTime =
      MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

  int64_t tmpTime = abs(getNtpTime - getLocTime);

  std::cout << "UTC Time: "
            << MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(
                   getLocTime)
            << std::endl;
  std::cout << "Ntp Time: "
            << MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(
                   getNtpTime)
            << std::endl;

  if (tmpTime <= 1000000) {

    return 0;
  } else {

    std::cout << "time check fail" << std::endl;
    return -1;
  }
}

bool handle_getTxStatus(int tx_id) {

  int tx_id__t = tx_id;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id__t);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return false;
  }

  IsOnChainReq req;
  for (auto &h : data_->checkHash) {
    req.add_txhash(h);
  }
  data_->checkHash.clear();

  req.set_version(global::kVersion);
  std::string outdata;
  SendMessage(req.SerializeAsString(), req.GetDescriptor()->name(), outdata);

  int ret = data_->netWork.send(outdata.data(), outdata.size());
  if (ret < 0) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(ret,
                                                          MSG(strerror(errno)));
    MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
    return false;
  }
  sleep(2);
  MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);

  return true;
}

bool handle_CaptureTheInvestment(const char *addr, int tx_id) {
  int tx_id__t = tx_id;
  ReturnData *data_ =
      MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id__t);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return false;
  }

  GetRestInvestAmountReq req;
  req.set_base58(std::string(addr));
  req.set_version(global::kVersion);

  std::string outdata;
  SendMessage(req.SerializeAsString(), req.GetDescriptor()->name(), outdata);

  int ret = data_->netWork.send(outdata.data(), outdata.size());
  if (ret < 0) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(ret,
                                                          MSG(strerror(errno)));
    MagicSingleton<Recver>::GetInstance()->close(tx_id__t);
    return false;
  }
  sleep(2);
  MagicSingleton<Recver>::GetInstance()->ReadData(tx_id__t);
  return true;
}


}
