#include "Tdata.h"
#include "utils/debug.h"

#include "ca/ca_global.h"
#include "ca/ca_handle_event.h"
#include "ca/ca_transaction.h"
#include "ca/ca_txhelper.h"
#include "common/global.h"
#include "proto/sdk.pb.h"
#include "utils/MagicSingleton.h"
#include "utils/bip39.h"
#include "utils/console.h"
#include "utils/hexcode.h"
#include "utils/qrcode.h"
#include "utils/string_util.h"
#include "utils/time_util.h"
#include "utils/util.h"


#include "ca_protomsg.pb.h"
#include "proto/sdk.pb.h"
#include "utils/EDManager.h"


#include "net/connect.h"
#include "net/dispatcher.h"
#include "net/net_api.h"
#include "utils/ErrorMessage.h"

#define PHONE_ 0x002
#define SHOW_ -0x003

#include "utils/MagicSingleton.h"

#include "utils/base58.h"

#include "net/debug.h"

#include "utils/EDManager.h"

#include "ca/ca.h"
#include "ca/jcAPI.h"

thread_local std::pair<int, std::string> er_msg;

extern "C" {

void init(const char *path, int size) {
  InitStart();
  std::string path_(path, size);
  InitAccount(path_.data(), path_.size());
}

void show(const char *ip, int size_ip, int port) {
  std::string ip_(ip, size_ip);
  ReturnData *data = MagicSingleton<Recver>::GetInstance()->newCodeData(SHOW_);
  data->netWork.connect(ip_, port);
  require_balance_height(SHOW_);
  MagicSingleton<Recver>::GetInstance()->close(SHOW_);
  MagicSingleton<Recver>::GetInstance()->freeCodeData(SHOW_);
}

bool Transaction(const char *addr, int size_addr, const char *toAddr,
                 int size_toAddr, const char *num, int num_size, const char *ip,
                 int size_ip, int port, int tx_id) {

  infoL("ip:" << ip);
  infoL("addr" << addr);
  infoL("toAddr" << toAddr);
  if (!CheckBase58Addr(addr)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -7, MSG(std::string(addr, size_addr) + "base58 error"));
    return false;
  }
  MagicSingleton<Recver>::GetInstance()->newCodeData(tx_id);
  if (!MagicSingleton<Recver>::GetInstance()->connect(tx_id, ip, port)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,
                                                          MSG(strerror(errno)));
    return false;
  }
  int ret = handle_transaction(addr, size_addr, toAddr, size_toAddr, num,
                               num_size, tx_id);
  MagicSingleton<Recver>::GetInstance()->close(tx_id);
  if (ret == false) {
    return false;
  }
  return true;
}

bool Stake(const char *addr, int size_addr, const char *num, int num_size,
           const char *ip, int size_ip, int port, int tx_id) {

  if (!CheckBase58Addr(addr)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -7, MSG(std::string(addr, size_addr) + "base58 error"));
    return false;
  }
  MagicSingleton<Recver>::GetInstance()->newCodeData(tx_id);
  if (!MagicSingleton<Recver>::GetInstance()->connect(tx_id, ip, port)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,
                                                          MSG(strerror(errno)));
    return false;
  }
  bool ret = handle_stake(addr, size_addr, num, num_size, tx_id);
  MagicSingleton<Recver>::GetInstance()->close(tx_id);
  if (ret == false) {

    return false;
  }
  return true;
}

bool Unstake(const char *addr, int size_addr, const char *utxoHash, int hashlen,
             const char *ip, int size_ip, int port, int tx_id) {
  if (!CheckBase58Addr(addr)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -7, MSG(std::string(addr, size_addr) + "base58 error"));
    return false;
  }
  MagicSingleton<Recver>::GetInstance()->newCodeData(tx_id);
  if (!MagicSingleton<Recver>::GetInstance()->connect(tx_id, ip, port)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,
                                                          MSG(strerror(errno)));
    return false;
  }
  bool ret = handle_unstake(addr, size_addr, utxoHash, hashlen, tx_id);
  MagicSingleton<Recver>::GetInstance()->close(tx_id);
  if (ret == false) {
    return false;
  }
  return true;
}

bool UnInvest(const char *FromAddr, int fromlen, const char *ToAddr, int tolen,
              const char *UtxoHash, int hashlen, const char *ip, int size_ip,
              int port, int tx_id) {
  if (!CheckBase58Addr(FromAddr)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -7, MSG(std::string(FromAddr, fromlen) + ":base58 error"));
    return false;
  }
  if (!CheckBase58Addr(ToAddr)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -7, MSG(std::string(ToAddr, tolen) + ":base58 error"));
    return false;
  }
  MagicSingleton<Recver>::GetInstance()->newCodeData(tx_id);
  if (!MagicSingleton<Recver>::GetInstance()->connect(tx_id, ip, port)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,
                                                          MSG(strerror(errno)));
    return false;
  }
  bool ret = handle_disinvest(FromAddr, fromlen, ToAddr, tolen, UtxoHash,
                              hashlen, tx_id);
  MagicSingleton<Recver>::GetInstance()->close(tx_id);
  if (ret == false) {
    return false;
  }
  return true;
}

bool Invest(const char *addr, int size_addr, const char *toAddr,
            int size_toAddr, const char *num, int num_size, const char *ip,
            int size_ip, int port, int tx_id) {
  if (!CheckBase58Addr(addr)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -7, MSG(std::string(addr, size_addr) + ":base58 error"));
    return false;
  }
  MagicSingleton<Recver>::GetInstance()->newCodeData(tx_id);
  if (!MagicSingleton<Recver>::GetInstance()->connect(tx_id, ip, port)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,
                                                          MSG(strerror(errno)));
    return false;
  }
  bool ret =
      handle_invest(addr, size_addr, toAddr, size_toAddr, num, num_size, tx_id);
  MagicSingleton<Recver>::GetInstance()->close(tx_id);
  if (ret == false) {
    return false;
  }

  return true;
}

char *getMessageData(int *size, int *type, int *Error, int tx_id) {
  std::tuple<char *, int, int, int> ret =
      MagicSingleton<Recver>::GetInstance()->getData(tx_id);
  *size = std::get<1>(ret);
  *Error = std::get<2>(ret);
  *type = std::get<3>(ret);
  char *data_p = std::get<0>(ret);
  std::cout << "data:" << data_p << std::endl;
  std::cout << "size:" << *size << std::endl;
  std::cout << "type:" << *type << std::endl;
  std::cout << "Error:" << *Error << std::endl;
  std::cout << std::endl;
  return data_p;
}

void getTxGasHashTime(int tx_id, double *gas, char *hash, double *time) {
  return MagicSingleton<Recver>::GetInstance()->getGasHashTime(tx_id, gas, hash,
                                                               time);
}

void toFreeTx(int tx_id) {
  MagicSingleton<Recver>::GetInstance()->freeCodeData(tx_id);
}

char *GetLastError(int *errorn) {
  er_msg = MagicSingleton<ErrorMessage>::GetInstance()->getLastError();
  *errorn = er_msg.first;
  return (char *)er_msg.second.c_str();
}

// void Set_defaultAccount(const std::string &addr)
void Set_defaultAccount(const char *base58, int base58_len) {
  std::string addr(base58, base58_len);
  if (addr[0] == '3') {
    std::cout << "The Default account cannot be MultiSign Addr" << std::endl;
    return;
  }

  ED oldAccount;
  EVP_PKEY_free(oldAccount.pkey);
  if (MagicSingleton<EDManager>::GetInstance()->GetDefaultAccount(oldAccount) !=
      0) {
    // ERRORLOG("not found DefaultKeyBs58Addr  in the _accountList");
    return;
  }

  if (MagicSingleton<EDManager>::GetInstance()->SetDefaultAccount(addr) != 0) {
    return;
  }

  ED newAccount;
  EVP_PKEY_free(newAccount.pkey);
  if (MagicSingleton<EDManager>::GetInstance()->GetDefaultAccount(newAccount) !=
      0) {
    // ERRORLOG("not found DefaultKeyBs58Addr  in the _accountList");
    return;
  }

  if (!CheckBase58Addr(oldAccount.base58Addr, Base58Ver::kBase58Ver_Normal) ||
      !CheckBase58Addr(newAccount.base58Addr, Base58Ver::kBase58Ver_Normal)) {
    return;
  }
}

void Add_Account(int num, int iVer) {
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

bool Delete_Account(const char *base58, int base58_len)
// bool Delete_Account(const std::string &addr)
{
  std::string addr(base58, base58_len);
  if (MagicSingleton<EDManager>::GetInstance()->DeleteAccount(addr) != 0) {
    return false;
  }
  return true;
}

// bool  Import_Account(const std::string &pri_key)
bool Import_Account(const char *pri_key, int pri_key_len) {
  std::string strpri_key(pri_key, pri_key_len);
  if (MagicSingleton<EDManager>::GetInstance()->ImportPrivateKeyHex(
          strpri_key) != 0) {
    return false;
  }
  return true;
}

// void Export_private_key(const std::string &addr,std::string
// &Mnemonic,std::string &PriHex,std::string &PubHex)
void Export_private_key(const char *base58, int base58_len, char *mnemonic,
                        char *out_private_key, int *out_private_len,
                        char *out_public_key, int *out_public_key_len) {
  std::string addr(base58, base58_len);
  ED account;
  EVP_PKEY_free(account.pkey);
  MagicSingleton<EDManager>::GetInstance()->FindAccount(addr, account);

  char out_data[1024] = {0};
  int data_len = sizeof(out_data);
  mnemonic_from_data((const uint8_t *)account.priStr.c_str(),
                     account.priStr.size(), out_data, data_len);
  memcpy(mnemonic, out_data, strlen(out_data));

  std::string Mnemonic = std::string(out_data, strlen(out_data));
  std::cout << "Mnemonic: " << out_data << std::endl;
  std::cout << "Mnemonic: " << Mnemonic << std::endl;

  std::string PriHex = Str2Hex(account.priStr);
  memcpy(out_private_key, PriHex.data(), PriHex.size());
  *out_private_len = PriHex.size();

  std::string PubHex = Str2Hex(account.pubStr);
  memcpy(out_public_key, PubHex.data(), PubHex.size());
  *out_public_key_len = PubHex.size();

  std::cout << "Private key: " << PriHex << std::endl;
  std::cout << "Private key: " << PubHex << std::endl;
  return;
}

void addCheckHash(const char *hash, int tx_id) {
  ReturnData *data_ = MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id);

  if (data_ == nullptr) {
    data_ = MagicSingleton<Recver>::GetInstance()->newCodeData(tx_id);
  }
  data_->checkHash.push_back(std::string(hash));
}

int checkTxStatus(const char *ip, int size_ip, int port, int tx_id) {
  if (!MagicSingleton<Recver>::GetInstance()->connect(tx_id, ip, port)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,
                                                          MSG(strerror(errno)));
    return -1;
  }
  bool ret = handle_getTxStatus(tx_id);

  MagicSingleton<Recver>::GetInstance()->close(tx_id);
  ReturnData *data_ = MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG("tx_id not found"));
    return -1;
  }
  return data_->checkRet.size();
}

void getTxStatus(double *Rote, char *desc, int tx_id) {
  ReturnData *data_ = MagicSingleton<Recver>::GetInstance()->getCodeData(tx_id);
  if (data_ == nullptr) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -1, MSG(" tx_id not found"));
    return;
  }
  if (data_->checkRet.size() > 0) {
    auto SUC = data_->checkRet.front();
    std::string hash = SUC.first;
    *Rote = SUC.second;
    data_->checkRet.pop();
    memcpy(desc, hash.c_str(), hash.size());
  }
}

double CaptureTheInvestment(const char *addr, const char *ip, int port,
                            int tx_id) {
  if (!CheckBase58Addr(addr)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(
        -7, MSG(std::string(addr) + ":base58 error"));
    return false;
  }
  ReturnData *data_ = MagicSingleton<Recver>::GetInstance()->newCodeData(tx_id);
  if (!MagicSingleton<Recver>::GetInstance()->connect(tx_id, ip, port)) {
    MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,
                                                          MSG(strerror(errno)));
    return false;
  }
  bool ret = handle_CaptureTheInvestment(addr, tx_id);
  if (!ret) {
    return false;
  }
  return data_->CaptureTheInvestment;
}
}