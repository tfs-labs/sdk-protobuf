#ifndef _EDManager_
#define _EDManager_

#include <iostream>
#include <string>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "base58.h"
#include "hexcode.h"
#include "utils/time_util.h"
#include "MagicSingleton.h"
#include "../ca/ca_global.h"
#include "utils/pbkdf2.h"
#include "utils/json.hpp"
#include "utils/bip39.h"
#include "utils/uuid4.h"

#include "../openssl/include/openssl/evp.h"
#include "../openssl/include/openssl/ec.h"
#include "../openssl/include/openssl/pem.h"
#include "../openssl/include/openssl/core_names.h"

class ED
{
    public:
        ED();
        ED(Base58Ver ver);
        ED(const std::string &bs58Addr);
        ~ED() = default;

        bool Sign(const std::string &message, std::string &signature);
        bool Verify(const std::string &message, std::string &signature);


        void  GetPublicKey(std::string& strPub);
        void  GetPrivateKey(std::string& strpriv);
        void  GetBase58Address(std::string& base58);
        int   ImportPrivateKeyHexNewAccount(const std::string & privateKeyHex);
        int  ImportMnemonicSetKey(const std::string & privateKeyHex);

    private:
        void _GetPubStr();
        void _GetPriStr();
        void _GetBase58Addr(Base58Ver ver);

    public:
        EVP_PKEY *pkey;
        std::string pubStr;
        std::string priStr;
        std::string base58Addr;
    
};

class EDManager
{
    public:
        EDManager();
        ~EDManager() = default;

        int AddAccount(ED & ed);
        void PrintAllAccount() const;
        int DeleteAccount(const std::string& base58addr);
        void SetDefaultBase58Addr(const std::string & bs58Addr);
        std::string GetDefaultBase58Addr() const;
        int SetDefaultAccount(const std::string & bs58Addr);
        bool IsExist(const std::string & bs58Addr);
        int GetAccountListSize() const;
        int FindAccount(const std::string & bs58Addr, ED & ed);
        int GetDefaultAccount(ED & ed);
        void GetAccountList(std::vector<std::string> & base58_list);
        int SavePrivateKeyToFile(const std::string & base58Addr);

        int GetMnemonic(const std::string & bs58Addr, std::string & mnemonic);
        int ImportMnemonic(const std::string & mnemonic);
        
        int GetPrivateKeyHex(const std::string & bs58Addr, std::string & privateKeyHex);
        int ImportPrivateKeyHex(const std::string & privateKeyHex);

  


    private:
        std::string defaultBase58Addr;
        std::map<std::string /*base58addr*/,ED> _accountList;
        
        int _init();
};

int Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
               unsigned char *iv, unsigned char *ciphertext);
int Decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
               unsigned char *iv, unsigned char *plaintext);
std::string RandGenerateString(int len); 

void testED25519();
void TestED25519Time();
void testEDFunction();
void GenesisAccount();
std::string getsha256hash(const std::string & text);

bool ED25519SignMessage(const std::string &message, EVP_PKEY* pkey, std::string &signature);
bool ED25519VerifyMessage(const std::string &message, EVP_PKEY* pkey, const std::string &signature);

bool GetEDPubKeyByBytes(const std::string &pubStr, EVP_PKEY* &pKey);
void testGenerate();

#endif
