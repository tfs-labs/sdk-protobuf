#ifndef _T_DATA_H_
#define _T_DATA_H_

#define CONNECT_ERROR 0x0001
#define SEND_ERROR 0x0002
#define READ_ERROR 0x0003

extern "C" {

void init(const char *path, int size_path);

void show(const char *ip, int size_ip, int port);

bool Transaction(const char *addr, int size_addr, const char *toAddr,
                 int size_toAddr, const char *num, int num_size, const char *ip,
                 int size_ip, int port, int tx_id);

bool Stake(const char *addr, int size_addr, const char *num, int num_size,
           const char *ip, int size_ip, int port, int tx_id);

bool Unstake(const char *addr, int size_add, const char *utxoHash, int hashlen,
             const char *ip, int size_ip, int port, int tx_id);

bool UnInvest(const char *FromAddr, int fromlen, const char *ToAddr, int tolen,
              const char *UtxoHash, int hashlen, const char *ip, int size_ip,
              int port, int tx_id);

bool Invest(const char *addr, int size_addr, const char *toAddr,
            int size_toAddr, const char *num, int num_size, const char *ip,
            int size_ip, int port, int tx_id);

char *GetLastError(int *errorn);

void getTxGasHashTime(int tx_id, double *gas, char *hash, double *time);

char *getMessageData(int *size, int *type, int *Error, int tx_id);

void addCheckHash(const char *hash, int tx_id);

int checkTxStatus(const char *ip, int size_ip, int port, int tx_id);

void getTxStatus(double *Rote, char *hash, int tx_id);

double CaptureTheInvestment(const char *addr, const char *ip, int port,
                            int tx_id);

void toFreeTx(int tx_id);

/**
 * @brief Set_defaultAccount
 * @param base58
 * @param base58_len
 */
void Set_defaultAccount(const char *base58, int base58_len);

/**
 * @brief Add_Account
 * @param num
 * @param iVer
 */
void Add_Account(int num, int iVer);
/**
 * @brief Delete_Account
 * @param base58
 * @param base58_len
 * @return
 */
bool Delete_Account(const char *base58, int base58_len);
/**
 * @brief Import_Account
 * @param pri_key
 * @param pri_key_len
 * @return
 */
bool Import_Account(const char *pri_key, int pri_key_len);
/**
 * @brief Export_private_key
 * @param base58
 * @param base58_len
 * @param mnemonic
 * @param out_private_key
 * @param out_private_len
 * @param out_public_key
 * @param out_public_key_len
 */
void Export_private_key(const char *base58, int base58_len, char *mnemonic,
                        char *out_private_key, int *out_private_len,
                        char *out_public_key, int *out_public_key_len);
}
#endif
