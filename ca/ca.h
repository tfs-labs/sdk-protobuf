#ifndef TFS_CA_H
#define TFS_CA_H

#include "proto/ca_protomsg.pb.h"
#include "proto/sdk.pb.h"
#include "proto/transaction.pb.h"
#include <iostream>
#include <shared_mutex>
#include <thread>

extern "C" {

void InitStart();

bool InitAccount(const char *path, int path_len);

void handle_SetdefaultAccount();

typedef int (*txdata_callback)(const char *, int, int);
typedef void (*txgas_callback)(int);

void set_phonegasptr(txgas_callback gasback_ptr);

bool require_balance_height(int tx_id);

bool handle_transaction(const char *FromAddr, int fromlen, const char *ToAddr,
                        int tolen, const char *Amt, int amtlen, int tx_id);

bool handle_stake(const char *FromAddr, int fromlen, const char *StakeFee,
                  int amtlen, int tx_id);

bool handle_unstake(const char *FromAddr, int fromlen, const char *UtxoHash,
                    int hashlen, int tx_id);

bool handle_invest(const char *FromAddr, int fromlen, const char *ToAddr,
                   int tolen, const char *Amt, int amtlen, int tx_id);

bool handle_disinvest(const char *FromAddr, int fromlen, const char *ToAddr,
                      int tolen, const char *UtxoHash, int hashlen, int tx_id);

bool handle_bonus(const char *FromAddr, int fromlen, int tx_id);

void handle_AccountManger();

bool handle_getTxStatus(int tx_id);

bool handle_CaptureTheInvestment(const char *addr, int tx_id);

void gen_key();

void handle_export_private_key();
}

#endif
