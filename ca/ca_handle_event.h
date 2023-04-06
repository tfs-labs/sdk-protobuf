#ifndef _CA_HANDLE_EVENT_H_
#define _CA_HANDLE_EVENT_H_

#include "../net/message_queue.h"
#include "proto/block.pb.h"
#include "proto/interface.pb.h"
#include "proto/interface.pb.h"
#include "proto/sdk.pb.h"
#include <memory>

int HandleTxStatus(const std::shared_ptr<IsOnChainAck> &ack,
                   const MsgData &from);

int HandleCaptureTheInvestment(
    const std::shared_ptr<GetRestInvestAmountAck> &ack, const MsgData &from);

int HandleGetUtxo(const std::shared_ptr<GetBalanceAck> &ack,
                  const MsgData &from);

int SendToNode(std::shared_ptr<TxMsgReq> msg, std::pair<std::string, uint64_t>);
int HandleGetSDKInfoReq(const std::vector<std::string> &fromAddr);

int HandleSdkTransaction(const std::shared_ptr<GetSDKAck> &ack,
                         const MsgData &from);
int HandleTransactionTxMsgAck(const std::shared_ptr<TxMsgAck> &ack,
                              const MsgData &from);

int HandleTransaction(const std::shared_ptr<GetSDKAck> &ack,
                      const MsgData &from);

int HandleStakedTransaction(const std::shared_ptr<GetSDKAck> &ack,
                            const MsgData &from);

int HandleUnStakedTransaction(const std::shared_ptr<GetSDKAck> &ack,
                              const MsgData &from);

int HandleinvestTransaction(const std::shared_ptr<GetSDKAck> &ack,
                            const MsgData &from);

int HandledisinvestTransaction(const std::shared_ptr<GetSDKAck> &ack,
                               const MsgData &from);

int HandleBonusTransaction(const std::shared_ptr<GetSDKAck> &ack,
                           const MsgData &from);

#endif