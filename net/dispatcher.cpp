#include <utility>
 
#include "utils/MagicSingleton.h"
#include "utils/compress.h"
#include "message_queue.h"
#include "dispatcher.h"
#include "proto/common.pb.h"
#include "../ca/ca_handle_event.h"

using Descriptor = google::protobuf::Descriptor;
void ProtobufDispatcher::Handle(const MsgData &msg)
{
    CommonMsg common_msg;
    bool flag = common_msg.ParseFromString(msg.data);
    if (!flag)
    {
         
        return;
    }
    std::string type = common_msg.type();
    if (type.empty())
    {
         
        return;
    }
    const Descriptor *des = google::protobuf::DescriptorPool::generated_pool()->FindMessageTypeByName(type);
    if (!des)
    {
        
        return;
    }

    const Message *proto = google::protobuf::MessageFactory::generated_factory()->GetPrototype(des);
    if (!proto)
    {
        
        return;
    }
    std::string sub_serialize_msg;
    if (common_msg.compress())
    {
         Compress uncpr(std::move(common_msg.data()), common_msg.data().size() * 10);
         sub_serialize_msg = uncpr.m_raw_data;
    }
    else
    {
        sub_serialize_msg = std::move(common_msg.data());
    }
    MessagePtr sub_msg(proto->New());
    flag = sub_msg->ParseFromString(sub_serialize_msg);
    if (!flag)
    {
        
        return;
    }

    std::string name = sub_msg->GetDescriptor()->name();
    auto itr = protocbs_.find(name);
    if (itr != protocbs_.end())
    {
        
        itr->second(sub_msg, msg);
    }
    else
    {
         
        return;
    }
}




void ProtobufDispatcher::registerAll()
{
    RegisterCallback<GetSDKAck>(HandleSdkTransaction);
    RegisterCallback<TxMsgAck>(HandleTransactionTxMsgAck);
    RegisterCallback<GetBalanceAck>(HandleGetUtxo);
    RegisterCallback<IsOnChainAck>(HandleTxStatus);
     RegisterCallback< GetRestInvestAmountAck>(HandleCaptureTheInvestment);
}
