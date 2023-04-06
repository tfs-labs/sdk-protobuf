
#ifndef UENC_NET_DISPATCHER_H_
#define UENC_NET_DISPATCHER_H_

#include <string>
#include <functional>
#include <google/protobuf/message.h>

struct MsgData;

class ProtobufDispatcher {
public:
    using Message = google::protobuf::Message;
    using MessagePtr = std::shared_ptr<google::protobuf::Message>;
    using ProtoCallBack = std::function<void(const std::shared_ptr<google::protobuf::Message>&, const MsgData&)> ;
    
    void Handle(const MsgData& data);
    template <typename T>
    void RegisterCallback(std::function<void( const std::shared_ptr<T>& msg, const MsgData& from)> cb)
    {
        protocbs_[T::descriptor()->name()] = [cb](const std::shared_ptr<google::protobuf::Message>& msg, const MsgData& from) { 
            cb(std::static_pointer_cast<T>(msg), from);
        };
    }
     void registerAll();
private:
    std::map<const std::string, ProtoCallBack> protocbs_;
};
template <typename T>
bool RegisterCallback(std::function<void( const std::shared_ptr<T>& msg, const MsgData& from)> cb)
{
    MagicSingleton<ProtobufDispatcher>::GetInstance()->RegisterCallback<T>(cb);
    return true;
}
#endif