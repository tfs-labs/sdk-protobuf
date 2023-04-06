#include "net_api.h"
#include "ca_handle_event.h"
 
#include "utils/compress.h"
#include "utils/util.h"
#include "../proto/common.pb.h"
#include "dispatcher.h"
#include "../net/message_queue.h"
#include <unistd.h>
#include "common/global.h"
#include  "proto/interface.pb.h"
#include "Tdata.h"
#include "utils/ErrorMessage.h"



void SendMessage(const std::string &msg_data, const std::string &msg_type,std::string &outdata)
{
    CommonMsg msg;
    msg.set_type(msg_type);
    msg.set_version(global::kNetVersion);
    msg.set_data(msg_data);
    
    std::string data = msg.SerializeAsString();
    uint32_t len = data.size() + 3 * sizeof(int);
    
     
    uint32_t checksum = Util::adler32((const uint8_t *)data.c_str(), data.size());
    uint32_t flag = 0;
    uint32_t end_flag = 7777777;


    std::string packagedata;
    
    std::cout<<"sizeof(len) = "<<sizeof(len)<<std::endl;
    
    std::cout<<"data.size() = "<<data.size()<<std::endl;
    packagedata.append((char*)&len, sizeof(len));
    packagedata.append(data.data(),data.size());
     
     
    packagedata.append((char*)&checksum, sizeof(checksum));
    std::cout<<"sizeof(flag) = "<<sizeof(flag)<<std::endl;
    packagedata.append((char*)&flag, sizeof(flag));
    
    packagedata.append((char*)&end_flag, sizeof(end_flag));
    {
         
        outdata.clear();
        outdata = packagedata;
       
      std::cout<<"   size()= "<<packagedata.size()<<std::endl;
    }
    return ;
}




 
bool Recver::ReadData(int Tx_ID)
{

    ReturnData *data_= getCodeData(Tx_ID);
    if(data_==nullptr){
         MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,MSG("tx_id not found"));
         return false;
    }
    char buffer_cache[1024] = {0};
    uint64_t size = 1024;
   
    int ret=0;

    while (true)
    {
      ret =data_->netWork.read(buffer_cache,size);
      if(ret == 0 )
      {
        break;
        
      }else if(ret <0){
            MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,MSG(strerror(errno)));
            return false;
      }
        std::string data(buffer_cache,ret);
        data_->read_data_ += data;
    }

    std::vector<MsgData> msgs;
    MsgData msg;
  
    if(data_->read_data_.empty())
    {
        MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,MSG("not Read data"));
        return false;
    }
    size_t read_data_size = data_->read_data_.size();
    size_t curr_msg_len = 0;
    msg.Clear();
    memcpy(&curr_msg_len, data_->read_data_.data(), sizeof(MsgData::len));
     

    curr_msg_len = curr_msg_len;
    std::cout<<"curr_msg_len = "<<curr_msg_len<<std::endl;
    std::cout<<"read_data_size = "<<read_data_size<<std::endl;
    if(curr_msg_len != read_data_size -4){
        MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,MSG("data not read all"));
        return false;
    }
    msg.ip = data_->netWork.getIp();
    std::cout<<"msg.ip = "<<msg.ip<<std::endl;
    msg.port = data_->netWork.getPort();
    std::cout<<"msg.port = "<<msg.port<<std::endl;
    msg.fd = data_->netWork.getfd();
    std::cout<<" msg.fd= "<< msg.fd<<std::endl;
    msg.Tx_ID=Tx_ID;

    msg.len = curr_msg_len;
    int pos = sizeof(MsgData::len);
    msg.data = std::string(data_->read_data_.begin() + pos, data_->read_data_.begin() + (curr_msg_len - sizeof(MsgData::flag) - sizeof(MsgData::end_flag)));
    pos = pos + curr_msg_len - sizeof(MsgData::checksum) - sizeof(MsgData::flag) - sizeof(MsgData::end_flag);
    memcpy(&msg.checksum, data_->read_data_.data() + pos, 4);

    msg.checksum = msg.checksum;
    pos = pos + sizeof(MsgData::checksum);
    memcpy(&msg.flag, data_->read_data_.data() + pos, 4);
    pos = pos + sizeof(MsgData::flag);
    memcpy(&msg.end_flag, data_->read_data_.data() + pos, 4);
    pos = pos + sizeof(MsgData::flag);
    msgs.push_back(msg);
    data_->read_data_.erase(0, sizeof(MsgData::len) + curr_msg_len);

    MagicSingleton<ProtobufDispatcher>::GetInstance()->Handle(msg);

    return true;
}



    


void Recver::set_accountpath(const char *path)
{
    account_path = path;
    std::cout<<"set account_path= "<<account_path<< std::endl;
}


std::string Recver::get_accountpath()
{
    return account_path;
}

void Recver::setGasHashTime(int Tx_id,uint64_t gas,const std::string & hash,uint64_t time){
    ReturnData *data_=getCodeData(Tx_id);
    if(data_==nullptr){
        return;
    }
    data_->Gas=gas;
    data_->hash=hash;
    data_->time=time;
}

void Recver::getGasHashTime(int Tx_id,double * gas,char * hash,double * time){
    ReturnData *data_=getCodeData(Tx_id);
    if(data_==nullptr){
        return;
    }
    *gas=data_->Gas;
    memcpy(hash,data_->hash.c_str(),data_->hash.size());
    *time=data_->time;
    data_->Gas=0;
    data_->hash="";
    data_->time=0;
}

void Recver::set_configpath(const std::string &path)
{
    config_path = path;
    std::cout<<"set global::config_path= "<<config_path<<std::endl;
}

std::string Recver::get_configpath()
{
    return config_path;
}




std::tuple<char * ,int ,int ,int > Recver::getData(int Tx_id){
    ReturnData * data=getCodeData(Tx_id);
    if(data==nullptr){
        MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,MSG(" tx_id not found"));
        return std::tuple<char * ,int ,int ,int >(0,0,0,0);
    }
    std::tuple<char * ,int ,int ,int > ret((char *)data->msg.c_str(),data->size,data->ErrorCode,data->transactionType);
    data->msg="";
    data->size=0;
    data->ErrorCode=0;
    data->transactionType=0;
    return ret;
}

void Recver::setData(int Tx_id,const std::string & data_,int code,int type){
   
    auto iter=reData.find(Tx_id);
    if(iter!=reData.end()){
        iter->second->msg=data_;
        iter->second->ErrorCode=code;
        iter->second->transactionType=type;
    }else{
         MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,MSG("not found tx_id"));
    }
}


ReturnData* Recver::getCodeData(int Tx_id){
   std::unique_lock<std::mutex> lck(mutex_);
    auto iter=reData.find(Tx_id);
    if(iter!=reData.end()){
        return iter->second;
    }else{
         
    }
    return nullptr;
}

ReturnData * Recver::newCodeData(int Tx_id){
    ReturnData * data=new ReturnData;
    std::unique_lock<std::mutex> lck(mutex_);
    reData[Tx_id]=data;
    return data;
 }

 void Recver::freeCodeData(int Tx_id){
    std::unique_lock<std::mutex> lck(mutex_);
    auto iter=reData.find(Tx_id);
    if(iter!=reData.end()){
        ReturnData * data_=iter->second;
        reData.erase(Tx_id);
        delete data_;
    }else{
         
    }
 }


bool Recver::connect(int Tx_id,const std::string & ip,int port){
    ReturnData * data_=getCodeData(Tx_id);
    if(data_==nullptr){
        MagicSingleton<ErrorMessage>::GetInstance()->addError(-1,MSG(" tx_id not found"));
        return false;
    }
    if(data_->netWork.connect( ip, port)){
        return true;
    }
    return false;
    
}

void Recver::close(int Tx_id){
     ReturnData * data_=getCodeData(Tx_id);
     data_->netWork.close();
}






