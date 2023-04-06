#ifndef UENC_NET_NETAPI_H_
#define UENC_NET_NETAPI_H_

#include "message_queue.h"
#include "../utils/MagicSingleton.h"
#include "connect.h"
#include <tuple>
#include <map>
#include <mutex>
#include <queue>






void SendMessage(const std::string &msg_data, const std::string &msg_type,std::string &outdata);



struct ReturnData{
        int TxID=0;
        std::string msg="";
        std::string hash="";
        uint64_t time=0;
        int ErrorCode=0;
        int transactionType=0;
        int size=0;
        uint64_t Gas=0;
        std::string read_data_="";
        net netWork;

        std::vector<std::string> checkHash;
        std::queue<std::pair<std::string,double>> checkRet;

        double CaptureTheInvestment=0;
    


         
        std::vector<std::string> from_Addr;
        std::string str_ToAddr;
        std::string str_Amt;
        std::string str_utxo;
        uint64_t cur_time;
        uint32_t nContractType;
    };


class  Recver
{
public:
    Recver(){}
    ~Recver()
    {
       

    }

    

  

    bool ReadData(int Tx_ID);
	 
    
     
    void set_accountpath(const char *path);
    std::string get_accountpath();
    void set_configpath(const std::string &path);
    std::string get_configpath();


   
    std::tuple<char * ,int,int ,int> getData(int Tx_id);
    void setData(int Tx_id,const std::string & data,int code,int type);

    void setGasHashTime(int Tx_id,uint64_t gas,const std::string & hash,uint64_t time);

    void getGasHashTime(int Tx_id,double * gas,char * hash,double * time);


    ReturnData * getCodeData(int Tx_id);
    ReturnData * newCodeData(int Tx_id);
    void freeCodeData(int Tx_id);

    bool connect(int Tx_id,const std::string & ip,int port);

    void close(int Tx_id);

private:
    std::string  account_path = "./cert/";
    std::string  config_path  = "./config.json";
    
    
    std::map<int,ReturnData*> reData;
    std::mutex mutex_;
};



#endif
