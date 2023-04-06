#ifndef UENC_NET_MESSAGE_QUEUE_H
#define UENC_NET_MESSAGE_QUEUE_H

#include <stdint.h>
#include <string>
#include <mutex>
#include <condition_variable>
#include <queue>
 

struct MsgData
{
    std::string ip;
    uint16_t port;
    uint32_t fd;
     
    bool need_pack;
    std::string data;
    uint32_t len;
    uint32_t checksum;
    uint32_t flag;
    uint32_t end_flag = 7777777;
    uint32_t Tx_ID;
    MsgData()
    {
        Clear();
    }
    void Clear()
    {
         
        std::string().swap(ip);
        port = 0;
        fd = -1;
         
        need_pack = true;
        std::string().swap(data);
        len = 0;
        checksum = 0;
        flag = 0;
        end_flag = 7777777;
    }
};

#endif 