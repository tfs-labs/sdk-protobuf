#ifndef CONNECT_H_
#define CONNECT_H_


#include <sys/types.h>

#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string>
#include <errno.h>
#include <string.h>
#include "debug.h"
#include<unistd.h>  
#include<fcntl.h>

#include <sys/ioctl.h>



class net {
public:
	bool connect(const std::string& ip, int port) 
    {
        int ret = 0;
        fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        

        if (fd < 0) 
        {
           
            ::close(fd);
             return false;
        }
        std::cout<<"in connect ip = "<< ip<<std::endl;
        std::cout<<"in connect port = "<< port<<std::endl;
        addr = { 0 };
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_aton(ip.c_str(), &addr.sin_addr);
  

        ret = ::connect(fd, (struct sockaddr*)&addr, sizeof(sockaddr_in));
        fcntl(fd, F_SETFL,O_NONBLOCK);
        if (ret < 0) 
        {
            
            ::close(fd);
            return false;
        }

        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);  
        return true;
	}

    int send(const char* data, int szie) 
    {
        int ret = 0;
        ret = ::send(fd,data, szie,0);
       if (ret < 0) 
       {
          return ret;
       }
       return ret;
    }

    int read(char* data, int size) 
    {
        int ret = 0;
        ret = ::read(fd, data, size);
        if (ret == 0) 
        {
           
            return 0;
        }
        else if (ret < 0) 
        {
            if (errno == EAGAIN) 
            {
                return 0;
            }
            
            ::close(fd);
            return -1;
        }
        return ret;
    }

    void close() 
    {
        ::close(fd);
        fd = -1;
    }

    std::string getIp()
    {
        return std::string(inet_ntoa(addr.sin_addr));
    }

    int getPort()
    {
        return ntohs(addr.sin_port);
    }

    int getfd()
    {
        return fd;
    }

private:
	struct sockaddr_in addr;
    int fd;
};

#endif