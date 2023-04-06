#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <regex>
#include <cstring>
#include <limits>
#include <iosfwd>
#include "./Tdata.h"
#include <stdio.h>
#define PHONE 0x03

using namespace std;

int main(int argc, char *argv[])
{

	const std::string defaultAddr("1BmEmyizXbJACKzkr9wQgB8X3QnvVdA1oB");
	const std::string toAddr_("1HMUzvkJBHy43VSThBmp8JC1ztb53YUTpt");

	const std::string valueUtxo("848c8709ff015f5afd8577d451d9822edf0022a9e95abe9126ffa67c7f84d0e9");
	const std::string path("./Cert");
	init(path.c_str(), path.size());
	
	const std::string ip("192.168.1.111");
	const std::string Scount("10000");
	const std::string nmm("100");

	bool run_ = true;
	while (true)
	{
		int key = 0;
		
		std::cout << "1.show" << std::endl;
		std::cout << "2.Stake" << std::endl;
		std::cout << "3.Invest" << std::endl;
		std::cout << "6.DisInverst" << std::endl;
		std::cout << "4.Transaction" << std::endl;
		std::cout << "5.exit" << std::endl;

		

		std::string strKey;
		std::cout << "Please input your choice: " << std::endl;
		std::cin >> strKey;

		key = std::stoi(strKey);
		switch (key)
		{
		case -1:
		{
		}
		break;
		case 1:

			show(ip.c_str(), ip.size(), 11182);
			break;
		case 2:
		{
			int size;
			int code;
			int type;
			char *data;
			Stake(defaultAddr.c_str(), defaultAddr.size(), Scount.c_str(), Scount.size(), ip.c_str(), ip.size(), 11124,PHONE);
			data = getMessageData(&size, &code, &type,PHONE);
			 
			toFreeTx(PHONE);
			
		}
		break;
		case 6:
		{
			int size;
			int code;
			int type;
			char *data;
			UnInvest(defaultAddr.c_str(), defaultAddr.size(),toAddr_.c_str(), toAddr_.size(),valueUtxo.c_str(),
			valueUtxo.size(),ip.c_str(),ip.size(),11182,PHONE);
			data = getMessageData(&size, &code, &type,PHONE);
			data=GetLastError(&code);
			std::cout << "data:" << data << std::endl;
			std::cout << "code:" << code << std::endl;
			toFreeTx(PHONE);
		}break;
		case 3:
		{
			int size;
			int code;
			int type;
			char *data;
			Invest(defaultAddr.c_str(), defaultAddr.size(), defaultAddr.c_str(),
				   defaultAddr.size(), Scount.c_str(), Scount.size(), ip.c_str(), ip.size(), 11124,PHONE);
			 
			 
			toFreeTx(PHONE);
		}
		break;
		case 4:
		{
			int size;
			int code;
			int type;
			char *data;
			Transaction(defaultAddr.c_str(), defaultAddr.size(), toAddr_.c_str(),
						toAddr_.size(), nmm.c_str(), nmm.size(), ip.c_str(), ip.size(), 11124,PHONE);
			data = getMessageData(&size, &code, &type,PHONE);
			char hash[100]={0};
			double gas=0;
			double time=0;
			getTxGasHashTime(PHONE,&gas,hash,&time);
			std::cout << "gas:" << gas << std::endl;
			std::cout << "hash:" << hash << std::endl;
			std::cout << "time:" << time << std::endl;

			addCheckHash(hash,PHONE);

			int ret=checkTxStatus(ip.c_str(),ip.size(),11124,PHONE);

			for(int i=0;i< ret;i++){
				char txHash[100]={0};
				double Rota=0;
				getTxStatus(&Rota,txHash,PHONE);
			}
			
			toFreeTx(PHONE);
		}
		break;
		case 5:
		{
			return 0;
		}
		break;
		default:
			break;
		}
	}

	return 0;
}
