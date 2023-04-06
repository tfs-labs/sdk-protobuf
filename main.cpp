#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <regex>
#include <cstring>
#include <limits>
#include <iosfwd>
#include "main.h"
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


#if 0
void GenWallet_test()
{
	const int BUFF_SIZE = 128;
	char *out_private_key = new char[BUFF_SIZE]{0};
	int *out_private_key_len = new int{BUFF_SIZE};
	char *out_public_key = new char[BUFF_SIZE]{0};
	int *out_public_key_len = new int{BUFF_SIZE};
	char *out_bs58addr = new char[BUFF_SIZE]{0};
	int *out_bs58addr_len = new int{BUFF_SIZE};
	char *out_mnemonic = new char[1024]{0};

	GenWallet_(out_private_key, out_private_key_len, out_public_key, out_public_key_len, out_bs58addr, out_bs58addr_len, out_mnemonic);
}

void KeyFromPrivate_test()
{
	const int BUFF_SIZE = 128;
	char *out_private_key = new char[BUFF_SIZE]{0};
	int *out_private_key_len = new int{BUFF_SIZE};
	char *out_public_key = new char[BUFF_SIZE]{0};
	int *out_public_key_len = new int{BUFF_SIZE};
	char *out_bs58addr = new char[BUFF_SIZE]{0};
	int *out_bs58addr_len = new int{BUFF_SIZE};
	char *out_mnemonic = new char[1024]{0};

	std::string pri_key;
	std::cout << "Please input private key :" << std::endl;
	std::cin >> pri_key;
	KeyFromPrivate_(pri_key.data(), pri_key.size(), out_public_key, out_public_key_len, out_bs58addr, out_bs58addr_len, out_mnemonic);
}

void GenerateKeyFromMnemonic__test()
{
	const int BUFF_SIZE = 128;
	char *out_private_key = new char[BUFF_SIZE]{0};
	int *out_private_key_len = new int{BUFF_SIZE};
	char *out_public_key = new char[BUFF_SIZE]{0};
	int *out_public_key_len = new int{BUFF_SIZE};
	char *out_bs58addr = new char[BUFF_SIZE]{0};
	int *out_bs58addr_len = new int{BUFF_SIZE};
	char *out_mnemonic = new char[1024]{0};
	std::string str;
	std::cin.ignore(std::numeric_limits<streamsize>::max(), '\n');
	std::getline(std::cin, str);
	GenerateKeyFromMnemonic_(str.data(), out_private_key, out_private_key_len, out_public_key, out_public_key_len, out_bs58addr, out_bs58addr_len);
}

void menu()
{

	while (true)
	{
		std::cout << std::endl
				  << std::endl;
		std::cout << "1.Transaction" << std::endl;
		std::cout << "2.Stake" << std::endl;
		std::cout << "3.Unstake" << std::endl;
		std::cout << "4.Invest" << std::endl;
		std::cout << "5.Disinvest" << std::endl;
		std::cout << "6.Bonus" << std::endl;
		 
		 
		std::cout << "9.Advanced_Menu" << std::endl;
		std::cout << "10.PrintAccountInfo" << std::endl;
		std::cout << "11.Generate wallet" << std::endl;
		std::cout << "12.Generate Key From Mnemonic" << std::endl;
		std::cout << "13.Key From Private" << std::endl;
		std::cout << "14.Gen Sign" << std::endl;
		std::cout << "15.connect node" << std::endl;
		std::cout << "0.Exit" << std::endl;

		std::string strKey;
		std::cout << "Please input your choice: " << std::endl;
		std::cin >> strKey;
		std::regex pattern("^[0-9]|([1][0-9])$");
		if (!std::regex_match(strKey, pattern))
		{
			std::cout << "Invalid input." << std::endl;
			continue;
		}
		int key = std::stoi(strKey);
		switch (key)
		{
		case 0:
			std::cout << "Exiting, bye!" << std::endl;
			return;
		case 1:
		{
			std::string strFromAddr;
			std::cout << "input FromAddr :" << std::endl;
			std::cin >> strFromAddr;
			if (!CheckBase58Addr(strFromAddr))
			{
				std::cout << "Input addr error!" << std::endl;
				return;
			}

			std::string strToAddr;
			std::cout << "input ToAddr :" << std::endl;
			std::cin >> strToAddr;
			if (!CheckBase58Addr(strToAddr))
			{
				std::cout << "input ToAddr error!" << std::endl;
				return;
			}

			std::string strAmt;
			std::cout << "input amount :" << std::endl;
			std::cin >> strAmt;
			std::regex pattern("^\\d+(\\.\\d+)?$");

			handle_transaction(strFromAddr.data(), strFromAddr.size(), strToAddr.data(), strToAddr.size(), strAmt.data(), strAmt.size());
			break;
		}
		case 2:
		{
			std::cout << std::endl
					  << std::endl;

			std::string strFromAddr;
			std::cout << "input FromAddr :" << std::endl;
			std::cin >> strFromAddr;
			if (!CheckBase58Addr(strFromAddr))
			{
				std::cout << "Input addr error!" << std::endl;
				return;
			}

			std::string strStakeFee;
			std::cout << "Please enter the amount to stake:" << std::endl;
			std::cin >> strStakeFee;
			std::regex pattern("^\\d+(\\.\\d+)?$");
			if (!std::regex_match(strStakeFee, pattern))
			{
				std::cout << "input stake amount error " << std::endl;
				return;
			}

			handle_stake(strFromAddr.data(), strFromAddr.size(), strStakeFee.data(), strStakeFee.size());
			break;
		}
		case 3:
		{
			std::cout << std::endl
					  << std::endl;

			std::string strFromAddr;
			std::cout << "Please enter unstake addr:" << std::endl;
			std::cin >> strFromAddr;
			if (!CheckBase58Addr(strFromAddr))
			{
				std::cout << "Input addr error!" << std::endl;
				return;
			}

			std::string strUtxoHash;
			std::cout << "utxo:";
			std::cin >> strUtxoHash;

			handle_unstake(strFromAddr.data(), strFromAddr.size(), strUtxoHash.data(), strUtxoHash.size());
			break;
		}
		case 4:
		{
			std::cout << std::endl
					  << std::endl;

			std::string strFromAddr;
			std::cout << "input FromAddr :" << std::endl;
			std::cin >> strFromAddr;
			if (!CheckBase58Addr(strFromAddr))
			{
				std::cout << "Input addr error!" << std::endl;
				return;
			}

			std::string strToAddr;
			std::cout << "input ToAddr :" << std::endl;
			std::cin >> strToAddr;
			if (!CheckBase58Addr(strToAddr))
			{
				std::cout << "input ToAddr error!" << std::endl;
				return;
			}

			std::string strInvestFee;
			std::cout << "Please enter the amount to invest:" << std::endl;
			std::cin >> strInvestFee;
			std::regex pattern("^\\d+(\\.\\d+)?$");
			if (!std::regex_match(strInvestFee, pattern))
			{
				std::cout << "input stake amount error " << std::endl;
				return;
			}

			handle_invest(strFromAddr.data(), strFromAddr.size(), strToAddr.data(), strToAddr.size(), strInvestFee.data(), strInvestFee.size());
			break;
		}
		case 5:
		{
			std::cout << std::endl
					  << std::endl;

			std::string strFromAddr;
			std::cout << "Please enter your addr:" << std::endl;
			std::cin >> strFromAddr;
			if (!CheckBase58Addr(strFromAddr))
			{
				std::cout << "Input addr error!" << std::endl;
				return;
			}

			std::string strToAddr;
			std::cout << "Please enter the addr you want to divest from:" << std::endl;
			std::cin >> strToAddr;
			if (!CheckBase58Addr(strToAddr))
			{
				std::cout << "Input addr error!" << std::endl;
				return;
			}

			std::string strUtxoHash;
			std::cout << "Please enter the utxo you want to divest:";
			std::cin >> strUtxoHash;

			handle_disinvest(strFromAddr.data(), strFromAddr.size(), strToAddr.data(), strToAddr.size(), strUtxoHash.data(), strUtxoHash.size());
			break;
		}
		case 6:
		{
			std::cout << std::endl
					  << std::endl;

			std::string strFromAddr;
			std::cout << "Please enter your addr:" << std::endl;
			std::cin >> strFromAddr;
			if (!CheckBase58Addr(strFromAddr))
			{
				std::cout << "Input addr error!" << std::endl;
				return;
			}

			handle_bonus(strFromAddr.data(), strFromAddr.size());
			break;
		}
		case 9:
			menu_advanced();
			break;
		case 10:
		{
			require_balance_height();
			break;
		}
		case 11:
		{
			GenWallet_test();
			break;
		}
		case 12:
		{
			GenerateKeyFromMnemonic__test();
			break;
		}
		case 13:
		{
			KeyFromPrivate_test();
			break;
		}
		case 14:
		{
			//GenSign__test();
			break;
		}
		case 15:
		{
			uint32_t port = 11124;
			std::string ip = "192.168.1.142";
			Require_config_random_node(ip.data(), ip.size(), port);

			break;
		}

		case 19:
		{
			std::cout << std::endl
					  << std::endl;

			std::string addr;
			std::cout << "Please enter your addr:" << std::endl;
			std::cin >> addr;
			 
			 
			 

			const int BUFF_SIZE = 128;
			char *out_private_key = new char[BUFF_SIZE]{0};
			int *out_private_key_len = new int{BUFF_SIZE};
			char *out_public_key = new char[BUFF_SIZE]{0};
			int *out_public_key_len = new int{BUFF_SIZE};
			char *out_mnemonic = new char[1024]{0};
			Export_private_key(addr.data(), addr.size(), out_mnemonic,
							   out_private_key, out_private_key_len,
							   out_public_key, out_public_key_len);
			std::cout << "main-->Mnemonic" << out_mnemonic << std::endl;
			std::cout << "main-->PriHex" << out_private_key << std::endl;
			std::cout << "main-->PubHex" << out_public_key << std::endl;
			break;
		}

		default:
			std::cout << "Invalid input." << std::endl;
			continue;
		}
		sleep(1);
	}
}

#endif