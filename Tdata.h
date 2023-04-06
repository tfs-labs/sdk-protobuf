#ifndef _T_DATA_H_
#define _T_DATA_H_

#define CONNECT_ERROR 0x0001
#define SEND_ERROR 0x0002
#define READ_ERROR 0x0003

extern "C"
{

    /**
     * @brief init      
     * @param path      The private key path
     * @param size_path 
     */
    void init(const char *path, int size_path);


    /**
     * @brief Transaction   
     * @param addr          The address from which the transaction originated
     * @param size_addr     
     * @param toAddr        The address of the recipient of the transaction
     * @param size_toAddr   
     * @param num           Transaction amount
     * @param num_size      
     * @param ip            The IP address of the dropshipping node
     * @param size_ip       
     * @param port          prot
     * @param tx_id         
     * @return              Success returns true  Failure returns false
     */
    bool Transaction(const char *addr, int size_addr, const char *toAddr, int size_toAddr,
                     const char *num, int num_size,
                     const char *ip, int size_ip, int port,int tx_id);


    /**
     * @brief Stake         
     * @param addr          The address to be staked
     * @param size_addr     
     * @param num           Staked amount
     * @param num_size      
     * @param ip            The IP address of the dropshipping node
     * @param size_ip       
     * @param port          
     * @param tx_id         
     * @return              Success returns true  Failure returns false
     */
    bool Stake(const char *addr,int size_addr,
                        const char *num, int num_size, 
                        const char *ip, int size_ip, int port,int tx_id);


    /**
      * @brief Unstake      
      * @param addr         The address to unstake
      * @param size_add     
      * @param utxoHash     utxoHash
      * @param hashlen      
      * @param ip           The IP address of the dropshipping node
      * @param size_ip      
      * @param port         
      * @param tx_id        
      * @return              Success returns true  Failure returns false
      */
     bool Unstake(const char * addr,int size_add,
    const char * utxoHash,int hashlen,
    const char *ip, int size_ip, int port,int tx_id);


     /**
     * @brief UnInvest      Solution investment
     * @param FromAddr      The address at which the investment originated
     * @param fromlen       
     * @param ToAddr        The address of the released investment
     * @param tole          
     * @param UtxoHash      UtxoHash
     * @param hashlen       
     * @param ip            The IP address of the dropshipping node
     * @param size_ip       
     * @param port          
     * @param tx_i
     * @return              Success returns true  Failure returns false
     */
    bool UnInvest(const char *FromAddr,int fromlen,
                      const char *ToAddr, int tolen,
                      const char * UtxoHash,int hashlen,
                      const char *ip, int size_ip, int port,int tx_id);
    /**
     * @brief Invest        investment
     * @param addr          The address from which the investment originated
     * @param size_addr     
     * @param toAddr        The address of the invested
     * @param size_toAddr   
     * @param num           Investment amount
     * @param num_size      
     * @param ip            The IP address of the dropshipping node
     * @param size_ip       
     * @param port          
     * @param tx_id
     * @return              Success returns true  Failure returns false
     */
    bool Invest(const char *addr, int size_addr, const char *toAddr, int size_toAddr,
                const char *num, int num_size,
                const char *ip, int size_ip, int port,int tx_id);
    /**
     * @brief GetLastError  Get error information
     * @param errorn         Outgoing parameter: Error number (negative)
     * @return              Error message (string type)
     */
    char * GetLastError(int * errorn);

    /**
     * @brief getTxGasHashTime    Get the transaction hash time
     * @param tx_id
     * @param gas                 Outgoing parameters: gas fee
     * @param hash                Outgoing parameter: hash
     * @param time                Outgoing parameters: The time obtained
     */
    void getTxGasHashTime(int tx_id,double * gas,char * hash,double * time);
    
    /**
     * @brief getMessageData
     * @param size      Error message length
     * @param type      Outgoing Parameter: Type (Deprecated)
     * @param Error     Outgoing parameter: Error number
     * @param tx_id
     * @return   Specific error description (usually empty)
     */
    char *getMessageData(int *size, int *type, int *Error,int tx_id);

    /**
     * @brief addCheckHash  Add the hash of the transaction you want to confirm to be on the chain to the query list
     * @param hash          The hash to detect
     * @param tx_id 
     */
    void addCheckHash(const char * hash,int tx_id);

    /**
     * @brief checkTxStatus   Byzantium checks whether a transaction is on the chain
     * @param ip              
     * @param size_ip         
     * @param port            
     * @param tx_id           
     * @return
     */
    int checkTxStatus(const char *ip, int size_ip, int port,int tx_id);

    /**
     * @brief getTxStatus     Get the results of a Byzantine query
     * @param Rote            On-chain ratio
     * @param hash            tx hash
     * @param tx_id
     */
    void getTxStatus(double * Rote ,char *hash,int tx_id);

    /**
     * @brief CaptureTheInvestment   Get the remaining investable amount
     * @param addr                   Lookup address 
     * @param ip                      
     * @param port                    
     * @param tx_id
     * @return
     */
    double CaptureTheInvestment(const char * addr,const char * ip,int port,int tx_id);


    /**
     * @brief toFreeTx     free tx_id
     * @param tx_id
     */
    void toFreeTx(int tx_id);
    

    /**
     * @brief Set_defaultAccount
     * @param base58                
     * @param base58_len            
     */
    void Set_defaultAccount(const char *base58, int base58_len);


    /**
     * @brief Add_Account     
     * @param num             quantity
     * @param iVer            version
     */
    void Add_Account(int num, int iVer);


    /**
     * @brief Delete_Account    
     * @param base58            
     * @param base58_len        
     * @return
     */
    bool Delete_Account(const char *base58, int base58_len);


    /**
     * @brief Import_Account      
     * @param pri_key             
     * @param pri_key_len         
     * @return
     */
    bool Import_Account(const char *pri_key, int pri_key_len);


    /**
     * @brief Export_private_key  
     * @param base58              base58
     * @param base58_len          base58
     * @param mnemonic            Wallet mnemonic
     * @param out_private_key     
     * @param out_private_len     
     * @param out_public_key      
     * @param out_public_key_len  
     */
    void Export_private_key(const char *base58, int base58_len,
                            char *mnemonic,
                            char *out_private_key, int *out_private_len,
                            char *out_public_key, int *out_public_key_len);
}
#endif
