# Abort

This SDK is used for dropshipping transactions


# Initialization

Account initialization is performed before using the SDK, which only needs to be done once, without repeated initialization.
API：
```cpp
    /**
     * @brief init initial
     * @param path private key path
     * @param size_path path character length
     */
    void init(const char *path, int size_path);
```

## Transaction process

0. Before making any trades, make sure that the init function is called for initialization.

1. Call the transaction interface (such as transaction, pledge, unpledge, investment, uninvestment, application, etc.).

2. Call GetLastError() to confirm whether the SDK has errors.

3. Call getMessageData to confirm whether the transaction is successful.

4. Call getTxGasHashTime() to get transaction information.

PS: For the relevant call interface, please refer to the description in the Tdata_t.h file.

## Confirm whether the transaction is on the chain

Confirm whether the transaction is on the chain through a byzantine inquiry.

When the confirmation request is issued, multiple nodes will query to determine whether the on-chain is successful, and when the success ratio is greater than 75%, it will be deemed to be on the chain.

The request does not need to be called frequently, and can be queried 10-30 seconds after the transaction is initiated.

The process is as follows:

1. Call addCheckHash() to add the transaction to the query list.

2. Call checkTxStatus() to request the node to query whether the transaction is on the chain.

3. Call GetLastError() to confirm whether the SDK has an error.

4. Call getTxStatus() to get the query result and on-chain rate.

PS: For the relevant call interface, please refer to the description in the Tdata_t.h file.

# About tx_id

tx_id is the ID used to identify each transaction, and tx_id is the ID maintained by the caller.

For each transaction, the tx_id is the same, obtain transaction information through tx_id and determine whether the transaction is on the chain.

The toFreeTx function should be used to free the tx_id after each transaction process is completed.

