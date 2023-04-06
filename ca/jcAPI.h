#ifndef _JCAPI_H_
#define _JCAPI_H_
extern "C" {
/*
          :

          :
            out_private_key:     ，    (     )，         ,      33
            out_private_key_len:     ，            ，
            out_public_key：    ，    (     )，         ，     67
            out_public_key_len：    ，            ，
            out_bs58addr：    ，    ，         ，     35
            out_bs58addr_len：    ，            ，
                        mnemonic:    ，
           :
            0
            -1
    */
int GenWallet_(char *out_private_key, int *out_private_key_len,
               char *out_public_key, int *out_public_key_len,
               char *out_bs58addr, int *out_bs58addr_len, char *mnemonic);

/*
  :
      base64
  :
    pri:   (     )
    pri_len:
    msg：
    msg_len：
    signature_msg：    ，  base64         ，         ，     90
    out_len：      ，            ，
   :
    0
    -1
*/

int KeyFromPrivate_(const char *pridata, int pri_len, char *out_public_key,
                    int *out_public_key_len, char *out_bs58addr,
                    int *out_bs58addr_len, char *mnemonic);

int GenerateKeyFromMnemonic_(const char *mnemonic, char *out_private_key,
                             int *out_private_len, char *out_public_key,
                             int *out_public_key_len, char *out_bs58addr,
                             int *out_bs58addr_len);
}
#endif
