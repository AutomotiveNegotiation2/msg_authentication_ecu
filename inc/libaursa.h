// libaursa.h

#ifndef _LIBAURSA_H_
#define _LIBAURSA_H_

#include <stdint.h>
#include "aursatype.h"


/*************
 User I/F
 ************/
#ifdef __cplusplus
extern "C" {
#endif
	
	
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[5];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */
}
sha1_context;

typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[8];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */

    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */
    int is224;                  /*!< 0 => SHA-256, else SHA-224 */
}
sha2_context;

AURSARET AURSA_oaep_encrypt(void* my_pub, void* input, uint32_t ilen, void* output );
size_t   AURSA_oaep_decrypt(void* my_prv, void* input, void* output, size_t olen );
AURSARET AURSA_pkcs1_sign_sha1(void* my_prv, void* output, unsigned char* sa1sum);
AURSARET AURSA_pkcs1_verify_sha1(void* my_pub, void* signtext, unsigned char* sa1sum);
AURSARET AURSA_pkcs1_sign_sha256(void* my_prv, void* output, unsigned char* sha2sum);
AURSARET AURSA_pkcs1_verify_sha256(void* my_pub, void* signtext, unsigned char* sha2sum);
AURSARET (*AURSA_pkcs_sign)(void* my_prv, void* output, unsigned char* md_sum);
AURSARET (*AURSA_pkcs_verify)(void* my_pub, void* signtext, unsigned char* md_sum);
void sha_starts(void*, uint8_t);
void sha_update(void*, void*, size_t, uint8_t);
void sha_finish(void*, void*, uint8_t);
void sha(void*, size_t, void*, uint8_t);
void sha2_mac_testing(uint8_t* buff, uint16_t buf_len, uint8_t hmac_idx);
uint8_t sha2_Hmac_analysis(uint8_t* buff, uint16_t buf_len, unsigned char* sha2result, uint8_t hmac_idx);

#ifdef __cplusplus
}
#endif

#endif
