// lib_ausec.h
#ifndef _LIB_AUSEC_H_
#define _LIB_AUSEC_H_

#include <stdint.h>


#define	MIN(x,y)		(x)>(y)?(y):(x)
#define MAX(x,y)		(x)>(y)?(x):(y)
#define FILE_BUFFER_SZ		2
#define PRIVATE_KEY_SZ		32	
#define PUBLIC_KEY_SZ		64
#define SIGNATURE_SZ		64
#define MSGDIGEST_SZ		32	
#define SHA256_IBLOCK_SIZE	64   // input block size in bytes
#define SHA256_OUTPUT_SIZE	32   // output size in bytes
#define HASH_SIZE_SHA256	32
#define CMAC_BLOCK_SIZE		16
#define CMAC_LAST_INDEX		(CMAC_BLOCK_SIZE - 1)



struct SEC_pack{
	uint8_t* private;
	uint8_t* public;
	uint8_t* sig;
	uint8_t* hash;
};

typedef enum _sec_return{
	SECRET_OK				= 0x00,
	SECRET_FAIL				= 0x80,
	SECRET_KEYGEN_FAIL,			//0x81
	SECRET_PUBLIC_KEY_FAIL,		//0x82
	SECRET_PRIVATE_KEY_FAIL,	//0x83
	SECRET_HASH_FAIL,			//0x84
	SECRET_SIGN_FAIL,			//0x85
	SECRET_VERIFYED_FAIL,		//0x86
	SECRET_SIZE_FAIL,			//0x87
	SECRET_ALLOC_FAIL,			//0x88
	SECRET_ALREADY_OPEN,		//0x89
	SECRET_ALREADY_CLOSED,		//0x8A
	SECRET_CMAC_COMP_FAIL		//0x8B
}sec_return_t;
#define SECRET	sec_return_t

typedef struct {
    uint32_t runninghash[8];    // intermediate hash value (H0 ~ H7)
    uint32_t totalbitlen[2];    // bit length (l) of the input message
    uint8_t buffer[64];         // buffer for unprocessed input message
    uint32_t bufferlen;         // byte length of unprocessed input message
} sha256_context_t;

/*****************
 hmacsha256
 *****************/
typedef struct {
    void *hash_context;
    void (*hash_begin)(void *);
    void (*hash_update)(void *, int, const unsigned char *);
    void (*hash_output)(void *, unsigned char *);
    int B;  // byte-length of an internal block of the underlying hash function
    int L;  // byte-length of a hashed result from the underlying hash function
            // for example: L = 32 and B = 64 for SHA-256; note that L <= B
    unsigned char *workingBufferB; // a B-byte buffer for HMAC computation
    unsigned char *workingBufferL; // a L-byte buffer for HMAC computation
}hmac_context_t;

typedef struct {
    hmac_context_t hmac_ctx;
    sha256_context_t sha256_ctx;
    unsigned char ibuf[SHA256_IBLOCK_SIZE];
    unsigned char obuf[SHA256_OUTPUT_SIZE];
} hmacsha256_context_t;



/*****************
 user I/F 
 *****************/

uint32_t  hexdump(void* msg, void* src, uint32_t len);
SECRET SEC_initialize(struct SEC_pack** ppk, 
					  void* priv, 
					  void* pub, 
					  void* sig, 
					  void* hash);
SECRET SEC_finalize(struct SEC_pack** ppk);
SECRET SEC_img_verify(void* keys);
void sha256_begin(void* _ctx);
void sha256_output(void *_ctx, uint8_t *output);
void sha256_update(void* _ctx, int ilen, const uint8_t *input);

void hmac_begin(
    const void *info_, int keylen, const unsigned char *key);
void hmac_update(
    const void *info_, int msglen, const unsigned char *msg);
void hmac_output(const void *info_, unsigned char *out);
void SEC_hmac_init(hmacsha256_context_t *);
void SEC_hmac(
    int keylen,
	const unsigned char *key,
    int msglen,
	const unsigned char *msg,
    unsigned char *out);
SECRET SEC_cmac_comp(
	const unsigned char *key, 
	const unsigned char *input, 
	int length,
    const unsigned char *mac);


#endif
