#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "libaursa.h"
#include "aursatype.h"
#include <assert.h>
#include "aesconfig.h"
#include "cipher.h"

#include "./key/my_private.h"
#include "./key/my_public.h"

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <inttypes.h>
#endif

//rsa 2048
#define KEY_LEN            256 

/**
 *  
 * @brief   AES CTR 128 Enc/Dec Define
 * 
 */
#define MD_BUF_SZ          10240U //1024U
#define BLOCK_SIZE         MD_BUF_SZ
#define FIRST_LEN          16
#define SECOND_LEN         (MD_BUF_SZ - FIRST_LEN)
#define ENC_DEC_KEY_SIZE   32
#define ENC_DEC_IV_SIZE    16

/**
 *  
 * @brief   Sflash format Define
 * 
 */
#define META_INFO1         0x5A
#define META_INFO2         0x5A
#define SIG_INFO1          0x6A
#define SIG_INFO2          0x6A
#define META_RESERVED      0xAA
#define HEADER_LENGTH      16
#define MAC_SIZE	       32
#define SIGN_SIZE          256

/**
 *  
 * @brief   Secure Boot size Define
 * 
 */
#define TEST_BOOTLEN       512


#define HASH_CHECK      0
#define PARSING_TEST    1
#define UNIT_TEST       1
#define DBG_PRINT_USE   1

#define GEN_MESSAGE     1
#if GEN_MESSAGE
	#define GEN_ENCMSG         1
	#define GEN_DECMSG         0	
	#define GEN_SIGNMSG        1
    #define GEN_HMACMSG        1
	#define GEN_ENCKEY         0
	#define PARSING_ENC        1
#endif
#define FAIL            1
#define SUCCESS         0            

#if DBG_PRINT_USE
    #define dbg_printf(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
    #define dbg_printf(fmt, ...)
#endif

/**
 *  
 * @brief   AES CTR 128 Enc/Dec Buffer
 * @details Encryption Buffer
 * 
 */
uint8_t *encbuf;

/**
 *
 * @brief   AES CTR 128 Enc/Dec Buffer
 * @details Decryption Buffer
 * 
 */
uint8_t *decbuf;

/** 
 * 
 * @brief   Secure Boot
 * @details testbootimg (boot Image buffer) \n
 *          testsignimg[SIGN_SIZE] (Signature file)
*/
uint8_t *testbootimg;
uint8_t testsignimg[SIGN_SIZE] = {0,};

/** 
 * 
 * @brief   SFLASH File Format struct
 * @details Header + Body + Signature \n
 *          Header Format struct
*/
typedef struct header_format {
	uint8_t  meta_inform[2]      ;
	uint16_t header_len          ;
	uint8_t  enc_key_index       ;
	uint8_t  hmac_key_index      ;
	uint32_t firm_version        ;
	uint32_t firm_size           ;
	uint8_t  reserve_use[2]      ;
} client_header;

/** 
 * 
 * @brief   SFLASH File Format struct
 * @details Header + Body + Signature \n
 *          Body (Block Format struct)
*/
typedef struct block_format {
	uint8_t  counter_data        ;
	uint8_t  hmac_data[MAC_SIZE] ;		//H-MAC 
	uint8_t  *app_data           ;  	//Encription Data
} block_body;

/** 
 * 
 * @brief   SFLASH File Format struct
 * @details Header + Body + Signature \n
 *          Body (Body Format struct)
*/
typedef struct body_format {
	uint8_t  total_counter       ;
	block_body block_no[2]       ;
	uint8_t  *total_app_data     ;  	//Total Encription Data	
} client_body;

/**
 * 
 * @brief   SFLASH File Format struct
 * @details Header + Body + Signature \n
 *          Signature (Signature Format struct)
*/
typedef struct sign_format {
	uint8_t  _inform[2]          ;	
	uint8_t  _data[SIGN_SIZE]    ;
} client_sign;

client_header header   ;
client_body   body     ;
client_sign   signature;

/**
 * 
 * @brief   AES CTR 128 Encryption/Decryption Key
 * @details AES CTR 128 Encryption/Decryption Key Sample
*/
static unsigned char ENC_DEC_test_key[7][32] =
{
    { "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" },
    { "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
      "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" },
    { "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02"
      "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02" },
    { "\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03"
      "\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03" },
    { "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04"
      "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04" },
    { "\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05"
      "\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05" },
    { "\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06"
      "\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06" }
};

/**
 * 
 * @brief       Hex Format Display.
 * @details     Function to create image to create hex file or image to apply to code. \n
 *              uint16_t hex_printf(uint8_t* print_buf, uint16_t length_buf ,uint8_t mode)
 * @param[in]	print_buf	buffer for display
 * @param[in]	length_buf	Length of buffer for display
 * @param[in]	mode	    mode = 0(0x01, 0x02 ...), mode = 1(aa bb), mode = 2(0x01, 0x02 ... aa bb)
 * @return		number of characters for display
 * @see			
*/
uint16_t hex_printf(uint8_t* print_buf, uint16_t length_buf, uint8_t mode)
{
	uint16_t idx          = 0;
	uint16_t seperate_idx = 0;
	uint16_t return_val   = 0;


	if(mode == 0) //0x?? Hex Format(code)
	{
		dbg_printf("{\r\n    ");
		for(idx = 0,seperate_idx = 0; idx < length_buf; idx++) {
			dbg_printf("0x%02X", print_buf[idx]&0xFF);
			if(idx != length_buf -1) dbg_printf(", ");
			if(seperate_idx == 15) {
				dbg_printf("\r\n    ");
				seperate_idx = 0;
			}
			else {
				seperate_idx++;
			}
			return_val++;	
		}
		if(seperate_idx < 15) dbg_printf("\r\n};\n");
		else dbg_printf("};\r\n");
	}
	else if(mode == 1) // ?? Hex Format (Bin file)
	{
		for(idx = 0,seperate_idx = 0; idx < length_buf; idx++) {
			dbg_printf("%02X", print_buf[idx]&0xFF);
			if(idx != length_buf -1) dbg_printf(" ");	
			if(seperate_idx == 15) {
				dbg_printf("\r\n");
				seperate_idx = 0;
			}
			else {
				seperate_idx++;
			}

			return_val++;
		}
		if(seperate_idx < 15) dbg_printf("\r\n");
	}
	else //All printf
	{
		dbg_printf("{\r\n    ");
		for(idx = 0,seperate_idx = 0; idx < length_buf; idx++) {
			dbg_printf("0x%02X", print_buf[idx]&0xFF);
			if(idx != length_buf -1) dbg_printf(", ");
			if(seperate_idx == 15) {
				dbg_printf("\r\n    ");
				seperate_idx = 0;
			}
			else {						
				seperate_idx++;
			}
			return_val++;	
		}
		if(seperate_idx < 15) dbg_printf("\r\n};\n");
		else dbg_printf("};\r\n");
		for(idx = 0,seperate_idx = 0; idx < length_buf; idx++) {
			dbg_printf("%02X", print_buf[idx]&0xFF);
			if(idx != length_buf -1) dbg_printf(" ");
			if(seperate_idx == 15) {
				dbg_printf("\r\n");
				seperate_idx = 0;
			}
			else {
				seperate_idx++;
			}
		}
		if(seperate_idx < 15) dbg_printf("\r\n\n");
		else dbg_printf("\r\n");
	}

	return return_val;
}

/**
 * 
 * @brief       AES 128 CTR Encryption test.
 * @details     AES 128 CTR encryption function. IV value 16 bytest 0x00. \n
 *              int test_aes128ctr_enc(uint8_t encdec_idx)
 * @param[in]	encdec_idx	Index of AES 128 CTR encryption keys
 * @return      0: success, 1: fail
 * @see			test_aes128ctr_dec(), aes128ctr_dec()
*/
int test_aes128ctr_enc(uint8_t encdec_idx)
{
    cipher_context_t ctx_enc;
    const cipher_info_t *cipher_info;
    uint8_t       retval                = SUCCESS;                      // 0: success, 1: fail
    size_t        first_length          = FIRST_LEN;
    size_t        second_length         = SECOND_LEN;
    size_t        length                = first_length + second_length; // 10240
    unsigned char key[ENC_DEC_KEY_SIZE] = {0,};
    unsigned char iv[ENC_DEC_IV_SIZE]   = {0,};
    unsigned char *inbuf;

    size_t        outlen                = 0;
    size_t        totaloutlen           = 0;
    size_t        enclen                = 0;

	uint16_t      aes_blk_sz            = first_length;                 //16
	int16_t       remaind_len           = length;
	uint16_t      progress_len          = 0;

    memset( key,      0, ENC_DEC_KEY_SIZE );
    memset( iv ,      0, ENC_DEC_IV_SIZE  );

	memcpy( key, ENC_DEC_test_key[encdec_idx], ENC_DEC_KEY_SIZE);
	dbg_printf("Enc/Dec Key Index[%d]\r\n", encdec_idx);

#if 0 //GEN_ENCKEY	
    hex_printf(key, ENC_DEC_KEY_SIZE, 1);
#endif

    memset( &ctx_enc, 0, sizeof( ctx_enc ) );

	//Memory Allocation (inbuf)
    inbuf = (unsigned char*)malloc(sizeof(unsigned char) * length);
	if(inbuf == NULL) {
		dbg_printf("malloc() Fail.(inbuf) \r\n ");
		retval = FAIL;
		return retval;
	}
    memset( inbuf,    5, MD_BUF_SZ );
    memset( encbuf,   0, MD_BUF_SZ );

    /* Initialise encryption contexts */
    cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
    if( NULL == cipher_info) {
		retval = FAIL;
		//Memory Allocation free (inbuf)
        free(inbuf);
		return retval;		
	}
    retval      = cipher_init_ctx( &ctx_enc, cipher_info );
    if(retval == FAIL) {
		//Memory Allocation free (inbuf)
        free(inbuf);
		return retval;
	}
    retval      = cipher_setkey( &ctx_enc, key, 128, POLARSSL_ENCRYPT );
    if(retval == FAIL) {
		//Memory Allocation free (inbuf)
        free(inbuf);
		return retval;
	}
    retval      = cipher_reset( &ctx_enc, iv );
    if(retval == FAIL) {
		//Memory Allocation free (inbuf)
        free(inbuf);
		return retval;
	}
    enclen      = length;
	totaloutlen	= 0;
	while(remaind_len) {
        /* encode length number of bytes from inbuf */
		progress_len = MIN(remaind_len, aes_blk_sz);
        retval = cipher_update( &ctx_enc, inbuf+totaloutlen, progress_len, encbuf+totaloutlen, &outlen );
		totaloutlen	+= outlen;
		remaind_len -= outlen;
        if(retval == FAIL) break;
//		dbg_printf("progress_len = %d, totaloutlen = %ld, remaind_len = %d\r\n", progress_len, totaloutlen, remaind_len);
    }
//	dbg_printf("progress_len = %d, totaloutlen = %ld, remaind_len = %d\r\n", progress_len, totaloutlen, remaind_len);
	dbg_printf("Encrypted msg[%ld]: \r\n",totaloutlen);

    if( totaloutlen != enclen ) retval  = FAIL;
    retval = cipher_finish( &ctx_enc, encbuf + totaloutlen, &outlen );
    totaloutlen += outlen;	

    retval = cipher_free_ctx( &ctx_enc ) ;

#if GEN_ENCMSG	
    hex_printf(encbuf, totaloutlen, 1);
#endif
    //Memory alloc free (inbuf)
	free(inbuf);
    return retval;

}

/**
 * 
 * @brief       AES 128 CTR Decryption test.
 * @details     AES 128 CTR decryption function. IV value 16 bytest 0x00. \n
 *              int test_aes128ctr_dec(uint8_t encdec_idx)
 * @param[in]	encdec_idx	Index of AES 128 CTR decryption keys
 * @return		0: success, 1: fail
 * @see			test_aes128ctr_enc(), aes128ctr_dec()
*/
int test_aes128ctr_dec(uint8_t encdec_idx)
{            
    cipher_context_t ctx_dec;
    const cipher_info_t *cipher_info;
    uint8_t       retval                = SUCCESS;                         //0: success, 1: fail
    size_t        first_length          = FIRST_LEN;
    size_t        second_length         = SECOND_LEN;
    size_t        length                = first_length + second_length;	   //10240
    unsigned char key[ENC_DEC_KEY_SIZE] = {0,};
    unsigned char iv[ENC_DEC_IV_SIZE]   = {0,};
    unsigned char *inbuf;

    size_t        outlen                = 0;
    size_t        totaloutlen           = 0;
    size_t        enclen                = 0;

	uint16_t      aes_blk_sz            = first_length;                    //16
	int16_t       remaind_len           = length;
	uint16_t      progress_len	        = 0;

    memset( key,      0, ENC_DEC_KEY_SIZE );
    memset( iv ,      0, ENC_DEC_IV_SIZE  );

	memcpy( key, ENC_DEC_test_key[encdec_idx], ENC_DEC_KEY_SIZE);
	dbg_printf("Enc/Dec Key Index[%d]\r\n", encdec_idx);

#if GEN_ENCKEY	
    hex_printf(key, ENC_DEC_KEY_SIZE, 1);
#endif

    memset( &ctx_dec, 0, sizeof( ctx_dec ) );

    //Memory Allocation (inbuf)
    inbuf = (unsigned char*)malloc(sizeof(unsigned char) * length);
	if(inbuf == NULL) {
		dbg_printf("malloc() Fail.(inbuf) \r\n ");
		retval = FAIL;
		return retval;
	}
    memset( inbuf,    5, MD_BUF_SZ );
    memset( decbuf,   0, MD_BUF_SZ );

    /* Initialise decryption contexts */
    cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
    if( NULL == cipher_info) {
		retval  = FAIL;
		//Memory Allocation free (inbuf)
        free(inbuf);
		return retval;
	}
    retval      = cipher_init_ctx( &ctx_dec, cipher_info );
    if(retval == FAIL) {
		//Memory Allocation free (inbuf)
        free(inbuf);
		return retval;
	}
    retval      = cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT );
    if(retval == FAIL) {
		//Memory Allocation free (inbuf)
        free(inbuf);
		return retval;
	}	
    retval      = cipher_reset( &ctx_dec, iv );
    if(retval == FAIL) {
		//Memory Allocation free (inbuf)
        free(inbuf);
		return retval;
	}
    enclen      = length;
	totaloutlen	= 0; 
	while(remaind_len){
		progress_len = MIN(remaind_len, aes_blk_sz);
		retval =  cipher_update( &ctx_dec, encbuf+totaloutlen, progress_len, decbuf+totaloutlen, &outlen );
		totaloutlen	+= outlen;
		remaind_len -= outlen;
		if(retval == FAIL) break;
//		dbg_printf("progress_len = %d, totaloutlen = %ld, remaind_len = %d\r\n", progress_len, totaloutlen, remaind_len);		
	}
//	dbg_printf("progress_len = %d, totaloutlen = %ld, remaind_len = %d\r\n", progress_len, totaloutlen, remaind_len);		

	if( enclen != totaloutlen )	retval	= FAIL;
	if( cipher_finish( &ctx_dec, decbuf+totaloutlen, &outlen ) ) retval	= FAIL;

    retval = memcmp(inbuf, decbuf, length) ;
    retval = cipher_free_ctx( &ctx_dec ) ;

	dbg_printf("Decrypted msg[%ld]: \r\n", totaloutlen);

#if GEN_DECMSG
    hex_printf(decbuf, totaloutlen, 1);
#endif
    //Memory alloc free (inbuf)
	free(inbuf);
    return retval;

}

/**
 * 
 * @brief       AES 128 CTR Decryption.
 * @details     AES 128 CTR decryption function. IV value 16 bytes 0x00. \n
 *              int aes128ctr_dec(uint8_t* enc_buf, uint16_t buf_length, uint8_t encdec_idx)
 * @param[in]	enc_buf	    Buffer for AES 128 CTR decryption
 * @param[in]	buf_length  The number of characters in the buffer for AES 128 CTR decryption
 * @param[in]	encdec_idx	Index of AES 128 CTR decryption keys
 * @return		0: success, 1: fail
 * @see			test_aes128ctr_enc(), test_aes128ctr_dec()
*/
int aes128ctr_dec(uint8_t* enc_buf, uint16_t buf_length, uint8_t encdec_idx)
{            
    cipher_context_t ctx_dec;
    const cipher_info_t *cipher_info;
    uint8_t       retval                = SUCCESS;                      //0: success, 1: fail
    size_t        first_length          = FIRST_LEN;
    size_t        second_length         = buf_length - FIRST_LEN;
    size_t        length                = first_length + second_length;	//10240
    unsigned char key[ENC_DEC_KEY_SIZE] = {0,};
    unsigned char iv[ENC_DEC_IV_SIZE]   = {0,};

    size_t        outlen                = 0;
    size_t        totaloutlen           = 0;
    size_t        enclen                = 0;

	uint16_t      aes_blk_sz            = first_length;                 //16
	int16_t       remaind_len           = length;
	uint16_t      progress_len          = 0;

    memset( key,      0, ENC_DEC_KEY_SIZE );
    memset( iv ,      0, ENC_DEC_IV_SIZE  );

	memcpy( key, ENC_DEC_test_key[encdec_idx], ENC_DEC_KEY_SIZE);
	dbg_printf("Enc/Dec Key Index[%d]\r\n", encdec_idx);

#if GEN_ENCKEY	
    hex_printf(key, ENC_DEC_KEY_SIZE, 1);
#endif

    memset( &ctx_dec, 0, sizeof( ctx_dec ) );
        
    memset( decbuf,   0, buf_length );

    /* Initialise decryption contexts */
    cipher_info = cipher_info_from_type( POLARSSL_CIPHER_AES_128_CTR );
    if( NULL == cipher_info) {
		retval  = FAIL;
		return retval;
	}
    retval = cipher_init_ctx( &ctx_dec, cipher_info );
	if(retval == FAIL) return retval;

    retval = cipher_setkey( &ctx_dec, key, 128, POLARSSL_DECRYPT );
    if(retval == FAIL) 	return retval;

    retval = cipher_reset( &ctx_dec, iv );
    if(retval == FAIL) return retval;

    enclen      = length;
	totaloutlen	= 0; 
	while(remaind_len) {
		progress_len = MIN(remaind_len, aes_blk_sz);
		retval =  cipher_update( &ctx_dec, enc_buf+totaloutlen, progress_len, decbuf+totaloutlen, &outlen );
		totaloutlen	+= outlen;
		remaind_len -= outlen;
		if(retval == FAIL) break;
//		dbg_printf("progress_len = %d, totaloutlen = %ld, remaind_len = %d\r\n", progress_len, totaloutlen, remaind_len);		
	}
//	dbg_printf("progress_len = %d, totaloutlen = %ld, remaind_len = %d\r\n", progress_len, totaloutlen, remaind_len);		

	if( enclen != totaloutlen )	retval	= FAIL;
	if( cipher_finish( &ctx_dec, decbuf+totaloutlen, &outlen ) ) retval	= FAIL;

    retval = cipher_free_ctx( &ctx_dec ) ;

	dbg_printf("Decrypted msg[%ld]: \r\n", totaloutlen);

#if GEN_DECMSG
    hex_printf(decbuf, totaloutlen, 1);
#endif

    return retval;

}

/**
 * 
 * @brief       Check HMAC, Signature, and Decryption of the parsed buffer.
 * @details     Check HMAC, Signature, and Decryption of the parsed buffer. \n
 *              uint8_t testing_analysis(void)
 * @param[in]	void
 * @return		uint8_t  ret_error \n
 * 		        ret_error = 0 (Pass) \n
 * 		        ret_error = 1 (HMAC Error) \n
 * 		        ret_error = 2 (pkcs1_verify_sha256 Error) \n
 * 		        ret_error = 3 (aes128ctr_dec Error) \n
 * 		        ret_error = 4 (Memory Allocation Failure.(md_buf)) \n
 * @see			testing_parsing()
*/
uint8_t testing_analysis(void)
{
    sha2_context Hctx;      //When using message digest as sha256
	mypublic_t my_pub={
		.len = KEY_LEN,
		.n	 = mypub_N,
		.e	 = mypub_E
	};

	myprivate_t my_prv={
		.len = KEY_LEN,
		.n	 = myprv_N,
		.e	 = myprv_E,
		.d	 = myprv_D
	};

	uint16_t idx                        = 0;	
    uint8_t  rsa_ciphertext[SIGN_SIZE]	= {0,};
    uint8_t  rsa_ciphertext1[SIGN_SIZE]	= {0,};	
    uint8_t  md_sum [SHA256_SZ]		    = {0,};

	uint8_t  ret_val                    = 0;
	uint8_t  ret_error                  = 0;
	uint8_t  *md_buf;

    dbg_printf("**********************************************************************\r\n");
	dbg_printf("** Analysis Sflash file testing                                     **\r\n");
    dbg_printf("**********************************************************************\r\n");

    //Memory Allocation (md_buf)
    md_buf = (uint8_t*)malloc(sizeof(uint8_t) * (header.firm_size + 1000));
	if(md_buf == NULL) {
		dbg_printf("malloc() Fail.(md_buf) \r\n ");
		ret_error = 4;
		return ret_error;
	}
    memset(md_buf, 0, (header.firm_size + 1000));
//1st Block
	md_buf[0] = body.block_no[0].counter_data & 0xff;
	for(idx = 0; idx < BLOCK_SIZE; idx++) {
		md_buf[idx+1] = body.block_no[0].app_data[idx] & 0xff;
	}

	ret_val = sha2_Hmac_analysis(md_buf, BLOCK_SIZE+1, body.block_no[0].hmac_data, header.hmac_key_index);

	if(ret_val) ret_error = 1;
//2nd Block
	if(body.total_counter == 2){
		memset(md_buf, 0, (header.firm_size + 1000));

		md_buf[0] = body.block_no[1].counter_data & 0xff;
		for(idx = 0; idx < BLOCK_SIZE; idx++) {
			md_buf[idx+1] = body.block_no[1].app_data[idx] & 0xff;
		}

		ret_val = sha2_Hmac_analysis(md_buf, BLOCK_SIZE+1, body.block_no[1].hmac_data, header.hmac_key_index);

		if(ret_val) ret_error = 1;
	}
	//Memory Allocation free (md_buf)
	free(md_buf);
    dbg_printf("---------------------  HMAC-SHA256 check End -------------------------\r\n");
    dbg_printf("\r\n\n");
    sha_starts( &Hctx, MD_SHA256);
    sha_update( &Hctx, body.total_app_data, header.firm_size, MD_SHA256 );
    sha_finish( &Hctx, md_sum, MD_SHA256 );

#if HASH_CHECK
	dbg_printf("SHA256[%02ld][%d]\r\n", sizeof(md_sum), header.firm_size);
	hex_printf(md_sum, sizeof(md_sum), 1);
#endif

    memcpy(rsa_ciphertext, signature._data, SIGN_SIZE);
	if(AURSARET_OK != AURSA_pkcs1_verify_sha256(
							&my_pub, 
							rsa_ciphertext,
							md_sum))
	{
		dbg_printf( "  Signature Verification failed!\n" );
		ret_error = 2;
		if(AURSARET_OK != AURSA_pkcs1_sign_sha256(
								&my_prv, 
								rsa_ciphertext1,
								md_sum ))
		{
			dbg_printf( "  Signature    gen. failed!\n" );
		}
		else {
			dbg_printf( "  Signature    gen. Successed!\n" );
			hex_printf(rsa_ciphertext1, sizeof(rsa_ciphertext1), 1);
		}
	}
	else {
		dbg_printf( "  Signature Verification Successed!\n" );
	}

    dbg_printf("-----------------------  Signature check End -------------------------\r\n");
    dbg_printf("\r\n\n");
	ret_val = aes128ctr_dec(body.total_app_data, header.firm_size, header.enc_key_index);
	if(ret_val != SUCCESS) {
		dbg_printf( "  Decryption   Failed!\n" );
		ret_error = 3;
	}
	else {
		dbg_printf( "  Decryption   Success! = %d\n" ,header.firm_size);			
	}

    dbg_printf("----------------------  Decryption check End -------------------------\r\n");
    dbg_printf("\r\n\n");
    return ret_error;
}

/**
 * 
 * @brief       Buffer construction by parsing in hex file.
 * @details     Buffer construction by parsing in hex file. \n
 *              uint8_t testing_parsing(void)
 * @param[in]	void
 * @return		uint8_t  ret_val \n
 *              ret_val = 0 (Pass) \n
 *              ret_val = 1 (Missmatch META_INFO Error) \n
 *              ret_val = 2 (Missmatch HEADER LENGTH Error) \n
 *              ret_val = 3 (Missmatch Firmware Size Error) \n
 *              ret_val = 4 (Missmatch reserve value Error) \n
 *              ret_val = 5 (Missmatch SIG_INFO Error) \n
 *              ret_val = 6 (Memory Allocation Failure.(md_buf)) \n
 *              ret_val = 7 (Memory Allocation Failure.(body.app_data)) \n
 *              ret_val = 8 (Memory Allocation Failure.(encbuf)) \n
 *              ret_val = 9 (Memory Allocation Failure.(decbuf)) \n
 *              ret_val = 10 (Malloc Failure.(body.block_no[0].app_data)) \n
 *              ret_val = 11 (Malloc Failure.(body.block_no[1].app_data)) \n
 * @see         testing_analysis()
*/
uint8_t testing_parsing(void)
{
	uint8_t  *md_buf;
	uint8_t  ret_val               = 0;
	uint16_t idx_cnt               = 0;	
	uint32_t temp_con[4]           = {0,};
	int32_t  fsz                   = 0;
	FILE*    fp;

#if HASH_CHECK
    sha2_context Hctx;                     //When using message digest as sha256
    uint8_t  md_sum [SHA256_SZ]	   = {0,};
#endif
	uint32_t firm_block_size       = 0;


    dbg_printf("**********************************************************************\r\n");
	dbg_printf("** Parsing Sflash file testing                                      **\r\n");
    dbg_printf("**********************************************************************\r\n");
	fp = fopen ("../key/Sflash_sample.bin", "r");
	fseek( fp, 0L, SEEK_END );
	fsz = ftell(fp);
	rewind(fp);

	//Memory Allocation (md_buf)
    md_buf = (uint8_t*)malloc(sizeof(uint8_t) * fsz);
	if(md_buf == NULL) {
		dbg_printf("malloc() Fail.(md_buf) \r\n ");
		ret_val = 6;
		return ret_val;
	}
	memset( md_buf, 0x00, fsz);	
    while( feof( fp ) == 0 ) {
//Header

		fread( md_buf, 1, fsz, fp );
		dbg_printf("Header(16) + TotalCount(1) + Count(1) + HMAC(32) + Enc Data(10240) + Inform(2) + Sign(256) \r\n");
		dbg_printf("Header Length = %d, Total Length = 0x%04X(%d) ,308(Size excluding Enc Data)\r\n", HEADER_LENGTH, fsz, fsz);
//		hex_printf(md_buf, HEADER_LENGTH + 1 + MAC_SIZE, 1);

		if((md_buf[0] != META_INFO1) || (md_buf[1] != META_INFO2)) {
          ret_val = 1;
		  break;
		}
        memcpy(header.meta_inform, md_buf, 2);
        dbg_printf("## META Inform      [%ld] = 0x%02X 0x%02X (FIX Value) \r\n", sizeof(header.meta_inform), header.meta_inform[0], header.meta_inform[1]);

        temp_con[0] = ((md_buf[2] & 0xff)*0x100);
		temp_con[1] = (md_buf[3] & 0xff);

		header.header_len = temp_con[0] + temp_con[1];
		if(header.header_len != HEADER_LENGTH) {
          ret_val = 2;
		  break;
		}
        dbg_printf("## HEADER Length    [%ld] = 0x%04X(%d) \r\n", sizeof(header.header_len), header.header_len, header.header_len);

		header.enc_key_index  = md_buf[4] & 0xff;
		header.hmac_key_index = md_buf[5] & 0xff;
        dbg_printf("## Enc/Dec Key Index[%ld] = 0x%02X \r\n", sizeof(header.enc_key_index), header.enc_key_index);
        dbg_printf("## HMac Key Index   [%ld] = 0x%02X \r\n",sizeof(header.hmac_key_index), header.hmac_key_index);

        temp_con[0]         = ((md_buf[6]&0xff)*0x1000000);
		temp_con[1]         = ((md_buf[7]&0xff)*0x10000);
		temp_con[2]         = ((md_buf[8]&0xff)*0x100);
		temp_con[3]         = (md_buf[9]&0xff);		
        header.firm_version =  temp_con[0] + temp_con[1] + temp_con[2] + temp_con[3];

        temp_con[0]         = ((md_buf[10]&0xff)*0x1000000);
		temp_con[1]         = ((md_buf[11]&0xff)*0x10000);
		temp_con[2]         = ((md_buf[12]&0xff)*0x100);
		temp_con[3]         = (md_buf[13]&0xff);		
        header.firm_size    = temp_con[0] + temp_con[1] + temp_con[2] + temp_con[3];		
		if(header.firm_size == 0) {
			ret_val = 3;
			break;
		}
        dbg_printf("## Firmware Version [%ld] = 0x%08X \r\n",sizeof(header.firm_version), header.firm_version);
        dbg_printf("## Firmware Size    [%ld] = 0x%08X(%d) \r\n",sizeof(header.firm_size), header.firm_size, header.firm_size);

		if((md_buf[14] != META_RESERVED) || (md_buf[15] != META_RESERVED)) {
          ret_val = 4;
		  break;
		}
        memcpy(header.reserve_use, md_buf+14, 2);

// Buffer define

		//Memory Allocation (body.app_data, encbuf, decbuf)
        body.total_app_data = (uint8_t*)malloc(sizeof(uint8_t) * header.firm_size);
		if(body.total_app_data == NULL) {
			dbg_printf("malloc() Fail.(body.app_data) \r\n ");
			ret_val = 7;
			free(md_buf);
			return ret_val;
		}
        encbuf        = (uint8_t*)malloc(sizeof(uint8_t) * header.firm_size);
		if(encbuf == NULL) {
			dbg_printf("malloc() Fail.(encbuf) \r\n ");
			ret_val = 8;
			free(md_buf);
			free(body.total_app_data);
			return ret_val;
		}
        decbuf        = (uint8_t*)malloc(sizeof(uint8_t) * header.firm_size);
		if(decbuf == NULL) {
			dbg_printf("malloc() Fail.(decbuf) \r\n ");
			ret_val = 9;
			free(md_buf);
			free(body.total_app_data);
			free(encbuf);
			return ret_val;
		}
//1st Block Memory allcoation
        body.block_no[0].app_data   = (uint8_t*)malloc(sizeof(uint8_t) * BLOCK_SIZE);
		if(decbuf == NULL) {
			dbg_printf("malloc() Fail.(body.block_no[0].app_data) \r\n ");
			ret_val = 10;
			free(md_buf);
			free(body.total_app_data);
			free(encbuf);
			free(decbuf);			
			return ret_val;
		}

		memset(body.total_app_data, 0 , header.firm_size);
		memset(encbuf, 0 , header.firm_size);
	    memset(decbuf, 0 , header.firm_size);
		memset(body.block_no[0].app_data, 0 , BLOCK_SIZE );

//2nd Block Memory allcoation
		if(body.total_counter == 2) {
			body.block_no[1].app_data   = (uint8_t*)malloc(sizeof(uint8_t) * BLOCK_SIZE);
			if(decbuf == NULL) {
				dbg_printf("malloc() Fail.(body.block_no[1].app_data) \r\n ");
				ret_val = 11;
				free(md_buf);
				free(body.total_app_data);
				free(encbuf);
				free(decbuf);
				free(body.block_no[0].app_data);
				return ret_val;
			}
			memset(body.block_no[1].app_data, 0 , BLOCK_SIZE );
		}

        dbg_printf("## META Reserved    [%ld] = 0x%02X 0x%02X (FIX Value) \r\n", sizeof(header.reserve_use), header.reserve_use[0], header.reserve_use[1]);
        dbg_printf("----------------------  Header area End  -----------------------------\r\n");
        dbg_printf("\r\n\n");

		body.total_counter  = md_buf[16];
        dbg_printf("## Total Counter    [%ld] = 0x%02X \r\n",sizeof(body.total_counter), body.total_counter);

// body start
/* 현재는 1개 block이지만 2개 block으로 변경 시 결정된 바가 없으나 가안은.
   1. BLOCK_SIZE 를 10240 -> 5120 으로 변경.
   2. body.total_counter 1-> 2로 변경.(Bin File에서 변경.)
   3. block count(1) + HMAC(32) + encrypt data(5120) 을 반복 2회 처리 해야 함.
   4. body start ~ body end 반복.
   5. server 에서 file 생성하는 방법 확인이 필요.
   6. HMAC의 경우 block 단위로 연산하고 siginature는 block 단위가 아닌 전체 encrypt data(10240) 으로 연산 필요.
*/
/* Currently, it is 1 block, but when changing to 2 blocks, nothing has been decided, but it is possible.
    1. Change BLOCK_SIZE from 10240 -> 5120.
    2. Change body.total_counter 1-> 2. (Changed in Bin File.)
    3. Block count(1) + HMAC(32) + encrypt data(5120) should be processed twice repeatedly.
    4. Repeat body start to body end.
    5. Need to check how to create a file on the server.
    6. In case of HMAC, it is operated in block unit, and siginature needs to be operated in whole encrypt data (10240), not in block unit.
*/
//1st Block
        dbg_printf("## Application Block #1\r\n");
        firm_block_size = (BLOCK_SIZE + 33) * (body.block_no[0].counter_data);
		body.block_no[0].counter_data   = md_buf[17 + firm_block_size];
        dbg_printf("## Body Counter     [%ld] = 0x%02X \r\n",sizeof(body.block_no[0].counter_data), body.block_no[0].counter_data);

		memcpy(body.block_no[0].hmac_data, md_buf + (18 + firm_block_size), MAC_SIZE);
        dbg_printf("## HMAC Data       [%d] = \r\n", MAC_SIZE);
        hex_printf(body.block_no[0].hmac_data, MAC_SIZE, 1);

		idx_cnt = (18 + firm_block_size) + MAC_SIZE;
		memcpy(&body.block_no[0].app_data[0], md_buf + idx_cnt, BLOCK_SIZE);		
		dbg_printf("## Application Encryption Data[%d] = \r\n", BLOCK_SIZE);
		memcpy(body.total_app_data, body.block_no[0].app_data, BLOCK_SIZE);

#if PARSING_ENC		
        hex_printf(body.block_no[0].app_data, BLOCK_SIZE, 1);
#endif
// body end
//2nd Block
        if(body.total_counter == 2){
			dbg_printf("## Application Block #2\r\n");
			firm_block_size = (BLOCK_SIZE + 33) * (body.block_no[1].counter_data);
			body.block_no[1].counter_data   = md_buf[17 + firm_block_size];
			dbg_printf("## Body Counter     [%ld] = 0x%02X \r\n",sizeof(body.block_no[1].counter_data), body.block_no[1].counter_data);

			memcpy(body.block_no[1].hmac_data, md_buf + (18 + firm_block_size), MAC_SIZE);
			dbg_printf("## HMAC Data       [%d] = \r\n", MAC_SIZE);
			hex_printf(body.block_no[1].hmac_data, MAC_SIZE, 1);

			idx_cnt = (18 + firm_block_size) + MAC_SIZE;
			memcpy(&body.block_no[1].app_data[0], md_buf + idx_cnt, BLOCK_SIZE);		
			dbg_printf("## Application Encryption Data[%d] = \r\n", BLOCK_SIZE);
		    memcpy(body.total_app_data + BLOCK_SIZE, body.block_no[1].app_data, BLOCK_SIZE);
#if PARSING_ENC		
        	hex_printf(body.block_no[1].app_data, BLOCK_SIZE, 1);
#endif	
		}
		idx_cnt = 17 + (BLOCK_SIZE + 33) * (body.total_counter);

		memcpy(signature._inform, md_buf + idx_cnt, 2);
		if((signature._inform[0] != SIG_INFO1) || (signature._inform[1] != SIG_INFO2)) {
          ret_val = 5;
		  break;
		}
        dbg_printf("-----------------------  Body area End  -----------------------------\r\n");
        dbg_printf("\r\n\n");
        dbg_printf("## Signature Inform [%ld] = 0x%02X 0x%02X (FIX Value) \r\n", sizeof(signature._inform), signature._inform[0], signature._inform[1]);

		memcpy(signature._data, md_buf + idx_cnt + 2, SIGN_SIZE);
		dbg_printf("## Signature Data [%d] = \r\n", SIGN_SIZE);
        hex_printf(signature._data, SIGN_SIZE, 1);

#if HASH_CHECK
    	sha_starts( &Hctx, MD_SHA256);
    	sha_update( &Hctx, body.total_app_data , header.firm_size, MD_SHA256 );
    	sha_finish( &Hctx, md_sum, MD_SHA256 );

		dbg_printf("SHA256[%02ld][%d] \r\n", sizeof(md_sum), header.firm_size);
		hex_printf(md_sum, sizeof(md_sum), 1);
#endif

        dbg_printf("--------------------  Signature area End  ----------------------------\r\n");
        break;
    }
	fclose (fp);
	//Memory Allocation free (md_buf)
	free(md_buf);
	return ret_val;
}

/**
 * 
 * @brief       Generate a signature for secure boot.
 * @details     Generate a signature for secure boot. \n
 *              int test_make_securboot(uint8_t* enc_buf, uint16_t buf_length, uint8_t* sign_buf)
 * @param[in]	enc_buf	    Buffer for signature
 * @param[in]	buf_length  The number of characters in the buffer for signature
 * @param[out]	sign_buf	Generate a signature
 * @return		0: success, 1: fail
 * @see			test_check_securboot()
*/
int test_make_secureboot(uint8_t* enc_buf, uint16_t buf_length, uint8_t* sign_buf)
{
    sha2_context Hctx;      //When using message digest as sha256
    uint8_t md_sum [SHA256_SZ]		  = {0,};


	myprivate_t my_prv={
		.len = KEY_LEN,
		.n	 = myprv_N,
		.e	 = myprv_E,
		.d	 = myprv_D
	};
    uint8_t retval                    = SUCCESS;    //0: success, 1: fail

    sha_starts( &Hctx, MD_SHA256);
    sha_update( &Hctx, enc_buf, buf_length, MD_SHA256 );
    sha_finish( &Hctx, md_sum, MD_SHA256 );

#if HASH_CHECK	
	dbg_printf("SHA256[%02ld][%d] \r\n", sizeof(md_sum),buf_length);	
	hex_printf((uint8_t *)md_sum, sizeof(md_sum), 0);
#endif

	if(AURSARET_OK != AURSA_pkcs1_sign_sha256(
							&my_prv, 
							sign_buf,
							md_sum ))
	{
		dbg_printf( "  Signature    Generate failed!\n" );
		retval = FAIL;
	}
	else {
		dbg_printf( "  Signature    Generate Successed!\n" );
		retval = SUCCESS;
	}
	return retval;	
}

/**
 * 
 * @brief       Validate the signature for secure boot.
 * @details     Validate the signature for secure boot. \n
 *              int test_check_securboot(uint8_t* enc_buf, uint16_t buf_length, uint8_t* sign_buf)
 * @param[in]	enc_buf	    Buffer for signature
 * @param[in]	buf_length  The number of characters in the buffer for signature
 * @param[in]	sign_buf	Generated a signature
 * @return		0: success, 1: fail
 * @see			test_make_securboot()
*/
int test_check_secureboot(uint8_t* enc_buf, uint16_t buf_length, uint8_t* sign_buf)
{
    sha2_context Hctx;      //When using message digest as sha256
    uint8_t md_sum [SHA256_SZ]		  = {0,};

	mypublic_t my_pub={
		.len = KEY_LEN,
		.n	 = mypub_N,
		.e	 = mypub_E
	};	
    uint8_t retval                    = SUCCESS;    //0: success, 1: fail

    sha_starts( &Hctx, MD_SHA256);
    sha_update( &Hctx, enc_buf, buf_length, MD_SHA256 );
    sha_finish( &Hctx, md_sum, MD_SHA256 );

#if HASH_CHECK	
	dbg_printf("SHA256[%02ld][%d] \r\n", sizeof(md_sum),buf_length);
	hex_printf((uint8_t *)md_sum, sizeof(md_sum), 0);
#endif

	if(AURSARET_OK != AURSA_pkcs1_verify_sha256(
							&my_pub, 
							sign_buf,
							md_sum))
	{
		dbg_printf( "  Verification Check failed!\n" );
		retval = FAIL;
	}
	else {
		dbg_printf( "  Verification Check Successed!\n" );
        retval = SUCCESS;
	}
	return retval;
}


/**
 * 
 * @brief       Validation for each function.
 * @details     Validation for each function. Encryption/decryption, HMAC, Signature generation and verification. \n
 *              uint8_t testing_func(void)
 * @param[in]	void
 * @return		uint8_t  ret_val
 * 		        ret_val = 0 (Pass)
 * 		        ret_val = 1 (Encryption   Failed Error)
 * 		        ret_val = 2 (Decryption   Failed Error)
 * 		        ret_val = 3 (Signature    failed Error)
 * 		        ret_val = 4 (Verification failed Error)
 *      		ret_val = 5 (Memory Allocation Failure.(rsa_cipherMac))
 * @see         testing_analysis()
*/
uint8_t testing_func(void)
{
    sha2_context Hctx;      //When using message digest as sha256
	mypublic_t my_pub={
		.len = KEY_LEN,
		.n	 = mypub_N,
		.e	 = mypub_E
	};

	myprivate_t my_prv={
		.len = KEY_LEN,
		.n	 = myprv_N,
		.e	 = myprv_E,
		.d	 = myprv_D
	};

    uint8_t  rsa_ciphertext[SIGN_SIZE] = {0,};
	
    uint8_t  *rsa_cipherMac;
    uint8_t  md_sum [SHA256_SZ]	 	   = {0,};
	uint16_t idx                       = 0;
    uint16_t block_cnt                 = 0;
    uint8_t  retval                    = SUCCESS;    //0: success, 1: fail
    uint8_t  ret_val                   = SUCCESS;
    uint8_t  encdec_index              = 0;

    dbg_printf("**********************************************************************\r\n");
	dbg_printf("** Individual function testing                                      **\r\n");
    dbg_printf("**********************************************************************\r\n");

    encdec_index = 0;
	retval = test_aes128ctr_enc(encdec_index);
	if(retval != SUCCESS) {
		dbg_printf( "  Encryption   Failed!\n" );
		ret_val = 1;
	}
	else {
		dbg_printf( "  Encryption   Success!\n" );
		dbg_printf("AES-CTR-128 CipherText[%03d]\r\n", FIRST_LEN+SECOND_LEN);
	}
	dbg_printf("======================================================================\r\n");
	dbg_printf("\r\n\n");

	retval = test_aes128ctr_dec(encdec_index);
	if(retval != SUCCESS) {
		dbg_printf( "  Decryption   Failed!\n" );
		ret_val = 2;		
	}
	else {
		dbg_printf( "  Decryption   Success! = %d, [Setting(Plain text = 0x05 * %d)]\n" ,FIRST_LEN+SECOND_LEN,FIRST_LEN+SECOND_LEN);
	}
    dbg_printf("======================================================================\r\n");
	dbg_printf("\r\n\n");
	
    sha_starts( &Hctx, MD_SHA256);
    sha_update( &Hctx, encbuf, FIRST_LEN+SECOND_LEN, MD_SHA256 );
    sha_finish( &Hctx, md_sum, MD_SHA256 );

#if HASH_CHECK	
	dbg_printf("SHA256[%02ld][%d] \r\n", sizeof(md_sum),FIRST_LEN+SECOND_LEN);
	hex_printf((uint8_t *)md_sum, sizeof(md_sum), 0);
#endif

	if(AURSARET_OK != AURSA_pkcs1_sign_sha256(
							&my_prv, 
							rsa_ciphertext,
							md_sum ))
	{
		dbg_printf( "  Signature    Generate failed!\n" );
		ret_val = 3;		
	}
	else {
		dbg_printf( "  Signature    Generate Successed!\n" );
	}

	if(AURSARET_OK != AURSA_pkcs1_verify_sha256(
							&my_pub, 
							rsa_ciphertext,
							md_sum))
	{
		dbg_printf( "  Verification failed!\n" );
		ret_val = 4;		
	}
	else {
		dbg_printf( "  Verification Successed!\n" );
		dbg_printf("RSA CipherText Signature [%03d] \r\n", SIGN_SIZE);
		hex_printf((uint8_t *)rsa_ciphertext, SIGN_SIZE, 1);		
	}
	dbg_printf("======================================================================\r\n");

    //Memory Allocation (rsa_cipherMac)
    rsa_cipherMac = (uint8_t*)malloc(sizeof(uint8_t) * (FIRST_LEN+SECOND_LEN+ 1));
	if(rsa_cipherMac == NULL) {
		dbg_printf("malloc() Fail.(rsa_cipherMac) \r\n ");
		ret_val = 5;
		return ret_val;
	}
	memset(rsa_cipherMac, 0, (FIRST_LEN+SECOND_LEN+ 1));

	rsa_cipherMac[0] = block_cnt & 0xff;

	for(idx = 0; idx < FIRST_LEN+SECOND_LEN; idx++) {
		rsa_cipherMac[idx+1] = encbuf[idx] & 0xff;
	}
	dbg_printf("\r\n\n");

    sha2_mac_testing(&rsa_cipherMac[0], FIRST_LEN+SECOND_LEN+1, 0);
	dbg_printf("\r\n");
	//Memory Allocation free (rsa_cipherMac)
	free(rsa_cipherMac);
	return ret_val;
}

/**
 * 
 * @brief       main function.
 * @details     main function. \n
 *              int main(void)
 * @param[in]	void
 * @return		uint8_t  err_return
 * @see         
*/
int main(void)
{
	uint8_t  err_return = 0;
	uint16_t idx        = 0;

#if UNIT_TEST
    unsigned char error_func[7][50] =
	{
		{ "Generate Func. test OK."                  },
		{ "AES-CTR-128 Encryption   Failed !"        },
		{ "AES-CTR-128 Decryption   Failed !"        },
		{ "Signature    Generate failed !"           },
		{ "Verification failed !"                    },
		{ "Memory Allocation Failure.(rsa_cipherMac)"},
	    { ""}

	};
#endif

#if PARSING_TEST
    unsigned char error_parsing[12][50] =
	{
		{ "Parsing OK."                               },
		{ "Meta information delimiter mismatch. !"    },
		{ "Header information length mismatch. !"     },
		{ "Firmware size is 0. !"                     },
		{ "Reserved value mismatch. !"                },
		{ "Digital signature delimiter mismatch. !"   },
		{ "Memory Allocation Failure.(md_buf)"        },
		{ "Memory Allocation Failure.(body.app_data)" },
		{ "Memory Allocation Failure.(encbuf)"        },
		{ "Memory Allocation Failure.(decbuf)"        },
		{ "Malloc Failure.(body.block_no[0].app_data)"},
		{ "Malloc Failure.(body.block_no[1].app_data)"}
	};
    unsigned char error_analysis[6][50] =
	{
		{ "Analysis OK."                             },
		{ "Hmac SHA256 Verification failed. !"       },
		{ "Signature Verification failed. !"         },
		{ "Decryption Verification failed. !"        },
		{ "Memory Allocation Failure.(md_buf)"       },
		{ ""                                         }
	};
#endif

//Function Test
#if UNIT_TEST

    //Memory Allocation (encbuf, decbuf)
    encbuf = (uint8_t*)malloc(sizeof(uint8_t) * MD_BUF_SZ);
	if(encbuf == NULL) {
		dbg_printf("malloc() Fail.(encbuf) \r\n ");
		return FAIL;
	}	
    decbuf = (uint8_t*)malloc(sizeof(uint8_t) * MD_BUF_SZ);
	if(decbuf == NULL) {
		dbg_printf("malloc() Fail.(decbuf) \r\n ");
		free(encbuf);
		return FAIL;
	}
	memset(encbuf, 0 , MD_BUF_SZ);
	memset(decbuf, 0 , MD_BUF_SZ);
	err_return = testing_func();
	dbg_printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\r\n");
	dbg_printf("++ Generate Result = %s\r\n", error_func[err_return]);
	dbg_printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\r\n");
	dbg_printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n");	
    dbg_printf("\r\n\n");
    dbg_printf("**********************************************************************\r\n");
	dbg_printf("** Secure Boot Image generate testing                               **\r\n");
    dbg_printf("**********************************************************************\r\n");

	//Memory Allocation free (encbuf, decbuf)
    free(encbuf);
    free(decbuf);

	//Memory Allocation (testbootimg)
    testbootimg = (uint8_t*)malloc(sizeof(uint8_t) * TEST_BOOTLEN);
	if(testbootimg == NULL) {
		dbg_printf("malloc() Fail.(testbootimg) \r\n ");
		return FAIL;
	}	
	memset(testbootimg, 0 , TEST_BOOTLEN);

    for(idx = 0; idx < TEST_BOOTLEN; idx++) {
		testbootimg[idx] = idx%16;
	}

	err_return = test_make_secureboot(testbootimg, TEST_BOOTLEN, testsignimg);
	if(err_return) dbg_printf("Secure boot Signature Generate Fail\r\n");
	else {
		err_return = test_check_secureboot(testbootimg, TEST_BOOTLEN, testsignimg);

		if(err_return) dbg_printf("Secure boot Verification Fail\r\n");
		else dbg_printf("Secure boot Ok !!\r\n");
	}

    //Memory Allocation free (testbootimg)
	free(testbootimg);
    dbg_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\r\n");	
    dbg_printf("\r\n\n\n\n\n");
#endif	

#if PARSING_TEST
//Parsing Test
	err_return = testing_parsing();
	dbg_printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\r\n");
	dbg_printf("++ Parsing Result = %s\r\n", error_parsing[err_return]);
	dbg_printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\r\n");
	dbg_printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n");
    dbg_printf("\r\n\n\n\n");

//Analysis test
    err_return = testing_analysis();
	dbg_printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\r\n");
	dbg_printf("++ Analysis Result = %s\r\n", error_analysis[err_return]);
	dbg_printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\r\n");
    dbg_printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\r\n");

    //Memory Allocation free (body.app_data, encbuf, decbuf)
	free(body.total_app_data);
	free(body.block_no[0].app_data);
	if(body.total_counter == 2) {
		free(body.block_no[1].app_data);
	}
    free(encbuf);
    free(decbuf);
#endif	
}