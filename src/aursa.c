/** 
  aursa.c
 */

#include <stdlib.h>
#include "config.h"
#include "rsa.h"
#include "md.h"
#include "aursatype.h"


#ifdef __linux__
int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    #include <time.h>
    srand (time(NULL));  //seed

    for( i = 0; i < len; ++i )
        output[i] = rand();

    return( 0 );
}
#else
/** dependency of CM0plus */
int myrand( void *rng_state, unsigned char *output, size_t len )
{

    if( rng_state != NULL )
        rng_state  = NULL;

	Run_CyRng((uint8_t*) output, (uint32_t) len);

    return( 0 );
}

#endif


AURSARET AURSA_oaep_encrypt(void* my_pub, void* input, uint32_t ilen, void* output )
{
	rsa_context rsa;
	mypublic_t *mykey = my_pub;
	unsigned char* rsa_plaintext = input;
	unsigned char* rsa_ciphertext = output;
	
	
    rsa_init( &rsa, RSA_PKCS_V21, POLARSSL_MD_SHA256 );
    rsa.len = mykey->len;
    mpi_read_string( &rsa.N , 16, (const char*)mykey->n  );
    mpi_read_string( &rsa.E , 16, (const char*)mykey->e  );

	if( rsa_pkcs1_encrypt( &rsa, &myrand, NULL, RSA_PUBLIC, ilen,
							   rsa_plaintext, rsa_ciphertext ) != 0 ) {
			//printf( "failed\n" );
			return( AURSARET_ENCRYT_FAIL );
		}
	return AURSARET_OK; 
}


size_t  AURSA_oaep_decrypt(void* my_prv, void* input, void* output, size_t olen )
{
    size_t len;
    rsa_context rsa;
	myprivate_t *mykey = my_prv;
    unsigned char *rsa_ciphertext = input;
    unsigned char *rsa_decrypted  = output;
	
    rsa_init( &rsa, RSA_PKCS_V21, POLARSSL_MD_SHA256 );
    rsa.len = mykey->len;
    mpi_read_string( &rsa.N , 16, (const char*)mykey->n  );
    mpi_read_string( &rsa.E , 16, (const char*)mykey->e  );
    mpi_read_string( &rsa.D , 16, (const char*)mykey->d  );
	

	if( rsa_pkcs1_decrypt( &rsa, RSA_PRIVATE, &len,
				rsa_ciphertext, rsa_decrypted,
				olen ) != 0 )
	{
		return( AURSARET_DECRYT_FAIL );
	}


	return len;
}

AURSARET AURSA_pkcs1_sign_sha1(void* my_prv, 
							void* output,
							unsigned char* sha1sum)
{
	rsa_context rsa;
	myprivate_t *mykey = my_prv;
    unsigned char *rsa_ciphertext  = output;

    rsa_init( &rsa, RSA_PKCS_V15, POLARSSL_MD_SHA1 );
    rsa.len = mykey->len;
    mpi_read_string( &rsa.N , 16, (const char*)mykey->n  );
    mpi_read_string( &rsa.E , 16, (const char*)mykey->e  );
    mpi_read_string( &rsa.D , 16, (const char*)mykey->d  );
	
	
    if( rsa_pkcs1_sign( &rsa, &myrand, NULL, RSA_PRIVATE, SIG_RSA_SHA1, SHA1_SZ,
                        sha1sum, rsa_ciphertext ) != 0 )
	{
        return( AURSARET_SIGN_FAIL );
    }
	return AURSARET_OK;
}

AURSARET AURSA_pkcs1_sign_sha256(void* my_prv, 
								void* output,
								unsigned char* sha256sum)
{
	rsa_context rsa;
	myprivate_t *mykey = my_prv;
	unsigned char* rsa_ciphertext	= output;

    rsa_init( &rsa, RSA_PKCS_V15, POLARSSL_MD_SHA256 );
    rsa.len = mykey->len;
    mpi_read_string( &rsa.N , 16, (const char*)mykey->n  );
    mpi_read_string( &rsa.E , 16, (const char*)mykey->e  );
    mpi_read_string( &rsa.D , 16, (const char*)mykey->d  );
	
	
    if( rsa_pkcs1_sign( &rsa, &myrand, NULL, RSA_PRIVATE, SIG_RSA_SHA256, SHA256_SZ,
                        sha256sum, rsa_ciphertext ) != 0 )
	{
        return( AURSARET_SIGN_FAIL );
    }
	return AURSARET_OK;
}


AURSARET AURSA_pkcs1_verify_sha1(void* my_pub, 
								void* signtext, 
								unsigned char* sha1sum)
{
	rsa_context rsa;
	mypublic_t *mykey				= my_pub;
	unsigned char* rsa_ciphertext	= signtext;
	
    rsa_init( &rsa, RSA_PKCS_V15, POLARSSL_MD_SHA1 );
    rsa.len = mykey->len;
    mpi_read_string( &rsa.N , 16, (const char*)mykey->n  );
    mpi_read_string( &rsa.E , 16, (const char*)mykey->e  );

	if( rsa_pkcs1_verify( &rsa, RSA_PUBLIC, SIG_RSA_SHA1, SHA1_SZ,
				sha1sum, rsa_ciphertext ) != 0 )
	{
		return( AURSARET_VERIFYED_FAIL );
	}
	return AURSARET_OK;

}

AURSARET AURSA_pkcs1_verify_sha256(void* my_pub, 
							void* signtext, 
							unsigned char* sha256sum)
{
	rsa_context rsa;
	mypublic_t *mykey				= my_pub;
	unsigned char* rsa_ciphertext	= signtext;
	
    rsa_init( &rsa, RSA_PKCS_V15, POLARSSL_MD_SHA256 );
    rsa.len = mykey->len;
    mpi_read_string( &rsa.N , 16, (const char*)mykey->n  );
    mpi_read_string( &rsa.E , 16, (const char*)mykey->e  );

	if( rsa_pkcs1_verify( &rsa, RSA_PUBLIC, SIG_RSA_SHA256, SHA256_SZ,
				sha256sum, rsa_ciphertext ) != 0 )
	{
		return( AURSARET_VERIFYED_FAIL );
	}
	return AURSARET_OK;

}


