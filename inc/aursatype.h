// aursatype.h

#ifndef _AURSATYPE_H_
#define _AURSATYPE_H_

#include <stdint.h>

#define MIN(x,y)        (x)>(y)?(y):(x)
#define MAX(x,y)        (x)>(y)?(x):(y)
#define SHA1_SZ			20
#define SHA256_SZ		32
#define MD_SHA256		0	//message digesting type is sha256
#define MD_SHA1			2	//message digesting type is sha1
#define TXT_BUF_MAX_SZ	2048


typedef struct{
	size_t len;
	const char* n;
	const char* e;
	const char* d;
}myprivate_t;

typedef struct{
	size_t	len;
	const char* n;
	const char* e;
}mypublic_t;


typedef enum _aursa_return{
	AURSARET_OK					= 0x00,
	AURSARET_FAIL				= 0xA0,
	AURSARET_KEYGEN_FAIL,		//0xA1
	AURSARET_PUBLIC_KEY_FAIL,	//0xA2
	AURSARET_PRIVATE_KEY_FAIL,	//0xA3
	AURSARET_HASH_FAIL,			//0xA4
	AURSARET_SIGN_FAIL,			//0xA5
	AURSARET_VERIFYED_FAIL,		//0xA6
	AURSARET_SIZE_FAIL,			//0xA7
	AURSARET_ALLOC_FAIL,		//0xA8
	AURSARET_ALREADY_OPEN,		//0xA9
	AURSARET_ALREADY_CLOSED,	//0xAA
	AURSARET_ENCRYT_FAIL,		//0xAB
	AURSARET_DECRYT_FAIL,		//0xAC
	AURSARET_BAD_INPUT,			//0xAD
	AURSARET_MAX				//0xAE
}aursa_return_t;
#define AURSARET	aursa_return_t


#endif
