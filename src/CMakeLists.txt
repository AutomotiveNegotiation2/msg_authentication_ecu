#CMAKE_MINIMUM_REQUIRED ( VERSION 2.8 )
 
#PROJECT ( "test_main" )

set (
	SRCS
	bignum.c  
	md.c  
	md_wrap.c  
	rsa.c  
	sha1.c  
	sha2.c
	aursa.c
	aes.c
	camellia.c
	cipher.c
	cipher_wrap.c
	padlock.c            
	)

include_directories( ${CMAKE_SOURCE_DIR}/inc )

add_library ( atmcrypto  ${SRCS})

