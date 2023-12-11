/*
 *  The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2011, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  RSA was designed by Ron Rivest, Adi Shamir and Len Adleman.
 *
 *  http://theory.lcs.mit.edu/~rivest/rsapaper.pdf
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap8.pdf
 */

#include "config.h"


#include "rsa.h"
#include "aursa.h"
#include "sha1.h"
#include "sha2.h"
#include "md.h"

#include <stdlib.h>
#include <stdio.h>


#define MD_SHA256	0
#define MD_SHA224	1
#define MD_SHA1		2

#define DBG_PRINT_USE1   1
#if DBG_PRINT_USE1
    #define dbg_printf1(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
    #define dbg_printf1(fmt, ...)
#endif

/*
 * RFC 4231 test vectors
 */
static unsigned char sha2_hmac_test_key2[7][26] =
{
    { "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"
      "\x0C\x0C\x0C\x0C" },      
    { "Jefe" },
    { "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
      "\xAA\xAA\xAA\xAA" },
    { "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
      "\x11\x12\x13\x14\x15\x16\x17\x18\x19" },
    { "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
      "\x0B\x0B\x0B\x0B" },
    { "" }, /* 0xAA 131 times */
    { "" }
};
static unsigned char sha2_hmac_test_key3[7][26] =
{
    { "\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D"
      "\x0D\x0D\x0D\x0D" },      
    { "Jefe" },
    { "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
      "\xAA\xAA\xAA\xAA" },
    { "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
      "\x11\x12\x13\x14\x15\x16\x17\x18\x19" },
    { "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
      "\x0B\x0B\x0B\x0B" },
    { "" }, /* 0xAA 131 times */
    { "" }
};
static const int sha2_hmac_test_keylen2[7] =
{
    20, 4, 20, 25, 20, 131, 131
};

void sha_starts(void* ctx, uint8_t md_type)
{
	if (md_type == MD_SHA1)
		sha1_starts((sha1_context*) ctx);
	else 
		sha2_starts((sha2_context*) ctx);
}

void sha_update(void* ctx, void* input, size_t sz, uint8_t md_type)
{
	if(md_type == MD_SHA1)
		sha1_update((sha1_context*) ctx, (uint8_t*) input, sz);
	else 
		sha2_update((sha2_context*) ctx, (uint8_t*) input, sz);
}

void sha_finish(void* ctx, void* output, uint8_t md_type)
{
	if(md_type == MD_SHA1)
		sha1_finish((sha1_context*) ctx, (uint8_t*) output);
	else 
		sha2_finish((sha2_context*) ctx, (uint8_t*) output);
}

void sha(void* input, size_t ilen, void* output, uint8_t md_type)
{
	if(md_type == MD_SHA1)
		sha1((unsigned char*) input, ilen, (unsigned char*) output);
	else
		sha2((unsigned char*) input, ilen, (unsigned char*) output, 0);
}

/*
 * Initialize an RSA context
 */
void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id )
{
    memset( ctx, 0, sizeof( rsa_context ) );

    ctx->padding = padding;
    ctx->hash_id = hash_id;
}


/*
 * Check a public RSA key
 */
int rsa_check_pubkey( const rsa_context *ctx )
{
    if( !ctx->N.p || !ctx->E.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( ( ctx->N.p[0] & 1 ) == 0 ||
        ( ctx->E.p[0] & 1 ) == 0 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->N ) < 128 ||
        mpi_msb( &ctx->N ) > POLARSSL_MPI_MAX_BITS )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->E ) < 2 ||
        mpi_msb( &ctx->E ) > 64 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    return( 0 );
}

/*
 * Check a private RSA key
 */
int rsa_check_privkey( const rsa_context *ctx )
{
    int ret;
    mpi PQ, DE, P1, Q1, H, I, G, G2, L1, L2, DP, DQ, QP;

    if( ( ret = rsa_check_pubkey( ctx ) ) != 0 )
        return( ret );

    if( !ctx->P.p || !ctx->Q.p || !ctx->D.p )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    mpi_init( &PQ ); mpi_init( &DE ); mpi_init( &P1 ); mpi_init( &Q1 );
    mpi_init( &H  ); mpi_init( &I  ); mpi_init( &G  ); mpi_init( &G2 );
    mpi_init( &L1 ); mpi_init( &L2 ); mpi_init( &DP ); mpi_init( &DQ );
    mpi_init( &QP );

    MPI_CHK( mpi_mul_mpi( &PQ, &ctx->P, &ctx->Q ) );
    MPI_CHK( mpi_mul_mpi( &DE, &ctx->D, &ctx->E ) );
    MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
    MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
    MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
    MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );

    MPI_CHK( mpi_gcd( &G2, &P1, &Q1 ) );
    MPI_CHK( mpi_div_mpi( &L1, &L2, &H, &G2 ) );
    MPI_CHK( mpi_mod_mpi( &I, &DE, &L1  ) );

    MPI_CHK( mpi_mod_mpi( &DP, &ctx->D, &P1 ) );
    MPI_CHK( mpi_mod_mpi( &DQ, &ctx->D, &Q1 ) );
    MPI_CHK( mpi_inv_mod( &QP, &ctx->Q, &ctx->P ) );
    /*
     * Check for a valid PKCS1v2 private key
     */
    if( mpi_cmp_mpi( &PQ, &ctx->N ) != 0 ||
        mpi_cmp_mpi( &DP, &ctx->DP ) != 0 ||
        mpi_cmp_mpi( &DQ, &ctx->DQ ) != 0 ||
        mpi_cmp_mpi( &QP, &ctx->QP ) != 0 ||
        mpi_cmp_int( &L2, 0 ) != 0 ||
        mpi_cmp_int( &I, 1 ) != 0 ||
        mpi_cmp_int( &G, 1 ) != 0 )
    {
        ret = POLARSSL_ERR_RSA_KEY_CHECK_FAILED;
    }

cleanup:
    mpi_free( &PQ ); mpi_free( &DE ); mpi_free( &P1 ); mpi_free( &Q1 );
    mpi_free( &H  ); mpi_free( &I  ); mpi_free( &G  ); mpi_free( &G2 );
    mpi_free( &L1 ); mpi_free( &L2 ); mpi_free( &DP ); mpi_free( &DQ );
    mpi_free( &QP );

    if( ret == POLARSSL_ERR_RSA_KEY_CHECK_FAILED )
        return( ret );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED + ret );

    return( 0 );
}

/*
 * Do an RSA public key operation
 */
int rsa_public( rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret;
    size_t olen;
    mpi T;

    mpi_init( &T );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    olen = ctx->len;
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PUBLIC_FAILED + ret );

    return( 0 );
}

/*
 * Do an RSA private key operation
 */
int rsa_private( rsa_context *ctx,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret;
    size_t olen;
    mpi T, T1, T2;

    mpi_init( &T ); mpi_init( &T1 ); mpi_init( &T2 );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

//#if defined(POLARSSL_RSA_NO_CRT)
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->D, &ctx->N, &ctx->RN ) );
#if 0
    /*
     * faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    MPI_CHK( mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P, &ctx->RP ) );
    MPI_CHK( mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    MPI_CHK( mpi_sub_mpi( &T, &T1, &T2 ) );
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    MPI_CHK( mpi_mod_mpi( &T, &T1, &ctx->P ) );

    /*
     * output = T2 + T * Q
     */
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MPI_CHK( mpi_add_mpi( &T, &T2, &T1 ) );
#endif
    olen = ctx->len;
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T ); mpi_free( &T1 ); mpi_free( &T2 );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PRIVATE_FAILED + ret );

    return( 0 );
}

#if defined(POLARSSL_PKCS1_V21)
/**
 * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * \param dst       buffer to mask
 * \param dlen      length of destination buffer
 * \param src       source of the mask generation
 * \param slen      length of the source buffer
 * \param md_ctx    message digest context to use
 */
 void mgf_mask( unsigned char *dst, size_t dlen, unsigned char *src, size_t slen,
                       md_context_t *md_ctx )
{
    unsigned char mask[POLARSSL_MD_MAX_SIZE];
    unsigned char counter[4];
    unsigned char *p;
    unsigned int hlen;
    size_t i, use_len;

    memset( mask, 0, POLARSSL_MD_MAX_SIZE );
    memset( counter, 0, 4 );

    hlen = md_ctx->md_info->size;

    // Generate and apply dbMask
    //
    p = dst;

    while( dlen > 0 )
    {
        use_len = hlen;
        if( dlen < hlen )
            use_len = dlen;

        md_starts( md_ctx );
        md_update( md_ctx, src, slen );
        md_update( md_ctx, counter, 4 );
        md_finish( md_ctx, mask );

        for( i = 0; i < use_len; ++i )
            *p++ ^= mask[i];

        counter[3]++;

        dlen -= use_len;
    }
}
#endif

#if defined(POLARSSL_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function
 */
int rsa_rsaes_oaep_encrypt( rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output )
{
    size_t olen;
    int ret;
    unsigned char *p = output;
    unsigned int hlen;
    const md_info_t *md_info;
    md_context_t md_ctx;

    if( ctx->padding != RSA_PKCS_V21 || f_rng == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    md_info = md_info_from_type((md_type_t) ctx->hash_id );

    if( md_info == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;
    hlen = md_get_size( md_info );

    if( olen < ilen + 2 * hlen + 2 || f_rng == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    memset( output, 0, olen );

    *p++ = 0;

    // Generate a random octet string seed
    //
    if( ( ret = f_rng( p_rng, p, hlen ) ) != 0 )
        return( POLARSSL_ERR_RSA_RNG_FAILED + ret );

    p += hlen;

    // Construct DB
    //
    md( md_info, label, label_len, p );
    //md( md_info, input, ilen, p );
    p += hlen;
    p += olen - 2 * hlen - 2 - ilen;
    *p++ = 1;
    memcpy( p, input, ilen );

    md_init_ctx( &md_ctx, md_info );

    // maskedDB: Apply dbMask to DB
    //
    mgf_mask( output + hlen + 1, olen - hlen - 1, output + 1, hlen,
               &md_ctx );

    // maskedSeed: Apply seedMask to seed
    //
    mgf_mask( output + 1, hlen, output + hlen + 1, olen - hlen - 1,
               &md_ctx );

    md_free_ctx( &md_ctx );

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, output, output )
            : rsa_private( ctx, output, output ) );
}
#endif /* POLARSSL_PKCS1_V21 */

/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-ENCRYPT function
 */
int rsa_rsaes_pkcs1_v15_encrypt( rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 int mode, size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    size_t nb_pad, olen;
    int ret;
    unsigned char *p = output;

    if( ctx->padding != RSA_PKCS_V15 || f_rng == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    if( olen < ilen + 11 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    nb_pad = olen - 3 - ilen;

    *p++ = 0;
    if( mode == RSA_PUBLIC )
    {
        *p++ = RSA_CRYPT;

        while( nb_pad-- > 0 )
        {
            int rng_dl = 100;

            do {
                ret = f_rng( p_rng, p, 1 );
            } while( *p == 0 && --rng_dl && ret == 0 );

            // Check if RNG failed to generate data
            //
            if( rng_dl == 0 || ret != 0)
                return POLARSSL_ERR_RSA_RNG_FAILED + ret;

            p++;
        }
    }
    else
    {
        *p++ = RSA_SIGN;

        while( nb_pad-- > 0 )
            *p++ = 0xFF;
    }

    *p++ = 0;
    memcpy( p, input, ilen );

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, output, output )
            : rsa_private( ctx, output, output ) );
}

/*
 * Add the message padding, then do an RSA operation
 */
int rsa_pkcs1_encrypt( rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       int mode, size_t ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
    switch( ctx->padding )
    {
        case RSA_PKCS_V15:
            return rsa_rsaes_pkcs1_v15_encrypt( ctx, f_rng, p_rng, mode, ilen,
                                                input, output );

#if defined(POLARSSL_PKCS1_V21)
        case RSA_PKCS_V21:
            return rsa_rsaes_oaep_encrypt( ctx, f_rng, p_rng, mode, NULL, 0,
                                           ilen, input, output );
#endif

        default:
            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(POLARSSL_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function
 */
int rsa_rsaes_oaep_decrypt( rsa_context *ctx,
                            int mode,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len )
{
    int ret;
    size_t ilen;
    unsigned char *p;
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];
    unsigned char lhash[POLARSSL_MD_MAX_SIZE];
    unsigned int hlen;
    const md_info_t *md_info;
    md_context_t md_ctx;

    if( ctx->padding != RSA_PKCS_V21 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ilen = ctx->len;

    if( ilen < 16 || ilen > sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, input, buf )
          : rsa_private( ctx, input, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    if( *p++ != 0 )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    md_info = md_info_from_type( (md_type_t)ctx->hash_id );
    if( md_info == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    hlen = md_get_size( md_info );

    md_init_ctx( &md_ctx, md_info );

    // Generate lHash
    //
    md( md_info, label, label_len, lhash );
    //md( md_info, input, ilen, lhash );

    // seed: Apply seedMask to maskedSeed
    //
    mgf_mask( buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1,
               &md_ctx );

    // DB: Apply dbMask to maskedDB
    //
    mgf_mask( buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen,
               &md_ctx );

    p += hlen;
    md_free_ctx( &md_ctx );

    // Check validity
    //
    if( memcmp( lhash, p, hlen ) != 0 )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    p += hlen;

    while( *p == 0 && p < buf + ilen )
        p++;

    if( p == buf + ilen )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    if( *p++ != 0x01 )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    if (ilen - (p - buf) > output_max_len)
        return( POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE );

    *olen = ilen - (p - buf);
    memcpy( output, p, *olen );

    return( 0 );
}
#endif /* POLARSSL_PKCS1_V21 */

/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT function
 */
int rsa_rsaes_pkcs1_v15_decrypt( rsa_context *ctx,
                                 int mode, size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len)
{
    int ret, correct = 1;
    size_t ilen, pad_count = 0;
    unsigned char *p, *q;
    unsigned char bt;
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];

    if( ctx->padding != RSA_PKCS_V15 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ilen = ctx->len;

    if( ilen < 16 || ilen > sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, input, buf )
          : rsa_private( ctx, input, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    if( *p++ != 0 )
        correct = 0;

    bt = *p++;
    if( ( bt != RSA_CRYPT && mode == RSA_PRIVATE ) ||
        ( bt != RSA_SIGN && mode == RSA_PUBLIC ) )
    {
        correct = 0;
    }

    if( bt == RSA_CRYPT )
    {
        while( *p != 0 && p < buf + ilen - 1 )
            pad_count += ( *p++ != 0 );

        correct &= ( *p == 0 && p < buf + ilen - 1 );

        q = p;

        // Also pass over all other bytes to reduce timing differences
        //
        while ( q < buf + ilen - 1 )
            pad_count += ( *q++ != 0 );

        // Prevent compiler optimization of pad_count
        //
        correct |= pad_count & 0x100000; /* Always 0 unless 1M bit keys */
        p++;
    }
    else
    {
        while( *p == 0xFF && p < buf + ilen - 1 )
            pad_count += ( *p++ == 0xFF );

        correct &= ( *p == 0 && p < buf + ilen - 1 );

        q = p;

        // Also pass over all other bytes to reduce timing differences
        //
        while ( q < buf + ilen - 1 )
            pad_count += ( *q++ != 0 );

        // Prevent compiler optimization of pad_count
        //
        correct |= pad_count & 0x100000; /* Always 0 unless 1M bit keys */
        p++;
    }

    if( correct == 0 )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    if (ilen - (p - buf) > output_max_len)
        return( POLARSSL_ERR_RSA_OUTPUT_TOO_LARGE );

    *olen = ilen - (p - buf);
    memcpy( output, p, *olen );

    return( 0 );
}

/*
 * Do an RSA operation, then remove the message padding
 */
int rsa_pkcs1_decrypt( rsa_context *ctx,
                       int mode, size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len)
{
    switch( ctx->padding )
    {
        case RSA_PKCS_V15:
            return rsa_rsaes_pkcs1_v15_decrypt( ctx, mode, olen, input, output,
                                                output_max_len );

#if defined(POLARSSL_PKCS1_V21)
        case RSA_PKCS_V21:
            return rsa_rsaes_oaep_decrypt( ctx, mode, NULL, 0, olen, input,
                                           output, output_max_len );
#endif

        default:
            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(POLARSSL_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function
 */
int rsa_rsassa_pss_sign( rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         int mode,
                         int hash_id,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig )
{
    size_t olen;
    unsigned char *p = sig;
    unsigned char salt[POLARSSL_MD_MAX_SIZE];
    unsigned int slen, hlen, offset = 0;
    int ret;
    size_t msb;
    const md_info_t *md_info;
    md_context_t md_ctx;

    if( ctx->padding != RSA_PKCS_V21 || f_rng == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    switch( hash_id )
    {

        case SIG_RSA_SHA1:
            hashlen = 20;
            break;

        case SIG_RSA_SHA256:
            hashlen = 32;
            break;

        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    md_info = md_info_from_type( (md_type_t)ctx->hash_id );
    if( md_info == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    hlen = md_get_size( md_info );
    slen = hlen;

    if( olen < hlen + slen + 2 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    memset( sig, 0, olen );

    msb = mpi_msb( &ctx->N ) - 1;

    // Generate salt of length slen
    //
    if( ( ret = f_rng( p_rng, salt, slen ) ) != 0 )
        return( POLARSSL_ERR_RSA_RNG_FAILED + ret );

    // Note: EMSA-PSS encoding is over the length of N - 1 bits
    //
    msb = mpi_msb( &ctx->N ) - 1;
    p += olen - hlen * 2 - 2;
    *p++ = 0x01;
    memcpy( p, salt, slen );
    p += slen;

    md_init_ctx( &md_ctx, md_info );

    // Generate H = Hash( M' )
    //
    md_starts( &md_ctx );
    md_update( &md_ctx, p, 8 );
    md_update( &md_ctx, hash, hashlen );
    md_update( &md_ctx, salt, slen );
    md_finish( &md_ctx, p );

    // Compensate for boundary condition when applying mask
    //
    if( msb % 8 == 0 )
        offset = 1;

    // maskedDB: Apply dbMask to DB
    //
    mgf_mask( sig + offset, olen - hlen - 1 - offset, p, hlen, &md_ctx );

    md_free_ctx( &md_ctx );

    msb = mpi_msb( &ctx->N ) - 1;
    sig[0] &= 0xFF >> ( olen * 8 - msb );

    p += hlen;
    *p++ = 0xBC;

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, sig, sig )
            : rsa_private( ctx, sig, sig ) );
}
#endif /* POLARSSL_PKCS1_V21 */

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-V1_5-SIGN function
 */
/*
 * Do an RSA operation to sign the message digest
 */
int rsa_rsassa_pkcs1_v15_sign( rsa_context *ctx,
                               int mode,
                               int hash_id,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig )
{
    size_t nb_pad, olen;
    unsigned char *p = sig;

    if( ctx->padding != RSA_PKCS_V15 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    switch( hash_id )
    {
        case SIG_RSA_RAW:
            nb_pad = olen - 3 - hashlen;
            break;

        case SIG_RSA_SHA1:
            nb_pad = olen - 3 - 35;
            break;

        case SIG_RSA_SHA256:
            nb_pad = olen - 3 - 51;
            break;

        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    if( ( nb_pad < 8 ) || ( nb_pad > olen ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    *p++ = 0;
    *p++ = RSA_SIGN;
    memset( p, 0xFF, nb_pad );
    p += nb_pad;
    *p++ = 0;

    switch( hash_id )
    {
        case SIG_RSA_RAW:
            memcpy( p, hash, hashlen );
            break;

        case SIG_RSA_SHA1:
            memcpy( p, ASN1_HASH_SHA1, 15 );
            memcpy( p + 15, hash, 20 );
            break;

        case SIG_RSA_SHA256:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 32 );
            p[1] += 32; p[14] = 1; p[18] += 32; break;

        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, sig, sig )
            : rsa_private( ctx, sig, sig ) );
}

/*
 * Do an RSA operation to sign the message digest
 */
int rsa_pkcs1_sign( rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    int mode,
                    int hash_id,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
    switch( ctx->padding )
    {
        case RSA_PKCS_V15:
            return rsa_rsassa_pkcs1_v15_sign( ctx, mode, hash_id,
                                              hashlen, hash, sig );

#if defined(POLARSSL_PKCS1_V21)
        case RSA_PKCS_V21:
            return rsa_rsassa_pss_sign( ctx, f_rng, p_rng, mode, hash_id,
                                        hashlen, hash, sig );
#endif

        default:
            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(POLARSSL_PKCS1_V21)
/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
int rsa_rsassa_pss_verify( rsa_context *ctx,
                           int mode,
                           int hash_id,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           unsigned char *sig )
{
    int ret;
    size_t siglen;
    unsigned char *p;
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];
    unsigned char result[POLARSSL_MD_MAX_SIZE];
    unsigned char zeros[8];
    unsigned int hlen;
    size_t slen, msb;
    const md_info_t *md_info;
    md_context_t md_ctx;

    if( ctx->padding != RSA_PKCS_V21 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    siglen = ctx->len;

    if( siglen < 16 || siglen > sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, sig, buf )
          : rsa_private( ctx, sig, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    if( buf[siglen - 1] != 0xBC )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    switch( hash_id )
    {
        case SIG_RSA_SHA1:
            hashlen = 20;
            break;

        case SIG_RSA_SHA256:
            hashlen = 32;
            break;

        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    md_info = md_info_from_type( (md_type_t)ctx->hash_id );
    if( md_info == NULL )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    hlen = md_get_size( md_info );
    slen = siglen - hlen - 1;

    memset( zeros, 0, 8 );

    // Note: EMSA-PSS verification is over the length of N - 1 bits
    //
    msb = mpi_msb( &ctx->N ) - 1;

    // Compensate for boundary condition when applying mask
    //
    if( msb % 8 == 0 )
    {
        p++;
        siglen -= 1;
    }
    if( buf[0] >> ( 8 - siglen * 8 + msb ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    md_init_ctx( &md_ctx, md_info );

    mgf_mask( p, siglen - hlen - 1, p + siglen - hlen - 1, hlen, &md_ctx );

    buf[0] &= 0xFF >> ( siglen * 8 - msb );

    while( *p == 0 && p < buf + siglen )
        p++;

    if( p == buf + siglen ||
        *p++ != 0x01 )
    {
        md_free_ctx( &md_ctx );
        return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    slen -= p - buf;

    // Generate H = Hash( M' )
    //
    md_starts( &md_ctx );
    md_update( &md_ctx, zeros, 8 );
    md_update( &md_ctx, hash, hashlen );
    md_update( &md_ctx, p, slen );
    md_finish( &md_ctx, result );

    md_free_ctx( &md_ctx );

    if( memcmp( p + slen, result, hlen ) == 0 )
        return( 0 );
    else
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );
}
#endif /* POLARSSL_PKCS1_V21 */

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-v1_5-VERIFY function
 */
int rsa_rsassa_pkcs1_v15_verify( rsa_context *ctx,
                                 int mode,
                                 int hash_id,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 unsigned char *sig )
{
    int ret;
    size_t len, siglen;
    unsigned char *p, c;
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];

    if( ctx->padding != RSA_PKCS_V15 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    siglen = ctx->len;

    if( siglen < 16 || siglen > sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, sig, buf )
          : rsa_private( ctx, sig, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    if( *p++ != 0 || *p++ != RSA_SIGN )
        return( POLARSSL_ERR_RSA_INVALID_PADDING );

    while( *p != 0 )
    {
        if( p >= buf + siglen - 1 || *p != 0xFF )
            return( POLARSSL_ERR_RSA_INVALID_PADDING );
        p++;
    }
    p++;

    len = siglen - ( p - buf );

    if( len == 33 && hash_id == SIG_RSA_SHA1 )
    {
        if( memcmp( p, ASN1_HASH_SHA1_ALT, 13 ) == 0 &&
                memcmp( p + 13, hash, 20 ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }
    if( len == 34 )
    {
        c = p[13];
        p[13] = 0;

        if( memcmp( p, ASN1_HASH_MDX, 18 ) != 0 )
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );

        if( ( c == 2 && hash_id == SIG_RSA_MD2 ) ||
                ( c == 4 && hash_id == SIG_RSA_MD4 ) ||
                ( c == 5 && hash_id == SIG_RSA_MD5 ) )
        {
            if( memcmp( p + 18, hash, 16 ) == 0 )
                return( 0 );
            else
                return( POLARSSL_ERR_RSA_VERIFY_FAILED );
        }
    }

    if( len == 35 && hash_id == SIG_RSA_SHA1 )
    {
        if( memcmp( p, ASN1_HASH_SHA1, 15 ) == 0 &&
                memcmp( p + 15, hash, 20 ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }
    if( ( len == 19 + 28 && p[14] == 4 && hash_id == SIG_RSA_SHA224 ) ||
            ( len == 19 + 32 && p[14] == 1 && hash_id == SIG_RSA_SHA256 ) ||
            ( len == 19 + 48 && p[14] == 2 && hash_id == SIG_RSA_SHA384 ) ||
            ( len == 19 + 64 && p[14] == 3 && hash_id == SIG_RSA_SHA512 ) )
    {
        c = p[1] - 17;
        p[1] = 17;
        p[14] = 0;

        if( p[18] == c &&
                memcmp( p, ASN1_HASH_SHA2X, 18 ) == 0 &&
                memcmp( p + 19, hash, c ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    if( len == hashlen && hash_id == SIG_RSA_RAW )
    {
        if( memcmp( p, hash, hashlen ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    return( POLARSSL_ERR_RSA_INVALID_PADDING );
}

/*
 * Do an RSA operation and check the message digest
 */
int rsa_pkcs1_verify( rsa_context *ctx,
                      int mode,
                      int hash_id,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      unsigned char *sig )
{
    switch( ctx->padding )
    {
        case RSA_PKCS_V15:
            return rsa_rsassa_pkcs1_v15_verify( ctx, mode, hash_id,
                                                hashlen, hash, sig );

        case RSA_PKCS_V21:
            return rsa_rsassa_pss_verify( ctx, mode, hash_id,
                                          hashlen, hash, sig );

        default:
            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }
}

/*
 * Free the components of an RSA key
 */
void rsa_free( rsa_context *ctx )
{
    mpi_free( &ctx->RQ ); mpi_free( &ctx->RP ); mpi_free( &ctx->RN );
    mpi_free( &ctx->QP ); mpi_free( &ctx->DQ ); mpi_free( &ctx->DP );
    mpi_free( &ctx->Q  ); mpi_free( &ctx->P  ); mpi_free( &ctx->D );
    mpi_free( &ctx->E  ); mpi_free( &ctx->N  );
}

/**
 * 
 * @brief       Hex Format Display.
 * @details     Function to create image to create hex file or image to apply to code. \n
 *              uint16_t hmac_printf(uint8_t* print_buf, uint16_t length_buf)
 * @param[in]	print_buf	buffer for display
 * @param[in]	length_buf	Length of buffer for display
 * @return		number of characters for display
 * @see	
*/
uint16_t hmac_printf(uint8_t* print_buf, uint16_t length_buf)
{
	uint16_t idx          = 0;
	uint16_t seperate_idx = 0;
	uint16_t return_val   = 0;


	for(idx = 0,seperate_idx = 0; idx < length_buf; idx++) {
		dbg_printf1("%02X", print_buf[idx]&0xFF);
		if(idx != length_buf -1) dbg_printf1(" ");	
		if(seperate_idx == 15) {
			dbg_printf1("\r\n");
			seperate_idx = 0;
		}
		else {
			seperate_idx++;
		}
		return_val++;
	}
	if(seperate_idx < 15) dbg_printf1("\r\n");
	return return_val;
}

/**
 * 
 * @brief       HMAC sha 256 generate & compare.
 * @details     HMAC-SHA-256 test. \n
 *              void sha2_mac_testing(uint8_t* buff, uint16_t buf_len, uint8_t hmac_idx )
 * @param[in]	buff	    Buffer for HMAC generate
 * @param[in]	buf_len     The number of characters in the buffer for HMAC
 * @param[in]	hmac_idx	Index of the key to be used for HMAC
 * @return		void
 * @see			sha2_Hmac_analysis()
*/
void sha2_mac_testing(uint8_t* buff, uint16_t buf_len, uint8_t hmac_idx )
{
    int i, j, buflen            = 0;
    unsigned char buf[1024]     = {0,};
    unsigned char sha2sum[32]   = {0,};
    unsigned char sha2sum2[32]  = {0,};    
    sha2_context ctx;

    uint16_t idx                = 0;
    uint16_t seperate_idx       = 0;

    dbg_printf1( "  HMAC-SHA-256 test : ");
    sha2_hmac_starts( &ctx, sha2_hmac_test_key2[hmac_idx],
                        sha2_hmac_test_keylen2[hmac_idx], 0 ); //HMAC-SHA-256 test = 0
    sha2_hmac_update( &ctx, buff, buf_len );
    sha2_hmac_finish( &ctx, sha2sum );

    sha2_hmac_starts( &ctx, sha2_hmac_test_key2[hmac_idx],
                        sha2_hmac_test_keylen2[hmac_idx], 0 ); //HMAC-SHA-256 test = 0
    sha2_hmac_update( &ctx, buff, buf_len );
    sha2_hmac_finish( &ctx, sha2sum2 );
    if( memcmp( sha2sum, sha2sum2, 32 ) != 0 ) {
        dbg_printf1( "Failed\n" );
        dbg_printf1( "HMAC Sha256 Diff.\r\n" );
        hmac_printf(sha2sum2, sizeof(sha2sum2));
    }
    else  dbg_printf1( "Passed\n" );

    dbg_printf1("HMAC SHA256 Key Index[%d], Key Length[%d] \r\n", hmac_idx, sha2_hmac_test_keylen2[hmac_idx]);
    dbg_printf1("CipherText[%06d] to HMAC Sha256 text[%02ld]\r\n", buf_len, sizeof(sha2sum));
    hmac_printf(sha2sum, sizeof(sha2sum));   
}

/**
 * 
 * @brief       HMAC sha 256 verify.
 * @details     HMAC-SHA-256 test. \n
 *              uint8_t sha2_Hmac_analysis(uint8_t* buff, uint16_t buf_len, unsigned char* sha2result, uint8_t hmac_idx)
 * @param[in]	buff	    Buffer for HMAC generate
 * @param[in]	buf_len     The number of characters in the buffer for HMAC
 * @param[in]	sha2result  sha2result for HMAC
 * @param[in]	hmac_idx	Index of the key to be used for HMAC
 * @return		success(0) or failure(1)
 * @see			sha2_mac_testing()
*/
uint8_t sha2_Hmac_analysis(uint8_t* buff, uint16_t buf_len, unsigned char* sha2result, uint8_t hmac_idx)
{
    int i, j, buflen            = 0;
    unsigned char sha2sum[32]   = {0,};
    unsigned char sha2sum2[32]  = {0,};
    sha2_context ctx;

    uint16_t idx                = 0;
    uint16_t seperate_idx       = 0;
	uint8_t ret_val             = 0;

    unsigned char testkey[20]  = {0,};

    dbg_printf1( "  HMAC-SHA-256 " );

    sha2_hmac_starts( &ctx, sha2_hmac_test_key2[hmac_idx],
                        sha2_hmac_test_keylen2[hmac_idx], 0 ); //HMAC-SHA-256 test = 0
    sha2_hmac_update( &ctx, buff, buf_len );
    sha2_hmac_finish( &ctx, sha2sum );

    buflen = 32;        
    memcpy(sha2sum2, sha2result, buflen);        

#if 0    
    dbg_printf1("\n");
    hmac_printf(buff, buf_len); 
#endif
    if( memcmp( sha2sum, sha2sum2, buflen ) != 0 ) {
        dbg_printf1( "Failed\n" );
        dbg_printf1("CipherText[%04d] to HMAC Sha256 text[%02ld]\r\n", buf_len, sizeof(sha2sum));
        hmac_printf(sha2sum, sizeof(sha2sum)); 
        ret_val = 1;
    }
    else {
        dbg_printf1( "Successed!\n" );

#if 0  
        hmac_printf(sha2sum, sizeof(sha2sum)); 
#endif        
        ret_val = 0;
    }    
    dbg_printf1("HMAC SHA256 Key Index[%d], Key Length[%d] \r\n", hmac_idx, sha2_hmac_test_keylen2[hmac_idx]);
#if 0    
    memcpy(testkey, sha2_hmac_test_key2[hmac_idx] ,sha2_hmac_test_keylen2[hmac_idx] );
    hmac_printf(testkey, sizeof(testkey)); 
    dbg_printf1("\r\n");
#endif    
    return ret_val;
}

#if 0

/** dependency of CM0plus */
#if 0
int myrand( void *rng_state, unsigned char *output, size_t len )
{

    if( rng_state != NULL )
        rng_state  = NULL;

	Run_CyRng((uint8_t*) output, (uint32_t) len);

    return( 0 );
}
#endif


#if 1
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

#endif
