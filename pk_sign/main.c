/*
 *  Public key-based signature creation program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_snprintf   snprintf
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SHA256_C) || !defined(MBEDTLS_MD_C) || \
    !defined(MBEDTLS_PK_PARSE_C) || \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_SHA256_C and/or MBEDTLS_MD_C and/or "
           "MBEDTLS_PK_PARSE_C and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\r\n");
    return( 0 );
}
#else

#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls_atca_engine.h"

#include <stdio.h>
#include <string.h>

static int ret = 1;
static mbedtls_pk_context pk, verify_pk;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static unsigned char message[] = "Hello World!";
static unsigned char hash[32];
static unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
static const char *pers = "mbedtls_pk_sign";
static size_t olen = 0;

int main( )
{
    mbedtls_printf( "\r\nPK Sign sample\r\n" );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_pk_init( &pk );
    mbedtls_pk_init( &verify_pk );

    mbedtls_printf( "\r\n  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\r\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\r\n", -ret );
        goto exit;
    }

    ret = mbedtls_atca_pk_setup( &pk, ATCA_ECC_KEY_ID_0 );
    if( ret < 0 )
    {
        mbedtls_printf( " failed\r\n  !  mbedtls_atca_pk_setup returned error!\r\n\r\n" );
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the signature of the hash.
     */
    mbedtls_printf( "\r\n  . Generating the SHA-256 signature" );
    fflush( stdout );

    if( ( ret = mbedtls_md(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    message, sizeof(message), hash ) ) != 0 )
    {
        mbedtls_printf( " failed\r\n  ! mbedtls_md returned -0x%04x\r\n\r\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_pk_sign( &pk, MBEDTLS_MD_SHA256, hash, 0, buf, &olen,
                         mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        mbedtls_printf( " failed\r\n  ! mbedtls_pk_sign returned -0x%04x\r\n", -ret );
        goto exit;
    }

    /*
     * Verify the HW PK generated signature using SW implementation of verify.
     */
    if( ( ret = mbedtls_atca_transparent_pk_setup( &verify_pk, ATCA_ECC_KEY_ID_0 )) != 0 )
    {
        mbedtls_printf( " failed\r\n  ! mbedtls_atca_transparent_pk_setup returned -0x%04x\r\n", -ret );
        goto exit;
    }
    if( ( ret = mbedtls_pk_verify( &verify_pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), buf, olen )) != 0 )
    {
        mbedtls_printf( " failed\r\n  ! mbedtls_pk_verify returned -0x%04x\r\n", -ret );
        goto exit;
    }

    mbedtls_printf( "Signature successfully verified!!!\r\n" );

exit:
    mbedtls_pk_free( &pk );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(MBEDTLS_ERROR_C)
    if( ret != 0 )
    {
        mbedtls_strerror( ret, (char *) buf, sizeof(buf) );
        mbedtls_printf( "  !  Last error was: %s\r\n", buf );
    }
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SHA256_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_CTR_DRBG_C */
