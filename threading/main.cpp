/*
 *  An example of using mbed TLS in a thread safe manner
 *
 *  Copyright (C) 2016, ARM Limited, All Rights Reserved
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
 */

#include "mbed.h"
#include "rtos.h"
#include "mbedtls/entropy.h"
#include "mbedtls/threading.h"

#define THREADS 2
#define ROUNDS 100

#if defined(MBEDTLS_ENTROPY_SHA512_ACCUMULATOR)
#define HASHSIZE 64
#else
#define HASHSIZE 32
#endif

#define BUFSIZE 64
#define MAIN_ID 0

#define THREAD_CHK(f) do { if( ( ret = f ) != osOK ) goto cleanup; } while( 0 )

const unsigned char data[HASHSIZE] = { 0xaa };

Mutex stdio_mutex;

mbedtls_entropy_context entropy;

void hexify( unsigned char *obuf, const unsigned char *ibuf, int len )
{
    unsigned char l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }

    *obuf = '\0';
}

void notify( const char* message, int thread_id, const int err_code )
{
    stdio_mutex.lock();

    if( err_code )
        printf( "Thread %d: ERR - %s: %d\n\r", thread_id, message, err_code );
    else
        printf( "Thread %d: %s\n\r", thread_id, message );

    stdio_mutex.unlock();
}

void test_thread( void const *args )
{
    int thread_id = *( (int*)args );
    int ret = 0;
    int i;

    for ( i = 0; i < ROUNDS; i++ )
    {

        ret = mbedtls_entropy_update_manual( &entropy, data, BUFSIZE );
        if( 0 != ret )
        {
            notify( "mbed TLS entropy update FAILED", thread_id, ret );
            return;
        }
    }

    notify( " Done.", thread_id, 0 );
}

int main( void )
{
    unsigned char *hash = new unsigned char[HASHSIZE];
    unsigned char *output = new unsigned char[2 * HASHSIZE + 1];
    Thread thread[THREADS * 2];
    int thread_id[THREADS * 2];
    int ret, i;

    /*
     * This calls mbedtls_threading_set_alt and tells the threading
     * abstraction layer in mbed TLS to use the mbed implementation.
     */
#if defined(MBEDTLS_THREADING_ALT)
    mbedtls_threading_set_mbed();
#endif
    mbedtls_entropy_init( &entropy );

    notify( "Starting threads one by one...", MAIN_ID, 0 );
    for( i = 0; i < THREADS; i++ )
    {
        thread_id[i] = i + 1;
        THREAD_CHK( thread[i].start( mbed::callback( test_thread, &thread_id[i] ) ) );
        THREAD_CHK( thread[i].join() );
    }

#if defined(MBEDTLS_ENTROPY_SHA512_ACCUMULATOR)
    mbedtls_sha512_finish( &entropy.accumulator, hash );
#else
    mbedtls_sha256_finish( &entropy.accumulator, hash );
#endif

    hexify( output, hash, HASHSIZE );
    notify( "Printing hash output...", MAIN_ID, 0 );
    notify( (char*)output, MAIN_ID, 0 );

    mbedtls_entropy_init( &entropy );

    notify( "Starting threads...", MAIN_ID, 0 );
    for( i = THREADS; i < 2 * THREADS; i++ )
    {
        thread_id[i] = i + 1;
        THREAD_CHK( thread[i].start( mbed::callback( test_thread, &thread_id[i] ) ) );
    }

    for( i = THREADS; i < 2 * THREADS; i++ )
        THREAD_CHK( thread[i].join() );

#if defined(MBEDTLS_ENTROPY_SHA512_ACCUMULATOR)
    mbedtls_sha512_finish( &entropy.accumulator, hash );
#else
    mbedtls_sha256_finish( &entropy.accumulator, hash );
#endif

    hexify( output, hash, HASHSIZE );
    notify( "Printing hash output...", MAIN_ID, 0 );
    notify( (char*)output, MAIN_ID, 0 );

cleanup:

    if( osOK != ret )
    {
        notify( "RTOS thread operation FAILED", MAIN_ID, ret );

        for( i = 0; i < 2 * THREADS; i++ )
            thread[i].terminate();
    }

#if defined(MBEDTLS_THREADING_ALT)
    mbedtls_entropy_free( &entropy );
#endif
    mbedtls_threading_free_alt();

    notify( "Done.", MAIN_ID, 0 );
}
