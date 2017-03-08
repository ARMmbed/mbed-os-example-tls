/*
 *  Hello world example of a TLS client: fetch an HTTPS page
 *
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
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

#include "HelloHttpsClient.h"

#include "NetworkInterface.h"
#include "TCPSocket.h"

#include "mbedtls/platform.h"
#include "mbedtls/config.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include <stdint.h>
#include <string.h>

HelloHttpsClient::HelloHttpsClient( const char *in_server_name,
                                    const uint16_t in_server_port ) :
    eth_iface( NULL ),
    socket( NULL ),
    server_name( in_server_name ),
    server_port( in_server_port )
{
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&ssl_conf);
}

HelloHttpsClient::~HelloHttpsClient( void )
{
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&ssl_conf);

    if( eth_iface != NULL )
        delete eth_iface;
    if( socket != NULL )
        delete socket;
}

int HelloHttpsClient::createTCPSocket( void )
{
    int ret;
    const char *ip_addr;

    eth_iface = new EthernetInterface();
    if( eth_iface == NULL )
    {
        mbedtls_printf( "Failed to allocate EthernetInterface\r\n" );
        return( -1 );
    }

    /* Initialise the ethernet interface and start up the stack */
    if( ( ret = eth_iface->connect() ) != 0 )
    {
        mbedtls_printf( "Failed call to eth_iface.connect(): %d\r\n", ret );
        return( ret );
    }

    ip_addr = eth_iface->get_ip_address();
    if( ip_addr != NULL )
    {
        mbedtls_printf( "Client IP address is %s\r\n", ip_addr );
    }
    else
    {
        mbedtls_printf( "Failed to get client IP address\r\n" );
        return( -1 );
    }

    /* Create a TCPSocket */
    socket = new TCPSocket( eth_iface );
    if ( socket == NULL )
    {
        mbedtls_printf( "Failed to allocate TCPSocket object\r\n" );
        return( -1 );
    }
    socket->set_blocking( false );

    return( 0 );
}

void HelloHttpsClient::logTlsError( const char *func_name, int ret )
{
    char buf[ERROR_LOG_BUFFER_LENGTH];

    mbedtls_strerror( ret, buf, sizeof( buf ) );
    mbedtls_printf( "Failed call to %s:\r\n", func_name );
    mbedtls_printf( "\t\tError (-0x%04X): %s\r\n", -ret, buf );
}

int HelloHttpsClient::configureTlsContexts( void )
{
    int ret;

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
            reinterpret_cast<const unsigned char *>( DRBG_PERSONALIZED_STR ),
            sizeof( DRBG_PERSONALIZED_STR ) );
    if( ret != 0 )
    {
        logTlsError( "mbedtls_ctr_drbg_seed()", ret );
        return( ret );
    }

    ret = mbedtls_x509_crt_parse( &cacert,
                        reinterpret_cast<const unsigned char *>( TLS_PEM_CA ),
                        sizeof( TLS_PEM_CA ) );
    if( ret != 0 )
    {
        logTlsError( "mbedtls_x509_crt_parse()", ret );
        return( ret );
    }

    ret = mbedtls_ssl_config_defaults( &ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT );
    if( ret != 0 )
    {
        logTlsError( "mbedtls_ssl_config_defaults()", ret );
        return( ret );
    }

    mbedtls_ssl_conf_ca_chain( &ssl_conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg );

    /*
     * It is possible to disable authentication by passing
     * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
     */
    mbedtls_ssl_conf_authmode( &ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED );

#if HELLO_HTTPS_CLIENT_DEBUG_LEVEL > 0
    mbedtls_ssl_conf_verify( &ssl_conf, sslVerify, NULL );
    mbedtls_ssl_conf_dbg( &ssl_conf, sslDebug, NULL );
    mbedtls_debug_set_threshold( HELLO_HTTPS_CLIENT_DEBUG_LEVEL );
#endif /* HELLO_HTTPS_CLIENT_DEBUG_LEVEL > 0 */

    ret = mbedtls_ssl_setup( &ssl, &ssl_conf );
    if( ret != 0 )
    {
        logTlsError( "mbedtls_ssl_setup()", ret );
        return( ret );
    }

    ret = mbedtls_ssl_set_hostname( &ssl, server_name );
    if( ret != 0 )
    {
        logTlsError( "mbedtls_ssl_set_hostname()", ret );
        return( ret );
    }

    mbedtls_ssl_set_bio( &ssl, static_cast<void *>( socket ), sslSend,
                         sslRecv, NULL );

    return( 0 );
}

int HelloHttpsClient::sslRecv( void *ctx, unsigned char *buf, size_t len )
{
    TCPSocket *socket = static_cast<TCPSocket *>( ctx );
    int ret = socket->recv( buf, len );

    if( ret == NSAPI_ERROR_WOULD_BLOCK )
    {
        return( MBEDTLS_ERR_SSL_WANT_READ );
    }
    else if( ret < 0 )
    {
        mbedtls_printf( "Failed call to socket->recv(): %d\r\n", ret );
    }

    return( ret );
}

int HelloHttpsClient::sslSend( void *ctx, const unsigned char *buf, size_t len )
{
    TCPSocket *socket = static_cast<TCPSocket *>( ctx );
    int ret = socket->send( buf, len );

    if( ret == NSAPI_ERROR_WOULD_BLOCK )
    {
        return( MBEDTLS_ERR_SSL_WANT_WRITE );
    }
    else if( ret < 0 )
    {
        mbedtls_printf( "Failed call to socket->send(): %d\r\n", ret );
    }

    return( ret );
}

void HelloHttpsClient::sslDebug( void *ctx, int level, const char *file,
                                 int line, const char *str )
{
    (void)ctx;

    const char *p, *basename;

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
    {
        if( *p == '/' || *p == '\\' )
        {
            basename = p + 1;
        }
    }

    mbedtls_printf( "%s:%d: |%d| %s\r", basename, line, level, str );
}

int HelloHttpsClient::sslVerify( void *data, mbedtls_x509_crt *crt, int depth,
                                 uint32_t *flags )
{
    (void)data;

    int ret = -1;
    char *buf = new char[GENERAL_PURPOSE_BUFFER_LENGTH];

    if( buf == NULL )
    {
        mbedtls_printf( "Failed to allocate sslVerify() buffer\r\n" );
        goto exit;
    }

    ret = mbedtls_x509_crt_info( buf, GENERAL_PURPOSE_BUFFER_LENGTH,
                                 "\r  ", crt );
    if( ret < 0 )
    {
        mbedtls_printf( "Failed call to mbedtls_x509_crt_info(): -0x%04X\r\n",
                        ret );
        goto cleanup;
    }
    else
    {
        mbedtls_printf( "Verifying certificate at depth %d:\r\n%s\r\n",
                        depth, buf );
    }

    ret = 0;

cleanup:
    delete[] buf;

exit:
    return( ret );
}

int HelloHttpsClient::run( void )
{
    int ret;
    size_t req_len, req_offset, resp_offset;
    uint32_t flags;
    bool resp_200, resp_hello;

    /* Configure the EthernetInterface and TCPSocket */
    if( ( ret = createTCPSocket() ) != 0 )
        goto exit;

    /* Configure already initialized mbed TLS structures */
    if( ( ret = configureTlsContexts() ) != 0 )
        goto exit;

    /* Start a connection to the server */
    if( ( ret = socket->connect( server_name, server_port ) ) != NSAPI_ERROR_OK )
    {
        mbedtls_printf( "Failed call to socket->connect(): %d\r\n", ret );
        goto exit;
    }
    else
    {
        mbedtls_printf( "Successfully connected to %s at port %u\r\n",
                        server_name, server_port );
    }

    /* Start the TLS handshake */
    do
    {
        ret = mbedtls_ssl_handshake( &ssl );
    }
    while( ret != 0 && ( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE ) );
    if( ret < 0 )
    {
        logTlsError( "mbedtls_ssl_handshake()", ret );
        goto close_socket;
    }
    else
    {
        mbedtls_printf( "Successfully completed the TLS handshake\r\n" );
    }

    /* Fill the request buffer */
    ret = snprintf( gp_buf, GENERAL_PURPOSE_BUFFER_LENGTH - 1,
                    "GET %s HTTP/1.1\nHost: %s\n\n", HTTP_REQUEST_FILE_PATH,
                    server_name );
    req_len = static_cast<size_t>( ret );
    if( ret < 0 || req_len >= GENERAL_PURPOSE_BUFFER_LENGTH - 1 )
    {
        mbedtls_printf( "Failed to compose HTTP request using snprintf: %d\r\n",
                        ret );
        goto close_socket;
    }

    /* Send the HTTP request to the server over TLS */
    req_offset = 0;
    do
    {
        ret = mbedtls_ssl_write( &ssl,
            reinterpret_cast<const unsigned char *>( gp_buf  + req_offset ),
            req_len - req_offset );
        if( ret > 0 )
        {
            req_offset += static_cast<size_t>( ret );
        }
    }
    while( req_offset < req_len && ( ret > 0 ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE ) );
    if( ret < 0 )
    {
        logTlsError( "mbedtls_ssl_write()", ret );
        goto close_socket;
    }

    /* Print information about the TLS connection */
    ret = mbedtls_x509_crt_info( gp_buf, GENERAL_PURPOSE_BUFFER_LENGTH,
                                 "\r  ", mbedtls_ssl_get_peer_cert( &ssl ) );
    if( ret < 0 )
    {
        logTlsError( "mbedtls_x509_crt_info()", ret );
        goto close_socket;
    }
    else
    {
        mbedtls_printf( "Server certificate:\r\n%s\r", gp_buf );
    }

    /* Ensure certificate verification was successful */
    flags = mbedtls_ssl_get_verify_result( &ssl );
    if( flags != 0 )
    {
        ret = mbedtls_x509_crt_verify_info( gp_buf,
                                            GENERAL_PURPOSE_BUFFER_LENGTH,
                                            "\r  ! ", flags );
        if( ret < 0 )
        {
            logTlsError( "mbedtls_x509_crt_verify_info()", ret );
        }
        else
        {
            mbedtls_printf( "Certificate verification failed:\r\n%s\r\n",
                            gp_buf );
        }
        goto close_socket;
    }
    else
    {
        mbedtls_printf( "Certificate verification passed\r\n\r\n" );
    }

    mbedtls_printf( "Established TLS connection to %s\r\n", server_name );

    /* Read response from the server */
    resp_offset = 0;
    resp_200 = false;
    resp_hello = false;
    do
    {
        ret = mbedtls_ssl_read( &ssl,
                    reinterpret_cast<unsigned char *>( gp_buf  + resp_offset ),
                    GENERAL_PURPOSE_BUFFER_LENGTH - resp_offset - 1 );
        if( ret > 0 )
        {
            resp_offset += static_cast<size_t>( ret );
        }

        /* Ensure that the response string is null-terminated */
        gp_buf[resp_offset] = '\0';

        /* Check  if we received expected string */
        resp_200 = resp_200 || strstr( gp_buf, HTTP_OK_STR ) != NULL;
        resp_hello = resp_hello || strstr( gp_buf, HTTP_HELLO_STR ) != NULL;
    }
    while( ( !resp_200 || !resp_hello ) &&
            ( ret > 0 || ret == MBEDTLS_ERR_SSL_WANT_READ ) );
    if( ret < 0 )
    {
        logTlsError( "mbedtls_ssl_read()", ret );
        goto close_socket;
    }
    gp_buf[resp_offset] = '\0';

    /* Display response information */
    mbedtls_printf( "HTTP: Received %d chars from server\r\n", resp_offset );
    mbedtls_printf( "HTTP: Received '%s' status ... %s\r\n", HTTP_OK_STR,
                    resp_200 ? "OK" : "FAIL" );
    mbedtls_printf( "HTTP: Received message:\r\n%s\r\n", gp_buf );

    /* Connection succeeded */
    ret = 0;

close_socket:
    socket->close();

exit:
    return( ret );
}
