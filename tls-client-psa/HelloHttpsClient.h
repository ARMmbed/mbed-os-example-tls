/*
 *  Hello world example of a TLS client: fetch an HTTPS page
 *
 *  Copyright (C) 2006-2018, Arm Limited, All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef _HELLOHTTPSCLIENT_H_
#define _HELLOHTTPSCLIENT_H_

#include "TCPSocket.h"

#include "mbedtls/config.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include <stdint.h>

/**
 * Change to a number between 1 and 4 to debug the TLS connection
 */
#define HELLO_HTTPS_CLIENT_DEBUG_LEVEL  0

/**
 * Length (in bytes) for generic buffers used to hold debug or HTTP
 * request/response strings
 */
#define GENERAL_PURPOSE_BUFFER_LENGTH   1024

/**
 * This class implements the logic for fetching a file from a webserver using
 * a TCP socket and parsing the result.
 */
class HelloHttpsClient
{
public:
    /**
     * Construct an HelloHttpsClient instance
     *
     * \param[in]   in_server_name
     *              The server host name
     * \param[in]   in_server_addr
     *              The server domain/IP address
     * \param[in]   in_server_port
     *              The server port
     */
    HelloHttpsClient(const char *in_server_name,
                     const char *in_server_addr,
                     const uint16_t in_server_port);

    /**
     * Free any allocated resources
     */
    ~HelloHttpsClient();

    /**
     * Start the connection to the server and request to read the file at
     * HTTP_REQUEST_FILE_PATH
     *
     * \return  0 if successful
     */
    int run();

private:
    /**
     * Create a TCPSocket object that can be used to communicate with the server
     */
    int configureTCPSocket();

    /**
     * Configure the Mbed TLS structures required to establish a TLS connection
     * with the server
     */
    int configureTlsContexts();

    /**
     * Wrapper function around TCPSocket that gets called by Mbed TLS whenever
     * we call mbedtls_ssl_read()
     *
     * \param[in]   ctx
     *              The TCPSocket object
     * \param[in]   buf
     *              Buffer where data received will be stored
     * \param[in]   len
     *              The length (in bytes) of the buffer
     *
     * \return  If successful, the number of bytes received, a negative value
     *          otherwise.
     */
    static int sslRecv(void *ctx, unsigned char *buf, size_t len);

    /**
     * Wrapper function around TCPSocket that gets called by Mbed TLS whenever
     * we call mbedtls_ssl_write()
     *
     * \param[in]   ctx
     *              The TCPSocket object
     * \param[in]   buf
     *              Buffer containing the data to be sent
     * \param[in]   len
     *              The number of bytes to send
     *
     * \return  If successful, the number of bytes sent, a negative value
     *          otherwise
     */
    static int sslSend(void *ctx, const unsigned char *buf, size_t len);

    /**
     * Callback to handle debug prints to serial
     *
     * \param[in]   ctx
     *              The context (unused in this case)
     * \param[in]   level
     *              The current debug level
     * \param[in]   file
     *              The C file that is logging this message
     * \param[in]   line
     *              The line number in the file
     * \param[in]   str
     *              The string to log to serial
     */
    static void sslDebug(void *ctx, int level, const char *file, int line,
                         const char *str);

    /**
     * Callback to handle certificate verification
     *
     * /param[in]       data
     *                  (unused)
     * /param[in]       crt
     *                  The crt in the chain that we are verifying
     * /param[in]       depth
     *                  The depth of the current certificate in the chain
     * /param[in/out]   flags
     *                  The flags resulting from the verification
     *
     * /return  0 if successful
     */
    static int sslVerify(void *ctx, mbedtls_x509_crt *crt, int depth,
                         uint32_t *flags);

private:
    /**
     * Personalization string for the drbg
     */
    static const char *DRBG_PERSONALIZED_STR;

    /**
     *  Length of error string buffer for logging failures related to Mbed TLS
     */
    static const size_t ERROR_LOG_BUFFER_LENGTH;

    /**
     * Chain of trusted CAs in PEM format
     */
    static const char *TLS_PEM_CA;

    /**
     * Path to the file that will be requested from the server
     */
    static const char *HTTP_REQUEST_FILE_PATH;

    /**
     * Expected strings in the HTTP response from the server
     */
    static const char *HTTP_OK_STR;

    /**
     * Expected strings in the HTTP response from the server
     */
    static const char *HTTP_HELLO_STR;

    /**
     * Instance of TCPSocket used to communicate with the server
     */
    TCPSocket socket;

    /**
     * The server host name to contact
     */
    const char *server_name;

    /**
     * The domain/IP address of the server to contact
     */
    const char *server_addr;
    /**
     * The port number to use in the connection
     */
    const uint16_t server_port;

    /**
     * A generic buffer used to hold debug or HTTP request/response strings
     */
    char gp_buf[GENERAL_PURPOSE_BUFFER_LENGTH];

    /**
     * Entropy context used to seed the DRBG to use in the TLS connection
     */
    mbedtls_entropy_context entropy;
    /**
     * The DRBG used throughout the TLS connection
     */
    mbedtls_ctr_drbg_context ctr_drbg;
    /**
     * The parsed chain of trusted CAs
     */
    mbedtls_x509_crt cacert;
    /**
     * THe TLS context
     */
    mbedtls_ssl_context ssl;
    /**
     * The TLS configuration in use
     */
    mbedtls_ssl_config ssl_conf;
};

#endif /* _HELLOHTTPSCLIENT_H_ */
