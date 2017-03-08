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

#ifndef _HELLOHTTPSCLIENT_H_
#define _HELLOHTTPSCLIENT_H_

#include "EthernetInterface.h"
#include "TCPSocket.h"

#include "mbedtls/config.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include <stdint.h>

/* Change to a number between 1 and 4 to debug the TLS connection */
#define HELLO_HTTPS_CLIENT_DEBUG_LEVEL  0

/* Personalization string for the drbg */
const char DRBG_PERSONALIZED_STR[] = "mbed TLS helloword client";

/* Length of error string buffer for logging failures related to mbed TLS */
const size_t ERROR_LOG_BUFFER_LENGTH = 128;

/* Chain of trusted CAs in PEM format */
const char TLS_PEM_CA[] = "-----BEGIN CERTIFICATE-----\n"
    "MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG\n"
    "A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\n"
    "b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw\n"
    "MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\n"
    "YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT\n"
    "aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ\n"
    "jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp\n"
    "xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp\n"
    "1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG\n"
    "snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ\n"
    "U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8\n"
    "9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\n"
    "BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B\n"
    "AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz\n"
    "yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE\n"
    "38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP\n"
    "AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad\n"
    "DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME\n"
    "HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\n"
    "-----END CERTIFICATE-----\n";

/* Path to the file that will be requested from the server */
const char HTTP_REQUEST_FILE_PATH[] = "/media/uploads/mbed_official/hello.txt";

/*
 * Length (in bytes) for generic buffers used to hold debug or HTTP
 * request/response strings
 */
const size_t GENERAL_PURPOSE_BUFFER_LENGTH = 1024;

/* Expected strings in the HTTP response from the server */
const char HTTP_OK_STR[] = "200 OK";
const char HTTP_HELLO_STR[] = "Hello world!";

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
     *              The server domain/IP address
     * \param[in]   in_server_port
     *              The server port
     */
    HelloHttpsClient( const char *in_server_name,
                      const uint16_t in_server_port );

    /**
     * Free any allocated resources
     */
    ~HelloHttpsClient( void );

    /**
     * Start the connection to the server and request to read the file at
     * HTTP_REQUEST_FILE_PATH
     *
     * \return  0 if successful
     */
    int run( void );

private:
    /**
     * Create a TCPSocket object that can be used to communicate with the server
     */
    int createTCPSocket( void );

    /**
     * Configure the mbed TLS structures required to establish a TLS connection
     * with the server
     */
    int configureTlsContexts( void );

    /**
     * Log an error message to serial
     *
     * \param[in]   func_name
     *              The name of the mbed TLS function that returned the error
     * \param[in]   ret
     *              The error code returned by the mbed TLS function
     */
    void logTlsError( const char *func_name, int ret );

    /**
     * Wrapper function around TCPSocket that gets called by mbed TLS whenever
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
    static int sslRecv( void *ctx, unsigned char *buf, size_t len );

    /**
     * Wrapper function around TCPSocket that gets called by mbed TLS whenever
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
    static int sslSend( void *ctx, const unsigned char *buf, size_t len );

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
    static void sslDebug( void *ctx, int level, const char *file, int line,
                          const char *str );

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
    static int sslVerify( void *data, mbedtls_x509_crt *crt, int depth,
                          uint32_t *flags );

private:
    /**
     * Instance of EthernetInterface used to create a TCPSocket
     */
    EthernetInterface *eth_iface;
    /**
     * Instance of TCPSocket used to communicate with the server
     */
    TCPSocket *socket;

    /**
     * The domain/IP address of the server to contact
     */
    const char *server_name;
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
