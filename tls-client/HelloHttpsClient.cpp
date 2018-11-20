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

#include "HelloHttpsClient.h"

#include "mbedtls/platform.h"
#include "mbedtls/config.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/x509.h"

#include <stdint.h>
#include <string.h>
#include "mbed.h"

const char *HelloHttpsClient::DRBG_PERSONALIZED_STR =
                                                "Mbed TLS helloword client";

const size_t HelloHttpsClient::ERROR_LOG_BUFFER_LENGTH = 128;

const char *HelloHttpsClient::TLS_PEM_CA =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n"
    "ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n"
    "b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n"
    "MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n"
    "b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n"
    "ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n"
    "9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n"
    "IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n"
    "VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n"
    "93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n"
    "jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
    "AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n"
    "A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n"
    "U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n"
    "N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n"
    "o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n"
    "5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n"
    "rqXRfboQnoZsG4q5WTP468SQvvG5\n"
    "-----END CERTIFICATE-----\n";

const char *HelloHttpsClient::HTTP_REQUEST_FILE_PATH =
                                    "/media/uploads/mbed_official/hello.txt";

const char *HelloHttpsClient::HTTP_HELLO_STR = "Hello world!";

const char *HelloHttpsClient::HTTP_OK_STR = "200 OK";

HelloHttpsClient::HelloHttpsClient(const char *in_server_name,
                                   const char *in_server_addr,
                                   const uint16_t in_server_port) :
    socket(),
    server_name(in_server_name),
    server_addr(in_server_addr),
    server_port(in_server_port)
{
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&ssl_conf);
}

HelloHttpsClient::~HelloHttpsClient()
{
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&ssl_conf);

    socket.close();
}

int HelloHttpsClient::run()
{
    int ret;
    size_t req_len, req_offset, resp_offset;
    uint32_t flags;
    bool resp_200, resp_hello;

    /* Configure the TCPSocket */
    if ((ret = configureTCPSocket()) != 0)
        return ret;

    /* Configure already initialized Mbed TLS structures */
    if ((ret = configureTlsContexts()) != 0)
        return ret;

    /* Start a connection to the server */
    if ((ret = socket.connect(server_addr, server_port)) != NSAPI_ERROR_OK) {
        mbedtls_printf("socket.connect() returned %d\n", ret);
        return ret;
    }
    mbedtls_printf("Successfully connected to %s at port %u\n",
                   server_addr, server_port);

    /* Start the TLS handshake */
    mbedtls_printf("Starting the TLS handshake...\n");
    do {
        ret = mbedtls_ssl_handshake(&ssl);
    } while(ret != 0 &&
            (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        mbedtls_printf("mbedtls_ssl_handshake() returned -0x%04X\n", -ret);
        return ret;
    }
    mbedtls_printf("Successfully completed the TLS handshake\n");

    /* Fill the request buffer */
    ret = snprintf(gp_buf, sizeof(gp_buf),
                   "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", HTTP_REQUEST_FILE_PATH,
                   server_name);
    req_len = static_cast<size_t>(ret);
    if (ret < 0 || req_len >= sizeof(gp_buf)) {
        mbedtls_printf("Failed to compose HTTP request using snprintf: %d\n",
                       ret);
        return ret;
    }

    /* Send the HTTP request to the server over TLS */
    req_offset = 0;
    do {
        ret = mbedtls_ssl_write(&ssl,
                reinterpret_cast<const unsigned char *>(gp_buf + req_offset),
                req_len - req_offset);
        if (ret > 0)
            req_offset += static_cast<size_t>(ret);
    }
    while(req_offset < req_len &&
          (ret > 0 ||
          ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
          ret == MBEDTLS_ERR_SSL_WANT_READ));
    if (ret < 0) {
        mbedtls_printf("mbedtls_ssl_write() returned -0x%04X\n", -ret);
        return ret;
    }

    /* Print information about the TLS connection */
    ret = mbedtls_x509_crt_info(gp_buf, sizeof(gp_buf),
                                "\r  ", mbedtls_ssl_get_peer_cert(&ssl));
    if (ret < 0) {
        mbedtls_printf("mbedtls_x509_crt_info() returned -0x%04X\n", -ret);
        return ret;
    }
    mbedtls_printf("Server certificate:\n%s\n", gp_buf);

    /* Ensure certificate verification was successful */
    flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        ret = mbedtls_x509_crt_verify_info(gp_buf, sizeof(gp_buf),
                                           "\r  ! ", flags);
        if (ret < 0) {
            mbedtls_printf("mbedtls_x509_crt_verify_info() returned "
                           "-0x%04X\n", -ret);
            return ret;
        } else {
            mbedtls_printf("Certificate verification failed (flags %lu):"
                           "\n%s\n", flags, gp_buf);
            return -1;
        }
    } else {
        mbedtls_printf("Certificate verification passed\n");
    }

    mbedtls_printf("Established TLS connection to %s\n", server_name);

    /* Read response from the server */
    resp_offset = 0;
    resp_200 = false;
    resp_hello = false;
    do {
        ret = mbedtls_ssl_read(&ssl,
                    reinterpret_cast<unsigned char *>(gp_buf  + resp_offset),
                    sizeof(gp_buf) - resp_offset - 1);
        if (ret > 0)
            resp_offset += static_cast<size_t>(ret);

        /* Ensure that the response string is null-terminated */
        gp_buf[resp_offset] = '\0';

        /* Check  if we received expected string */
        resp_200 = resp_200 || strstr(gp_buf, HTTP_OK_STR) != NULL;
        resp_hello = resp_hello || strstr(gp_buf, HTTP_HELLO_STR) != NULL;
    } while((!resp_200 || !resp_hello) &&
            (ret > 0 ||
            ret == MBEDTLS_ERR_SSL_WANT_READ || MBEDTLS_ERR_SSL_WANT_WRITE));
    if (ret < 0) {
        mbedtls_printf("mbedtls_ssl_read() returned -0x%04X\n", -ret);
        return ret;
    }

    /* Display response information */
    mbedtls_printf("HTTP: Received %u chars from server\n", resp_offset);
    mbedtls_printf("HTTP: Received '%s' status ... %s\n", HTTP_OK_STR,
                   resp_200 ? "OK" : "FAIL");
    mbedtls_printf("HTTP: Received message:\n%s\n", gp_buf);

    return 0;
}

int HelloHttpsClient::configureTCPSocket()
{
    int ret;

    NetworkInterface *network = NetworkInterface::get_default_instance();
    if(network == NULL) {
        mbedtls_printf("ERROR: No network interface found!\n");
        return -1;
    }
    ret = network->connect();
    if (ret != 0) {
        mbedtls_printf("Error! network->connect() returned: %d\n", ret);
        return ret;
    }

    if ((ret = socket.open(network)) != NSAPI_ERROR_OK) {
        mbedtls_printf("socket.open() returned %d\n", ret);
        return ret;
    }

    socket.set_blocking(false);

    return 0;
}

int HelloHttpsClient::configureTlsContexts()
{
    int ret;

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            reinterpret_cast<const unsigned char *>(DRBG_PERSONALIZED_STR),
            strlen(DRBG_PERSONALIZED_STR) + 1);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed() returned -0x%04X\n", -ret);
        return ret;
    }

    ret = mbedtls_x509_crt_parse(&cacert,
                        reinterpret_cast<const unsigned char *>(TLS_PEM_CA),
                        strlen(TLS_PEM_CA) + 1);
    if (ret != 0) {
        mbedtls_printf("mbedtls_x509_crt_parse() returned -0x%04X\n", -ret);
        return ret;
    }

    ret = mbedtls_ssl_config_defaults(&ssl_conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ssl_config_defaults() returned -0x%04X\n",
                       -ret);
        return ret;
    }

    mbedtls_ssl_conf_ca_chain(&ssl_conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    /*
     * It is possible to disable authentication by passing
     * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
     */
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    /* Configure certificate verification function to clear time/date flags */
    mbedtls_ssl_conf_verify(&ssl_conf, sslVerify, this);

#if HELLO_HTTPS_CLIENT_DEBUG_LEVEL > 0
    mbedtls_ssl_conf_dbg(&ssl_conf, sslDebug, NULL);
    mbedtls_debug_set_threshold(HELLO_HTTPS_CLIENT_DEBUG_LEVEL);
#endif /* HELLO_HTTPS_CLIENT_DEBUG_LEVEL > 0 */

    if ((ret = mbedtls_ssl_setup( &ssl, &ssl_conf)) != 0) {
        mbedtls_printf("mbedtls_ssl_setup() returned -0x%04X\n", -ret);
        return ret;
    }

    if ((ret = mbedtls_ssl_set_hostname( &ssl, server_name )) != 0) {
        mbedtls_printf("mbedtls_ssl_set_hostname() returned -0x%04X\n",
                       -ret);
        return ret;
    }

    mbedtls_ssl_set_bio(&ssl, static_cast<void *>(&socket), sslSend, sslRecv,
                        NULL);

    return 0;
}

int HelloHttpsClient::sslRecv(void *ctx, unsigned char *buf, size_t len)
{
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    int ret = socket->recv(buf, len);

    if (ret == NSAPI_ERROR_WOULD_BLOCK)
        ret = MBEDTLS_ERR_SSL_WANT_READ;
    else if (ret < 0)
        mbedtls_printf("socket.recv() returned %d\n", ret);

    return ret;
}

int HelloHttpsClient::sslSend(void *ctx, const unsigned char *buf, size_t len)
{
    TCPSocket *socket = static_cast<TCPSocket *>(ctx);
    int ret = socket->send(buf, len);

    if (ret == NSAPI_ERROR_WOULD_BLOCK)
        ret = MBEDTLS_ERR_SSL_WANT_WRITE;
    else if (ret < 0)
        mbedtls_printf("socket.send() returned %d\n", ret);

    return ret;
}

void HelloHttpsClient::sslDebug(void *ctx, int level, const char *file,
                                int line, const char *str)
{
    (void)ctx;

    const char *p, *basename;

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\')
            basename = p + 1;
    }

    mbedtls_printf("%s:%d: |%d| %s\r", basename, line, level, str);
}

int HelloHttpsClient::sslVerify(void *ctx, mbedtls_x509_crt *crt, int depth,
                                uint32_t *flags)
{
    int ret = 0;

    /*
     * If MBEDTLS_HAVE_TIME_DATE is defined, then the certificate date and time
     * validity checks will probably fail because this application does not set
     * up the clock correctly. We filter out date and time related failures
     * instead
     */
    *flags &= ~MBEDTLS_X509_BADCERT_FUTURE & ~MBEDTLS_X509_BADCERT_EXPIRED;

#if HELLO_HTTPS_CLIENT_DEBUG_LEVEL > 0
    HelloHttpsClient *client = static_cast<HelloHttpsClient *>(ctx);

    ret = mbedtls_x509_crt_info(client->gp_buf, sizeof(gp_buf), "\r  ", crt);
    if (ret < 0) {
        mbedtls_printf("mbedtls_x509_crt_info() returned -0x%04X\n", -ret);
    } else {
        ret = 0;
        mbedtls_printf("Verifying certificate at depth %d:\n%s\n",
                       depth, client->gp_buf);
    }
#endif /* HELLO_HTTPS_CLIENT_DEBUG_LEVEL > 0 */

    return ret;
}
