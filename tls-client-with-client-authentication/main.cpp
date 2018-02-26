/*
 *  Hello world example of a TLS client: fetch an HTTPS page
 *
 *  Copyright (C) 2006-2016, Arm Limited, All Rights Reserved
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

/** \file main.cpp
 *  \brief An example TLS Client application
 *  This application sends an HTTPS request to os.mbed.com and searches for a string in
 *  the result.
 *
 *  This example is implemented as a logic class (HelloHTTPS) wrapping a TCP socket.
 *  The logic class handles all events, leaving the main loop to just check if the process
 *  has finished.
 */

/* Change to a number between 1 and 4 to debug the TLS connection */
#define DEBUG_LEVEL 0

#include "mbed.h"
#include "easy-connect.h"

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#if DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

#include "mbedtls_atca_engine.h"

namespace {

const char *HTTPS_SERVER_NAME = "E112111";
const int HTTPS_SERVER_PORT = 4433;
const int RECV_BUFFER_SIZE = 600;

#define GET_REQUEST "GET / HTTP/1.0 \r\n\r\n"

/* personalization string for the drbg */
const char *DRBG_PERS = "ssl_client";

/* Server's root CA certificate
 */
const char SSL_CA_PEM[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIICfDCCAiGgAwIBAgIBADAKBggqhkjOPQQDAjCBnTELMAkGA1UEBhMCR0IxFzAV\r\n"
"BgNVBAgMDkNhbWJyaWRnZXNoaXJlMRIwEAYDVQQHDAlDYW1icmlkZ2UxDjAMBgNV\r\n"
"BAoMBU15IENvMRAwDgYDVQQLDAdNeSBEZXB0MR0wGwYDVQQDDBRtYXppbWtoYW4t\r\n"
"VmlydHVhbEJveDEgMB4GCSqGSIb3DQEJARYRQXppbS5LaGFuQGFybS5jb20wHhcN\r\n"
"MTgwMjAzMDEzMzA3WhcNMjgwMjAxMDEzMzA3WjCBnTELMAkGA1UEBhMCR0IxFzAV\r\n"
"BgNVBAgMDkNhbWJyaWRnZXNoaXJlMRIwEAYDVQQHDAlDYW1icmlkZ2UxDjAMBgNV\r\n"
"BAoMBU15IENvMRAwDgYDVQQLDAdNeSBEZXB0MR0wGwYDVQQDDBRtYXppbWtoYW4t\r\n"
"VmlydHVhbEJveDEgMB4GCSqGSIb3DQEJARYRQXppbS5LaGFuQGFybS5jb20wWTAT\r\n"
"BgcqhkjOPQIBBggqhkjOPQMBBwNCAAS+ImO4q+2w6l8fN3y9dRFgmb4dmaCYIUK6\r\n"
"ZG0hGT/AqLC8ds0al7Mzw8+MUsYNpsxUToFU4EvV3iCxhd2vZFhho1AwTjAdBgNV\r\n"
"HQ4EFgQUBN3Eifs+3C9ZwHMAF3GBPNKDH08wHwYDVR0jBBgwFoAUBN3Eifs+3C9Z\r\n"
"wHMAF3GBPNKDH08wDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAhYwb\r\n"
"wAQiGkOTt/YbdPY1ZuEjCBY6dyqCPI9blT0EVvQCIQCJCSLSQ0IW37SI4RHXuBDZ\r\n"
"fCh27v3WWb8djrwpjSyg+g==\r\n"
"-----END CERTIFICATE-----\r\n";

static const char CLIENT_CERT_PEM[] = 
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBfTCCASGgAwIBAgIBATAMBggqhkjOPQQDAgUAMC8xDTALBgNVBAMTBENlcnQx\r\n"
"ETAPBgNVBAoTCG1iZWQgVExTMQswCQYDVQQGEwJVSzAeFw0wMTAxMDEwMDAwMDBa\r\n"
"Fw0zMDEyMzEyMzU5NTlaMC8xDTALBgNVBAMTBENlcnQxETAPBgNVBAoTCG1iZWQg\r\n"
"VExTMQswCQYDVQQGEwJVSzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOC03rQc\r\n"
"nePEsBd8IVKaBStz2LfRNAXnxbyR7vbdP2qvF72KHfcwj3/EieTz7o0v399J9xBe\r\n"
"Gjviq0DPMLRYpq6jLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFG973jHQ2GP8JXd2\r\n"
"9HUvNT2GWZV2MAwGCCqGSM49BAMCBQADSAAwRQIgP9Dv55CBaj2ZE+XVxkUizE0A\r\n"
"GsdZvOiFnlOICCOyB4gCIQCFqRLUkctB3Anxfqz6E3hjlGk68i5PNnXDvcRkVzQE\r\n"
"Wg==\r\n"
"-----END CERTIFICATE-----\r\n";

}

/**
 * \brief HelloHTTPS implements the logic for fetching a file from a webserver
 * using a TCP socket and parsing the result.
 */
class HelloHTTPS {
public:
    /**
     * HelloHTTPS Constructor
     * Initializes the TCP socket, sets up event handlers and flags.
     *
     * @param[in] domain The domain name to fetch from
     * @param[in] port The port of the HTTPS server
     */
    HelloHTTPS(const char * domain, const uint16_t port, NetworkInterface *net_iface) :
            _domain(domain), _port(port)
    {

        _gothello = false;
        _got200 = false;
        _bpos = 0;
        _request_sent = 0;
        _tcpsocket = new TCPSocket(net_iface);
        _tcpsocket->set_blocking(false);
        _buffer[RECV_BUFFER_SIZE - 1] = 0;

        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
        mbedtls_x509_crt_init(&_cacert);
        mbedtls_x509_crt_init(&_clientcert);
        mbedtls_ssl_init(&_ssl);
        mbedtls_ssl_config_init(&_ssl_conf);
        mbedtls_pk_init( &_clientkey );
    }
    /**
     * HelloHTTPS Desctructor
     */
    ~HelloHTTPS() {
        mbedtls_entropy_free(&_entropy);
        mbedtls_ctr_drbg_free(&_ctr_drbg);
        mbedtls_x509_crt_free(&_cacert);
        mbedtls_x509_crt_free(&_clientcert);
        mbedtls_ssl_free(&_ssl);
        mbedtls_ssl_config_free(&_ssl_conf);
        _tcpsocket->close();
        delete _tcpsocket;
    }
    /**
     * Start the test.
     *
     * Starts by clearing test flags, then resolves the address with DNS.
     *
     * @return SOCKET_ERROR_NONE on success, or an error code on failure
     */
    void startTest() {
        /* Initialize the flags */
        _got200 = false;
        _gothello = false;
        _disconnected = false;
        _request_sent = false;

        /*
         * Initialize TLS-related stuf.
         */
        int ret;
        if ((ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                          (const unsigned char *) DRBG_PERS,
                          sizeof (DRBG_PERS))) != 0) {
            print_mbedtls_error("mbedtls_crt_drbg_init", ret);
            return;
        }

        if ((ret = mbedtls_x509_crt_parse(&_cacert, (const unsigned char *) SSL_CA_PEM,
                           sizeof (SSL_CA_PEM))) != 0) {
            print_mbedtls_error("mbedtls_x509_crt_parse(SSL_CA_PEM)", ret);
            return;
        }
        if ((ret = mbedtls_x509_crt_parse( &_clientcert,
            (const unsigned char *)CLIENT_CERT_PEM,
            sizeof(CLIENT_CERT_PEM))) != 0) {
            print_mbedtls_error("mbedtls_x509_crt_parse(CLIENT_CERT_PEM)", ret);
            return;
        }
        if ((ret = mbedtls_atca_pk_setup( &_clientkey, ATCA_ECC_KEY_ID_0 )) != 0){
            print_mbedtls_error("mbedtls_atca_pk_setup(CLIENT_CERT_PEM)", ret);
            return;
        }

        if ((ret = mbedtls_ssl_config_defaults(&_ssl_conf,
                        MBEDTLS_SSL_IS_CLIENT,
                        MBEDTLS_SSL_TRANSPORT_STREAM,
                        MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
            return;
        }

        mbedtls_ssl_conf_ca_chain(&_ssl_conf, &_cacert, NULL);
        mbedtls_ssl_conf_own_cert( &_ssl_conf, &_clientcert, &_clientkey );
        mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

        /* It is possible to disable authentication by passing
         * MBEDTLS_SSL_VERIFY_NONE in the call to mbedtls_ssl_conf_authmode()
         */
        mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if DEBUG_LEVEL > 0
        mbedtls_ssl_conf_verify(&_ssl_conf, my_verify, NULL);
        mbedtls_ssl_conf_dbg(&_ssl_conf, my_debug, NULL);
        mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

        if ((ret = mbedtls_ssl_setup(&_ssl, &_ssl_conf)) != 0) {
            print_mbedtls_error("mbedtls_ssl_setup", ret);
            return;
        }

        mbedtls_ssl_set_hostname(&_ssl, HTTPS_SERVER_NAME);

        mbedtls_ssl_set_bio(&_ssl, static_cast<void *>(_tcpsocket),
                                   ssl_send, ssl_recv, NULL );


        /* Connect to the server */
        mbedtls_printf("Connecting with %s\n", _domain);
        ret = _tcpsocket->connect(_domain, _port);
        if (ret != NSAPI_ERROR_OK) {
            mbedtls_printf("Failed to connect\n");
            printf("MBED: Socket Error: %d\n", ret);
            _tcpsocket->close();
            return;
        }

       /* Start the handshake, the rest will be done in onReceive() */
        mbedtls_printf("Starting the TLS handshake...\n");
        do {
            ret = mbedtls_ssl_handshake(&_ssl);
        } while (ret != 0 && (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE));
        if (ret < 0) {
            print_mbedtls_error("mbedtls_ssl_handshake", ret);
            _tcpsocket->close();
            return;
        }

        /* It also means the handshake is done, time to print info */
        printf("TLS connection to %s established\n", HTTPS_SERVER_NAME);

        const uint32_t buf_size = 1024;
        char *buf = new char[buf_size];
        if (buf == NULL)
        {
            mbedtls_printf("Memory allocation failure!\n");
            return;
        }
        mbedtls_x509_crt_info(buf, buf_size, "\r    ",
                        mbedtls_ssl_get_peer_cert(&_ssl));
        mbedtls_printf("Server certificate:\n%s", buf);

        uint32_t flags = mbedtls_ssl_get_verify_result(&_ssl);
        if( flags != 0 )
        {
            mbedtls_x509_crt_verify_info(buf, buf_size, "\r  ! ", flags);
            printf("Certificate verification failed:\n%s\n", buf);
        }
        else
            printf("Certificate verification passed\n\n");
        delete buf;

        size_t offset = 0;
        do {
            ret = mbedtls_ssl_write(&_ssl,
                                    (const unsigned char *) GET_REQUEST + offset,
                                    sizeof(GET_REQUEST) - 1 - offset);
            if (ret > 0)
              offset += ret;
        } while ((offset < sizeof(GET_REQUEST) - 1) && (ret > 0 || ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE));
        if (ret < 0) {
            print_mbedtls_error("mbedtls_ssl_write", ret);
            _tcpsocket->close();
            return;
        }

        /* Read data out of the socket */
        offset = 0;
        do {
            ret = mbedtls_ssl_read(&_ssl, (unsigned char *) _buffer,
                                   sizeof(_buffer) - 1);
            if (ret > 0)
            {
                _buffer[ret] = '\0';
                mbedtls_printf( " %d bytes read\r\n\n%s\r\n", ret, _buffer );
            }
        } while (ret > 0 || ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE);
        if (ret < 0 && ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            print_mbedtls_error("mbedtls_ssl_read", ret);
        }

        /* Close socket before status */
        _tcpsocket->close();
    }

protected:
    /**
     * Helper for pretty-printing mbed TLS error codes
     */
    static void print_mbedtls_error(const char *name, int err) {
        char buf[128];
        mbedtls_strerror(err, buf, sizeof (buf));
        mbedtls_printf("%s() failed: -0x%04x (%d): %s\n", name, -err, err, buf);
    }

#if DEBUG_LEVEL > 0
    /**
     * Debug callback for Mbed TLS
     * Just prints on the USB serial port
     */
    static void my_debug(void *ctx, int level, const char *file, int line,
                         const char *str)
    {
        const char *p, *basename;
        (void) ctx;

        /* Extract basename from file */
        for(p = basename = file; *p != '\0'; p++) {
            if(*p == '/' || *p == '\\') {
                basename = p + 1;
            }
        }

        mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
    }

    /**
     * Certificate verification callback for Mbed TLS
     * Here we only use it to display information on each cert in the chain
     */
    static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
    {
        const uint32_t buf_size = 1024;
        char *buf = new char[buf_size];
        (void) data;

        mbedtls_printf("\nVerifying certificate at depth %d:\n", depth);
        mbedtls_x509_crt_info(buf, buf_size - 1, "  ", crt);
        mbedtls_printf("%s", buf);

        if (*flags == 0)
            mbedtls_printf("No verification issue for this certificate\n");
        else
        {
            mbedtls_x509_crt_verify_info(buf, buf_size, "  ! ", *flags);
            mbedtls_printf("%s\n", buf);
        }

        delete[] buf;
        return 0;
    }
#endif

    /**
     * Receive callback for Mbed TLS
     */
    static int ssl_recv(void *ctx, unsigned char *buf, size_t len) {
        int recv = -1;
        TCPSocket *socket = static_cast<TCPSocket *>(ctx);
        recv = socket->recv(buf, len);

        if(NSAPI_ERROR_WOULD_BLOCK == recv){
            return MBEDTLS_ERR_SSL_WANT_READ;
        }else if(recv < 0){
            mbedtls_printf("Socket recv error %d\n", recv);
            return -1;
        }else{
            return recv;
        }
   }

    /**
     * Send callback for Mbed TLS
     */
    static int ssl_send(void *ctx, const unsigned char *buf, size_t len) {
       int size = -1;
        TCPSocket *socket = static_cast<TCPSocket *>(ctx);
        size = socket->send(buf, len);

        if(NSAPI_ERROR_WOULD_BLOCK == size){
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }else if(size < 0){
            mbedtls_printf("Socket send error %d\n", size);
            return -1;
        }else{
            return size;
        }
    }

protected:
    TCPSocket* _tcpsocket;

    const char *_domain;            /**< The domain name of the HTTPS server */
    const uint16_t _port;           /**< The HTTPS server port */
    char _buffer[RECV_BUFFER_SIZE]; /**< The response buffer */
    size_t _bpos;                   /**< The current offset in the response buffer */
    volatile bool _got200;          /**< Status flag for HTTPS 200 */
    volatile bool _gothello;        /**< Status flag for finding the test string */
    volatile bool _disconnected;
    volatile bool _request_sent;

    mbedtls_entropy_context _entropy;
    mbedtls_ctr_drbg_context _ctr_drbg;
    mbedtls_x509_crt _cacert;
    mbedtls_x509_crt _clientcert;
    mbedtls_ssl_context _ssl;
    mbedtls_ssl_config _ssl_conf;
    mbedtls_pk_context _clientkey;
};

/**
 * The main loop of the HTTPS Hello World test
 */
int main() {
    /* The default 9600 bps is too slow to print full TLS debug info and could
     * cause the other party to time out. */

    printf("\nStarting mbed-os-example-tls/tls-client\n");
#if defined(MBED_MAJOR_VERSION)
    printf("Using Mbed OS %d.%d.%d\n", MBED_MAJOR_VERSION, MBED_MINOR_VERSION, MBED_PATCH_VERSION);
#else
    printf("Using Mbed OS from master.\n");
#endif

    /* Use the easy-connect lib to support multiple network bearers.   */
    /* See https://github.com/ARMmbed/easy-connect README.md for info. */

#if DEBUG_LEVEL > 0
    NetworkInterface* network = easy_connect(true);
#else
    NetworkInterface* network = easy_connect(false);
#endif /* DEBUG_LEVEL > 0 */
    if (NULL == network) {
        printf("Connecting to the network failed... See serial output.\n");
        return 1;
    }

    HelloHTTPS *hello = new HelloHTTPS(HTTPS_SERVER_NAME, HTTPS_SERVER_PORT, network);
    hello->startTest();
    delete hello;
}
