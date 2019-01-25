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

/**
 * \file main.cpp
 *
 * \brief An example TLS Client application
 *
 * This application sends an HTTPS request to os.mbed.com and searches
 * for a string in the result.
 *
 * This example is implemented as a logic class (HelloHttpsClient) wrapping a
 * TCP socket. The logic class handles all events, leaving the main loop to just
 * check if the process  has finished.
 */

#include "mbed.h"

#include "mbedtls/platform.h"
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#include "HelloHttpsClient.h"

/* Domain/IP address of the server to contact */
const char SERVER_NAME[] = "os.mbed.com";
const char SERVER_ADDR[] = "os.mbed.com";

/* Port used to connect to the server */
const int SERVER_PORT = 443;

/**
 * The main function driving the HTTPS client.
 */
int main()
{
    int exit_code = MBEDTLS_EXIT_FAILURE;

    if((exit_code = mbedtls_platform_setup(NULL)) != 0) {
        printf("Platform initialization failed with error %d\r\n", exit_code);
        return MBEDTLS_EXIT_FAILURE;
    }

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    /*
     * Initialize underlying PSA Crypto implementation.
     * Even if the HTTPS client doesn't make use of
     * PSA-specific API, for example for setting opaque PSKs
     * or opaque private keys, Mbed TLS will use PSA
     * for public and symmetric key operations as well as
     * hashing.
     */
    psa_status_t status;
    status = psa_crypto_init();
    if( status != PSA_SUCCESS )
    {
        printf("psa_crypto_init() failed with %d\r\n", status );
        return MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    /*
     * The default 9600 bps is too slow to print full TLS debug info and could
     * cause the other party to time out.
     */

    HelloHttpsClient *client;

    mbedtls_printf("Starting mbed-os-example-tls/tls-client\n");

#if defined(MBED_MAJOR_VERSION)
    mbedtls_printf("Using Mbed OS %d.%d.%d\n",
                   MBED_MAJOR_VERSION, MBED_MINOR_VERSION, MBED_PATCH_VERSION);
#else
    printf("Using Mbed OS from master.\n");
#endif /* MBEDTLS_MAJOR_VERSION */

    /* Allocate a HTTPS client */
    client = new (std::nothrow) HelloHttpsClient(SERVER_NAME, SERVER_ADDR, SERVER_PORT);

    if (client == NULL) {
        mbedtls_printf("Failed to allocate HelloHttpsClient object\n"
                       "\nFAIL\n");
        mbedtls_platform_teardown(NULL);
        return exit_code;
    }

    /* Run the client */
    if (client->run() != 0) {
        mbedtls_printf("\nFAIL\n");
    } else {
        exit_code = MBEDTLS_EXIT_SUCCESS;
        mbedtls_printf("\nDONE\n");
    }

    delete client;

    mbedtls_platform_teardown(NULL);
    return exit_code;
}
