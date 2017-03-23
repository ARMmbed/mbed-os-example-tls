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

/**
 * \file main.cpp
 *
 * \brief An example TLS Client application
 *
 * This application sends an HTTPS request to developer.mbed.org and searches
 * for a string in the result.
 *
 * This example is implemented as a logic class (HelloHttpsClient) wrapping a
 * TCP socket. The logic class handles all events, leaving the main loop to just
 * check if the process  has finished.
 */

#include "mbed.h"

#include "mbedtls/platform.h"

#include "HelloHttpsClient.h"

/* Domain/IP address of the server to contact */
const char SERVER_NAME[] = "developer.mbed.org";

/* Port used to connect to the server */
const int SERVER_PORT = 443;

/**
 * The main function driving the HTTPS client.
 */
int main( void )
{
    /*
     * The default 9600 bps is too slow to print full TLS debug info and could
     * cause the other party to time out.
     */

    HelloHttpsClient *client;
    int exit_code = MBEDTLS_EXIT_FAILURE;

    /* Allocate a HTTPS client */
    client = new HelloHttpsClient( SERVER_NAME, SERVER_PORT );
    if( client == NULL )
    {
        mbedtls_printf( "Failed to allocate HelloHttpsClient object\r\n" );
        goto exit;
    }

    /* Run the client */
    if( client->run() != 0 )
    {
        goto cleanup;
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

cleanup:
    delete client;

exit:
    if( exit_code == MBEDTLS_EXIT_SUCCESS )
    {
        mbedtls_printf( "DONE\r\n" );
    }
    else
    {
        mbedtls_printf( "FAIL\r\n" );
    }

    return( exit_code );
}
