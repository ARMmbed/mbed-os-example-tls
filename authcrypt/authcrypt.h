/*
 *  Hello world example of using the authenticated encryption with Mbed TLS
 *
 *  Copyright (C) 2017, Arm Limited, All Rights Reserved
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

#ifndef _AUTHCRYPT_H_
#define _AUTHCRYPT_H_

#include "mbedtls/cipher.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"

/**
 * This class implements the logic to demonstrate authenticated encryption using
 * mbed TLS.
 */
class Authcrypt
{
public:
    /**
     * Construct an Authcrypt instance
     */
    Authcrypt();

    /**
     * Free any allocated resources
     */
    ~Authcrypt();

    /**
     * Run the authenticated encryption example
     *
     * \return  0 if successful
     */
    int run();

private:
    /**
     * Print a buffer's contents in hexadecimal
     *
     * \param[in]   title
     *              The string to print before the hex string
     * \param[in]   buf
     *              The buffer to print in hex
     * \param[in]   len
     *              The length of the buffer
     */
    void print_hex(const char *title, const unsigned char buf[], size_t len);

    /**
     * The pre-shared key
     *
     * \note This should be generated randomly and be unique to the
     *       device/channel/etc. Just used a fixed on here for simplicity.
     */
    static const unsigned char secret_key[16];

    /**
     * Message that should be protected
     */
    static const char message[];

    /**
     * Metadata transmitted in the clear but authenticated
     */
    static const char metadata[];

    /**
     * Ciphertext buffer large enough to hold message + nonce + tag
     */
    unsigned char ciphertext[128];

    /**
     * Plaintext buffer large enough to hold the decrypted message
     */
    unsigned char decrypted[128];

    /**
     * Entropy pool for seeding PRNG
     */
    mbedtls_entropy_context entropy;

    /**
     * Pseudo-random generator
     */
    mbedtls_ctr_drbg_context drbg;

    /**
     * The block cipher configuration
     */
    mbedtls_cipher_context_t cipher;
};

#endif /* _AUTHCRYPT_H_ */
