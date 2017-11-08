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

#include "authcrypt.h"

#include "mbed.h"

#include "mbedtls/cipher.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#if DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

#include "mbedtls/platform.h"

#include <string.h>

const unsigned char Authcrypt::secret_key[16] = {
    0xf4, 0x82, 0xc6, 0x70, 0x3c, 0xc7, 0x61, 0x0a,
    0xb9, 0xa0, 0xb8, 0xe9, 0x87, 0xb8, 0xc1, 0x72,
};

const char Authcrypt::message[] = "Some things are better left unread";

const char Authcrypt::metadata[] = "eg sequence number, routing info";

Authcrypt::Authcrypt()
{
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(decrypted, 0, sizeof(decrypted));

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_cipher_init(&cipher);
}

Authcrypt::~Authcrypt()
{
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(decrypted, 0, sizeof(decrypted));

    mbedtls_cipher_free(&cipher);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
}

int Authcrypt::run()
{
    mbedtls_printf("\r\n\r\n");
    print_hex("plaintext message",
              reinterpret_cast<const unsigned char *>(message),
              sizeof(message));

    /*
     * Seed the PRNG using the entropy pool, and throw in our secret key as an
     * additional source of randomness.
     */
    int ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                    secret_key, sizeof(secret_key));
    if (ret != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed() returned -0x%04X\r\n", -ret);
        return ret;
    }

    /* Setup AES-CCM contex */
    ret = mbedtls_cipher_setup(&cipher,
                    mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CCM));
    if (ret != 0) {
        mbedtls_printf("mbedtls_cipher_setup() returned -0x%04X\r\n", -ret);
        return ret;
    }

    ret = mbedtls_cipher_setkey(&cipher, secret_key,
                                8 * sizeof(secret_key), MBEDTLS_ENCRYPT);
    if (ret != 0) {
        mbedtls_printf("mbedtls_cipher_setkey() returned -0x%04X\r\n", -ret);
        return ret;
    }

    /*
     * Encrypt-authenticate the message and authenticate additional data
     *
     * First generate a random 8-byte nonce.
     * Put it directly in the output buffer as the recipient will need it.
     *
     * Warning: you must never re-use the same (key, nonce) pair. One of
     * the best ways to ensure this to use a counter for the nonce.
     * However, this means you should save the counter accross rebots, if
     * the key is a long-term one. The alternative we choose here is to
     * generate the nonce randomly. However it only works if you have a
     * good source of randomness.
     */
    const size_t nonce_len = 8;
    mbedtls_ctr_drbg_random(&drbg, ciphertext, nonce_len);

    size_t ciphertext_len = 0;
    /*
     * Go for a conservative 16-byte (128-bit) tag and append it to the
     * ciphertext
     */
    const size_t tag_len = 16;
    ret = mbedtls_cipher_auth_encrypt(&cipher, ciphertext, nonce_len,
                        reinterpret_cast<const unsigned char *>(metadata),
                        sizeof(metadata),
                        reinterpret_cast<const unsigned char *>(message),
                        sizeof(message),
                        ciphertext + nonce_len, &ciphertext_len,
                        ciphertext + nonce_len + sizeof(message),
                        tag_len);
    if (ret != 0) {
        mbedtls_printf("mbedtls_cipher_auth_encrypt() returned -0x%04X\r\n",
                       -ret);
        return ret;
    }
    ciphertext_len += nonce_len + tag_len;

    /*
     * The following information should now be transmitted:
     * - First ciphertext_len bytes of ciphertext buffer
     * - Metadata if not already transmitted elsewhere
     */
    print_hex("ciphertext", ciphertext, ciphertext_len);

    /* Decrypt-authenticate */
    size_t decrypted_len = 0;

    ret = mbedtls_cipher_setkey(&cipher, secret_key, 8 * sizeof(secret_key),
                                MBEDTLS_DECRYPT);
    if (ret != 0) {
        mbedtls_printf("mbedtls_cipher_setkey() returned -0x%04X\r\n", -ret);
        return ret;
    }

    ret = mbedtls_cipher_auth_decrypt(&cipher, ciphertext, nonce_len,
                    reinterpret_cast<const unsigned char *>(metadata),
                    sizeof(metadata), ciphertext + nonce_len,
                    ciphertext_len - nonce_len - tag_len, decrypted,
                    &decrypted_len, ciphertext + ciphertext_len - tag_len,
                    tag_len);
    /* Checking the return code is CRITICAL for security here */
    if (ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED) {
        mbedtls_printf("Something bad is happening! Data is not "
                       "authentic!\r\n");
        return ret;
    } else if (ret != 0) {
        mbedtls_printf("mbedtls_cipher_authdecrypt() returned -0x%04X\r\n",
                       -ret);
        return ret;
    }

    print_hex("decrypted", decrypted, decrypted_len);

    mbedtls_printf("\r\nDONE\r\n");

    return 0;
}

void Authcrypt::print_hex(const char *title,
                          const unsigned char buf[],
                          size_t len)
{
    mbedtls_printf("%s: ", title);

    for (size_t i = 0; i < len; i++)
        mbedtls_printf("%02x", buf[i]);

    mbedtls_printf("\r\n");
}
