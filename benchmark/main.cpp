/*
 *  Benchmark demonstration program
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
 */

#include "mbed.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif /* MBEDTLS_CONFIG_FILE */

#include "mbedtls/platform.h"
#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/arc4.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/cmac.h"
#include "mbedtls/blowfish.h"
#include "mbedtls/camellia.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ccm.h"
#include "mbedtls/havege.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"

#define RSA_PRIVATE_KEY_2048                                          \
"-----BEGIN RSA PRIVATE KEY-----\n"                                   \
"MIIEogIBAAKCAQEA2dwVr+IMGEtA2/MCP6fA5eb/6B18Bq6e7gw8brNPkm3E6LyR\n"  \
"4DnMJVxZmw3bPDKBDoKzfntkMESi/Yw5UopLtVfjGfWeQWPClqffLZBsZ60BRAsg\n"  \
"/g+ID5tgzxSuxzftypK59uexOVCAm7hCKZHGO3DbI7bLY27j7VAgEP7d/yuaz5Fx\n"  \
"Kl/vu7shqrBoz6ABJVJD3KC8nUiMRUCXRINmxbyUUjA4DnicZv6+xrGKr36r6M8h\n"  \
"VYLa5msKc8WzbnBWzpUsrpb4/r7ML+qp92gdSfVJ8/bLiU7h2C7faDA59uaqrFK9\n"  \
"xmDdx7FaWhGQs3LWW6w1UNgkPS0FDYUslpsnsQIDAQABAoIBAC7IJNwM5V3+IuJY\n"  \
"T35Nzo1PyloUosJokvY5KGz5Ejg2XBdCDu0gXCcVqqQyGIbXrYDpLhQV+RCoXHun\n"  \
"tdN0oQdC5SB47s/J1Uo2qCUHo0+sBd6PqTkFKsl3KxWssk9TQjvCwC412IefMs69\n"  \
"hW+ZvwCanmQP56LleApIr2oW4KLfW8Ry/QfZlua+dizctdN7+H1mWwgZQTY9T27J\n"  \
"6RtGRA5NVkKVPzIHVJfdpKoO7xGg1g06aEbPB/VmGvZaaFWWnaf7uRvFjLZecBLu\n"  \
"QSx2DA/GDjirlDYj99PJb7DtB4xRtKzsyw0o+xapC8w6OtIl/3xFt9moCu2jGrsx\n"  \
"vpjHdfECgYEA7fSACRseIs9gAIVX8wq6gayTpA47DHYWAD6IQfIj35SJ+AgsvbFF\n"  \
"4AmrwDhcJVPmDy1N4nLBfyGAMt/2CfiYkdkW6QFX/ULRMMBL/G7kWV8hYQDICB2g\n"  \
"xaMRN1lPCmFq6BkSWjwIYTnYDFBDWVm1GVT8TMtJoM8Erej9qC0PeFUCgYEA6mF3\n"  \
"bigO3t8f5sig+XepaftEUbkJMzo72TVRnIR2ycdR2ihelPQ+25g9dwV0ZA5XXhBS\n"  \
"DKOABWjMM739Mwmy9v26Dlmu9R01zHQktMvtEAyfz7lk2NF0aMuj8285OJUBf9bz\n"  \
"Cq3MjtMCD+4CZ6iaEqCdUKOuxfpx5cWVJV+qve0CgYBhD1YaYMFOGaBjFgDl1f51\n"  \
"Xltqk5NqZdBbkSYrIAWZ8RDF5y+4wFJsLAWuhk6vuyUgE66tK3nZzWRpXAkT0B8L\n"  \
"fq1lpXKqj1KcvBNCiEkEW1VWJ+dvyAYIF5eyJ++hoFLnETL3M32HivyhKSwPihPg\n"  \
"nVW8TT9fJJIYDe1JZ/fjcQKBgHJfv7UsrR0LSvkG3K8AOtbx+8PZhOjPuRbk0v+L\n"  \
"EKCkuIe5/XW4vtfQMeZb7hFJgk7vrepm+vkoy8VQKDf4urGW3W1VTHBmobM01hi4\n"  \
"DuYvEul+Mf0wMRtWjJolo4m+BO5KiW2jpFfqFm6JmfjVqOIAKOSKC6am8V/MDF0h\n"  \
"kyN9AoGAT9oOiEXMolbkDZw/QCaBiRoAGlGlNYUkJ+58U6OjIZLISw6aFv+Y2uE0\n"  \
"mEImItjuYZtSYKblWikp6ldPoKlt9bwEFe3c6IZ8kJ3+xyEyAGrvjXjEY7PzP6dp\n"  \
"Ajbjp9X9uocEBv9W/KsBLdQ7yizcL/toHwdBO4vQqmqTvAc5IIw=\n"              \
"-----END RSA PRIVATE KEY-----\n"

#define RSA_PRIVATE_KEY_4096                                          \
"-----BEGIN RSA PRIVATE KEY-----\n"                                   \
"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\n"  \
"-----END RSA PRIVATE KEY-----\n"

#define BUFSIZE         1024
#define HEADER_FORMAT   "  %-24s :  "
#define TITLE_LEN       25

#define BENCHMARK_FUNC_CALL(TITLE, CODE)                                    \
do {                                                                        \
    unsigned long i;                                                        \
    Timeout t;                                                              \
                                                                            \
    mbedtls_printf(HEADER_FORMAT, TITLE);                                   \
    fflush(stdout);                                                         \
                                                                            \
    for (i = 1, alarmed = 0, t.attach(alarm, 1.0); !alarmed; i++)           \
    {                                                                       \
        if ((ret = (CODE)) != 0) {                                          \
            mbedtls_printf("%s returned -0x%04X\n", #CODE, -ret);           \
            goto exit;                                                      \
        }                                                                   \
    }                                                                       \
                                                                            \
    if (ret == 0) {                                                         \
        mbedtls_printf("%9lu KB/s\n", i * BUFSIZE / 1024);                  \
    }                                                                       \
} while(0)

#define BENCHMARK_PUBLIC(TITLE, TYPE, CODE)             \
do {                                                    \
    unsigned long ms;                                   \
    Timer t;                                            \
                                                        \
    mbedtls_printf(HEADER_FORMAT, TITLE);               \
    fflush(stdout);                                     \
                                                        \
    t.start();                                          \
    CODE;                                               \
    t.stop();                                           \
    ms = t.read_ms();                                   \
                                                        \
    if (ret != 0) {                                     \
        mbedtls_printf( "FAILED: -0x%04x\r\n", -ret );  \
        goto exit;                                      \
    } else {                                            \
        mbedtls_printf("%6lu ms/" TYPE, ms);            \
        mbedtls_printf("\r\n");                         \
    }                                                   \
} while(0)

/* Clear some memory that was used to prepare the context */
#if defined(MBEDTLS_ECP_C)
void ecp_clear_precomputed(mbedtls_ecp_group *grp)
{
    if (grp->T != NULL) {
        size_t i;
        for (i = 0; i < grp->T_size; i++) {
            mbedtls_ecp_point_free(&grp->T[i]);
        }
        mbedtls_free(grp->T);
    }
    grp->T = NULL;
    grp->T_size = 0;
}
#else
#define ecp_clear_precomputed( g )
#endif /* MBEDTLS_ECP_C */

static unsigned char buf[BUFSIZE];
static unsigned char tmp[200];
static char title[TITLE_LEN];

static volatile int alarmed;

static void alarm()
{
    alarmed = 1;
}

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
    size_t use_len;
    int rnd;

    if (rng_state != NULL) {
        rng_state  = NULL;
    }

    while (len > 0) {
        use_len = len;
        if (use_len > sizeof(int)) {
            use_len = sizeof(int);
        }

        rnd = rand();
        memcpy(output, &rnd, use_len);
        output += use_len;
        len -= use_len;
    }

    return 0;
}

#if defined(MBEDTLS_MD4_C)
MBED_NOINLINE static int benchmark_md4()
{
    int ret;

    BENCHMARK_FUNC_CALL("MD4", mbedtls_md4_ret(buf, BUFSIZE, tmp));

exit:

    return ret;
}
#endif /* MBEDTLS_MD4_C */

#if defined(MBEDTLS_MD5_C)
MBED_NOINLINE static int benchmark_md5()
{
    int ret;

    BENCHMARK_FUNC_CALL("MD5", mbedtls_md5_ret(buf, BUFSIZE, tmp));

exit:

    return ret;
}
#endif /* MBEDTLS_MD5_C */

#if defined(MBEDTLS_RIPEMD160_C)
MBED_NOINLINE static int benchmark_ripemd160()
{
    int ret;

    BENCHMARK_FUNC_CALL("RIPEMD160", mbedtls_ripemd160_ret(buf, BUFSIZE, tmp));

exit:

    return ret;
}
#endif /* MBEDTLS_RIPEMD160_C */

#if defined(MBEDTLS_SHA1_C)
MBED_NOINLINE static int benchmark_sha1()
{
    int ret;

    BENCHMARK_FUNC_CALL("SHA-1", mbedtls_sha1_ret(buf, BUFSIZE, tmp));

exit:

    return ret;
}
#endif /* MBEDTLS_SHA1_C */

#if defined(MBEDTLS_SHA256_C)
MBED_NOINLINE static int benchmark_sha256()
{
    int ret;

    BENCHMARK_FUNC_CALL("SHA-256", mbedtls_sha256_ret(buf, BUFSIZE, tmp, 0));

exit:

    return ret;
}
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA512_C)
MBED_NOINLINE static int benchmark_sha512()
{
    int ret;

    BENCHMARK_FUNC_CALL("SHA-512", mbedtls_sha512_ret(buf, BUFSIZE, tmp, 0));

exit:

    return ret;
}
#endif /* MBEDTLS_SHA512_C */


#if defined(MBEDTLS_ARC4_C)
MBED_NOINLINE static int benchmark_arc4()
{
    int ret = 0;
    mbedtls_arc4_context arc4;

    mbedtls_arc4_init(&arc4);

    mbedtls_arc4_setup(&arc4, tmp, 32);
    BENCHMARK_FUNC_CALL("ARC4",
                        mbedtls_arc4_crypt(&arc4, BUFSIZE, buf, buf));

exit:
    mbedtls_arc4_free(&arc4);

    return ret;
}
#endif /* MBEDTLS_ARC4_C */

#if defined(MBEDTLS_DES_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
MBED_NOINLINE static int benchmark_des3()
{
    int ret = 0;
    mbedtls_des3_context des3;

    mbedtls_des3_init(&des3);

    if ((ret = mbedtls_des3_set3key_enc(&des3, tmp)) != 0) {
        mbedtls_printf("mbedtls_des3_set3key_enc() returned -0x%04X\n", -ret);
        goto exit;
    }
    BENCHMARK_FUNC_CALL("3DES",
                        mbedtls_des3_crypt_cbc(&des3, MBEDTLS_DES_ENCRYPT,
                                BUFSIZE, tmp, buf, buf));

exit:
    mbedtls_des3_free(&des3);

    return ret;
}
#endif /* MBEDTLS_DES_C && MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_DES_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
MBED_NOINLINE static int benchmark_des()
{
    int ret = 0;
    mbedtls_des_context des;

    mbedtls_des_init(&des);

    if ((ret = mbedtls_des_setkey_enc(&des, tmp)) != 0) {
        mbedtls_printf("mbedtls_des_setkey_enc() returned -0x%04X\n", -ret);
        goto exit;
    }
    BENCHMARK_FUNC_CALL("DES",
                        mbedtls_des_crypt_cbc(&des, MBEDTLS_DES_ENCRYPT,
                                BUFSIZE, tmp, buf, buf));

exit:
    mbedtls_des_free(&des);

    return ret;
}
#endif /* MBEDTLS_DES_C && MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_DES_C) && defined(MBEDTLS_CIPHER_MODE_CBC) && \
    defined(MBEDTLS_CMAC_C)
MBED_NOINLINE static int benchmark_des3_cmac()
{
    int ret = 0;
    unsigned char output[8];
    const mbedtls_cipher_info_t *cipher_info;

    memset(buf, 0, sizeof(buf));
    memset(tmp, 0, sizeof(tmp));

    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_DES_EDE3_ECB);
    if (cipher_info == NULL) {
        mbedtls_printf("mbedtls_cipher_info_from_type() returned NULL\n");
        return -1;
    }

    BENCHMARK_FUNC_CALL("3DES-CMAC",
                        mbedtls_cipher_cmac(cipher_info, tmp, 192, buf,
                                            BUFSIZE, output));

exit:
    return ret;
}
#endif /* MBEDTLS_DES_C && MBEDTLS_CIPHER_MODE_CBC && MBEDTLS_CMAC_C */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
MBED_NOINLINE static int benchmark_aes_cbc()
{
    int ret = 0;
    int keysize;
    mbedtls_aes_context aes;

    mbedtls_aes_init(&aes);

    for (keysize = 128; keysize <= 256; keysize += 64) {
        ret = mbedtls_snprintf(title, sizeof(title), "AES-CBC-%d", keysize);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        memset(buf, 0, sizeof(buf));
        memset(tmp, 0, sizeof(tmp));

        ret = mbedtls_aes_setkey_enc(&aes, tmp, keysize);
        if (ret == MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE) {
            continue;
        } else if (ret != 0) {
            mbedtls_printf("mbedtls_aes_setkey_enc() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        BENCHMARK_FUNC_CALL(title,
                            mbedtls_aes_crypt_cbc(&aes,
                                    MBEDTLS_AES_ENCRYPT, BUFSIZE,
                                    tmp, buf, buf));
    }

exit:
    mbedtls_aes_free(&aes);

    return ret;
}
#endif /* MBEDTLS_AES_C && MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CTR)
MBED_NOINLINE static int benchmark_aes_ctr()
{
    int ret = 0;
    int keysize;
    size_t nc_offset = 0;
    unsigned char stream_block[16];
    mbedtls_aes_context aes;

    mbedtls_aes_init(&aes);

    for (keysize = 128; keysize <= 256; keysize += 64) {
        ret = mbedtls_snprintf(title, sizeof(title), "AES-CTR-%d", keysize);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        memset(buf, 0, sizeof(buf));
        memset(tmp, 0, sizeof(tmp));

        ret = mbedtls_aes_setkey_enc(&aes, tmp, keysize);
        if (ret == MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE) {
            continue;
        } else if (ret != 0) {
            mbedtls_printf("mbedtls_aes_setkey_enc() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        BENCHMARK_FUNC_CALL(title,
                            mbedtls_aes_crypt_ctr(&aes, BUFSIZE, &nc_offset,
                                    tmp, stream_block, buf,
                                    buf));
    }

exit:
    mbedtls_aes_free(&aes);

    return ret;
}
#endif /* MBEDTLS_AES_C && MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_GCM_C)
MBED_NOINLINE static int benchmark_aes_gcm()
{
    int ret = 0;
    int keysize;
    mbedtls_gcm_context gcm;

    mbedtls_gcm_init(&gcm);

    for (keysize = 128; keysize <= 256; keysize += 64) {
        ret = mbedtls_snprintf(title, sizeof(title), "AES-GCM-%d", keysize);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        memset(buf, 0, sizeof(buf));
        memset(tmp, 0, sizeof(tmp));

        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, tmp, keysize);
        if (ret == MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE) {
            continue;
        } else if (ret != 0) {
            mbedtls_printf("mbedtls_gcm_setkey() returned -0x%04X\n", -ret);
            goto exit;
        }

        BENCHMARK_FUNC_CALL(title,
                            mbedtls_gcm_crypt_and_tag(&gcm,
                                    MBEDTLS_GCM_ENCRYPT,
                                    BUFSIZE, tmp, 12, NULL,
                                    0, buf, buf, 16, tmp));
    }

exit:
    mbedtls_gcm_free(&gcm);

    return ret;
}
#endif /* MBEDTLS_AES_C && MBEDTLS_GCM_C */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CCM_C)
MBED_NOINLINE static int benchmark_aes_ccm()
{
    int ret = 0;
    int keysize;
    mbedtls_ccm_context ccm;

    mbedtls_ccm_init(&ccm);

    for (keysize = 128; keysize <= 256; keysize += 64) {
        ret = mbedtls_snprintf(title, sizeof(title), "AES-CCM-%d", keysize);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        memset(buf, 0, sizeof(buf));
        memset(tmp, 0, sizeof(tmp));

        ret = mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, tmp, keysize);
        if (ret != 0) {
            mbedtls_printf("mbedtls_gcm_setkey() returned -0x%04X\n", -ret);
            goto exit;
        }

        BENCHMARK_FUNC_CALL(title,
                            mbedtls_ccm_encrypt_and_tag(&ccm, BUFSIZE, tmp, 12,
                                    NULL, 0, buf, buf, tmp,
                                    16));
    }

exit:
    mbedtls_ccm_free(&ccm);

    return ret;
}
#endif /* MBEDTLS_AES_C && MBEDTLS_CCM_C */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CMAC_C)
MBED_NOINLINE static int benchmark_aes_cmac()
{
    int ret = 0;
    unsigned char output[16];
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_type_t cipher_type;
    int keysize;

    cipher_type = MBEDTLS_CIPHER_AES_128_ECB;
    for (keysize = 128; keysize <= 256; keysize += 64) {
        ret = mbedtls_snprintf(title, sizeof(title), "AES-CMAC-%d", keysize);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        memset(buf, 0, sizeof(buf));
        memset(tmp, 0, sizeof(tmp));

        cipher_info = mbedtls_cipher_info_from_type(cipher_type);
        if (cipher_info == NULL) {
            mbedtls_printf("mbedtls_cipher_info_from_type() returned NULL\n");
            goto exit;
        }

        BENCHMARK_FUNC_CALL(title,
                            mbedtls_cipher_cmac(cipher_info, tmp, keysize,
                                                buf, BUFSIZE, output));
        cipher_type = (mbedtls_cipher_type_t)(cipher_type + 1);
    }

    memset(buf, 0, sizeof(buf));
    memset(tmp, 0, sizeof(tmp));

    BENCHMARK_FUNC_CALL("AES-CMAC-PRF-128",
                        mbedtls_aes_cmac_prf_128(tmp, 16, buf, BUFSIZE,
                                output));

exit:

    return ret;
}
#endif /* MBEDTLS_AES_C && MBEDTLS_CMAC_C */

#if defined(MBEDTLS_CAMELLIA_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
MBED_NOINLINE static int benchmark_camellia()
{
    int ret = 0;
    int keysize;
    mbedtls_camellia_context camellia;

    mbedtls_camellia_init(&camellia);

    for (keysize = 128; keysize <= 256; keysize += 64) {
        ret = mbedtls_snprintf(title, sizeof(title), "CAMELLIA-CBC-%d",
                               keysize);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        memset(buf, 0, sizeof(buf));
        memset(tmp, 0, sizeof(tmp));

        ret = mbedtls_camellia_setkey_enc(&camellia, tmp, keysize);
        if (ret != 0) {
            mbedtls_printf("mbedtls_camellia_setkey_enc() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        BENCHMARK_FUNC_CALL(title,
                            mbedtls_camellia_crypt_cbc(&camellia,
                                    MBEDTLS_CAMELLIA_ENCRYPT,
                                    BUFSIZE, tmp, buf, buf));
    }

exit:
    mbedtls_camellia_free(&camellia);

    return ret;
}
#endif /* MBEDTLS_CAMELLIA_C && MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_BLOWFISH_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
MBED_NOINLINE static int benchmark_blowfish()
{
    int ret = 0;
    int keysize;
    mbedtls_blowfish_context *blowfish;

    blowfish = (mbedtls_blowfish_context *)mbedtls_calloc(1,
               sizeof(mbedtls_blowfish_context *));
    if (blowfish == NULL) {
        mbedtls_printf("Failed to allocate mbedtls_blowfish_context\n");
        return -1;
    }

    mbedtls_blowfish_init(blowfish);

    for (keysize = 128; keysize <= 256; keysize += 64) {
        mbedtls_snprintf(title, sizeof(title), "BLOWFISH-CBC-%d", keysize);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        memset(buf, 0, sizeof(buf));
        memset(tmp, 0, sizeof(tmp));

        if ((ret = mbedtls_blowfish_setkey(blowfish, tmp, keysize)) != 0) {
            mbedtls_printf("mbedtls_blowfish_setkey() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        BENCHMARK_FUNC_CALL(title,
                            mbedtls_blowfish_crypt_cbc(blowfish,
                                    MBEDTLS_BLOWFISH_ENCRYPT,
                                    BUFSIZE,
                                    tmp, buf, buf));
    }

exit:
    mbedtls_blowfish_free(blowfish);
    mbedtls_free(blowfish);

    return ret;
}
#endif /* MBEDTLS_BLOWFISH_C && MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_HAVEGE_C)
MBED_NOINLINE static int benchmark_havege()
{
    int ret = 0;
    mbedtls_havege_state hs;

    mbedtls_havege_init(&hs);

    BENCHMARK_FUNC_CALL("HAVEGE", mbedtls_havege_random(&hs, buf, BUFSIZE));

exit:
    mbedtls_havege_free(&hs);

    return ret;
}
#endif /* MBEDTLS_HAVEGE_C */

#if defined(MBEDTLS_CTR_DRBG_C)
MBED_NOINLINE static int benchmark_ctr_drbg()
{
    int ret = 0;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, myrand, NULL, NULL, 0);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed() returned -0x%04X\n", -ret);
        goto exit;
    }

    BENCHMARK_FUNC_CALL("CTR_DRBG (NOPR)",
                        mbedtls_ctr_drbg_random(&ctr_drbg, buf, BUFSIZE));

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, myrand, NULL, NULL, 0);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ctr_drbg_seed() returned -0x%04X\n", -ret);
        goto exit;
    }

    mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg,
            MBEDTLS_CTR_DRBG_PR_ON);
    BENCHMARK_FUNC_CALL("CTR_DRBG (PR)",
                        mbedtls_ctr_drbg_random(&ctr_drbg, buf, BUFSIZE));

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);

    return ret;
}
#endif /* MBEDTLS_CTR_DRBG_C */

#if defined(MBEDTLS_HMAC_DRBG_C)
MBED_NOINLINE static int benchmark_hmac_drbg()
{
    int ret = 0;
    mbedtls_hmac_drbg_context hmac_drbg;
    const mbedtls_md_info_t *md_info;

    mbedtls_hmac_drbg_init(&hmac_drbg);

#if defined(MBEDTLS_SHA1_C)
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (md_info == NULL) {
        mbedtls_printf("mbedtls_md_info_from_type() returned NULL\n");
        ret = -1;
        goto exit;
    }

    ret = mbedtls_hmac_drbg_seed(&hmac_drbg, md_info, myrand, NULL, NULL, 0);
    if (ret != 0) {
        mbedtls_printf("mbedtls_hmac_drbg_seed() returned -0x%04X\n", -ret);
        goto exit;
    }
    BENCHMARK_FUNC_CALL("HMAC_DRBG SHA-1 (NOPR)",
                        mbedtls_hmac_drbg_random(&hmac_drbg, buf, BUFSIZE));

    ret = mbedtls_hmac_drbg_seed(&hmac_drbg, md_info, myrand, NULL, NULL, 0);
    if (ret != 0) {
        mbedtls_printf("mbedtls_hmac_drbg_seed() returned -0x%04X\n", -ret);
        goto exit;
    }
    mbedtls_hmac_drbg_set_prediction_resistance(&hmac_drbg,
            MBEDTLS_HMAC_DRBG_PR_ON);
    BENCHMARK_FUNC_CALL("HMAC_DRBG SHA-1 (PR)",
                        mbedtls_hmac_drbg_random(&hmac_drbg, buf, BUFSIZE));
#endif /* MBEDTLS_SHA1_C */

#if defined(MBEDTLS_SHA256_C)
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        mbedtls_printf("mbedtls_md_info_from_type() returned -0x%04X\n", -ret);
        goto exit;
    }

    ret = mbedtls_hmac_drbg_seed(&hmac_drbg, md_info, myrand, NULL, NULL, 0);
    if (ret != 0) {
        mbedtls_printf("mbedtls_hmac_drbg_seed() returned -0x%04X\n", -ret);
        goto exit;
    }
    BENCHMARK_FUNC_CALL("HMAC_DRBG SHA-256 (NOPR)",
                        mbedtls_hmac_drbg_random(&hmac_drbg, buf, BUFSIZE));

    ret = mbedtls_hmac_drbg_seed(&hmac_drbg, md_info, myrand, NULL, NULL, 0);
    if (ret != 0) {
        mbedtls_printf("mbedtls_hmac_drbg_seed() returned -0x%04X\n", -ret);
        goto exit;
    }
    mbedtls_hmac_drbg_set_prediction_resistance(&hmac_drbg,
            MBEDTLS_HMAC_DRBG_PR_ON);
    BENCHMARK_FUNC_CALL("HMAC_DRBG SHA-256 (PR)",
                        mbedtls_hmac_drbg_random(&hmac_drbg, buf, BUFSIZE));
#endif /* MBEDTLS_SHA256_C */

exit:
    mbedtls_hmac_drbg_free(&hmac_drbg);

    return ret;
}
#endif /* MBEDTLS_HMAC_DRBG_C */

#if defined(MBEDTLS_RSA_C) && \
    defined(MBEDTLS_PEM_PARSE_C) && defined(MBEDTLS_PK_PARSE_C)
MBED_NOINLINE static int benchmark_rsa()
{
    int ret = 0;
    mbedtls_pk_context pk;
    mbedtls_rsa_context *rsa;
    const char *rsa_keys[] = {
        RSA_PRIVATE_KEY_2048,
        RSA_PRIVATE_KEY_4096,
    };
    size_t i;

    for (i = 0; i < sizeof(rsa_keys) / sizeof(rsa_keys[0]) && ret == 0; i++) {
        mbedtls_pk_init(&pk);

        ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)rsa_keys[i],
                                   strlen(rsa_keys[i]) + 1, NULL, 0);
        if (ret != 0) {
            mbedtls_printf("mbedtls_pk_parse_key() returned -0x%04X\n", -ret);
            goto exit;
        }

        rsa = mbedtls_pk_rsa(pk);

        ret = mbedtls_snprintf(title, sizeof(title), "RSA-%d",
                               mbedtls_pk_get_bitlen(&pk));
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        BENCHMARK_PUBLIC(title, " public",
                         buf[0] = 0;
                         ret = mbedtls_rsa_public(rsa, buf, buf));

        BENCHMARK_PUBLIC(title, "private",
                         buf[0] = 0;
                         ret = mbedtls_rsa_private(rsa, myrand, NULL, buf,
                                 buf));

exit:
        mbedtls_pk_free(&pk);
    }

    return ret;
}
#endif /* MBEDTLS_RSA_C && MBEDTLS_PEM_PARSE_C && MBEDTLS_PK_PARSE_C */

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_BIGNUM_C)
MBED_NOINLINE static int benchmark_dhm()
{
    int ret = 0;
    int dhm_sizes[] = {
        2048,
        3072,
    };
    const char *dhm_P[] = {
        MBEDTLS_DHM_RFC3526_MODP_2048_P,
        MBEDTLS_DHM_RFC3526_MODP_3072_P,
    };
    const char *dhm_G[] = {
        MBEDTLS_DHM_RFC3526_MODP_2048_G,
        MBEDTLS_DHM_RFC3526_MODP_3072_G,
    };

    mbedtls_dhm_context dhm;
    size_t olen;
    size_t i;

    for (i = 0;
            i < sizeof(dhm_sizes) / sizeof(dhm_sizes[0]) && ret == 0;
            i++) {
        mbedtls_dhm_init(&dhm);

        ret = mbedtls_mpi_read_string(&dhm.P, 16, dhm_P[i]);
        if (ret != 0) {
            mbedtls_printf("mbedtls_mpi_read_string() returned -0x%04X\n",
                           -ret);
            goto exit;
        }
        ret = mbedtls_mpi_read_string(&dhm.G, 16, dhm_G[i]);
        if (ret != 0) {
            mbedtls_printf("mbedtls_mpi_read_string() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        dhm.len = mbedtls_mpi_size(&dhm.P);
        ret = mbedtls_dhm_make_public(&dhm, (int) dhm.len, buf, dhm.len,
                                      myrand, NULL);
        if (ret != 0) {
            mbedtls_printf("mbedtls_dhm_make_public() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        ret = mbedtls_mpi_copy(&dhm.GY, &dhm.GX);
        if (ret != 0) {
            mbedtls_printf("mbedtls_mpi_copy() returned -0x%04X\n", -ret);
            goto exit;
        }

        ret = mbedtls_snprintf(title, sizeof(title), "DHE-%d", dhm_sizes[i]);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        BENCHMARK_PUBLIC(title, "handshake",
                         ret  = mbedtls_dhm_make_public(&dhm, (int)dhm.len,
                                 buf, dhm.len, myrand,
                                 NULL);
                         ret |= mbedtls_dhm_calc_secret(&dhm, buf, sizeof(buf),
                                 &olen, myrand, NULL));

        ret = mbedtls_snprintf(title, sizeof(title), "DH-%d", dhm_sizes[i]);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        BENCHMARK_PUBLIC(title, "handshake",
                         ret = mbedtls_dhm_calc_secret(&dhm, buf, sizeof(buf),
                                 &olen, myrand, NULL));

exit:
        mbedtls_dhm_free(&dhm);
    }

    return ret;
}
#endif /* MBEDTLS_DHM_C && MBEDTLS_BIGNUM_C */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_SHA256_C)
MBED_NOINLINE static int benchmark_ecdsa()
{
    int ret = 0;
    mbedtls_ecdsa_context ecdsa;
    const mbedtls_ecp_curve_info *curve_info;
    size_t sig_len;
    size_t hash_len;

    memset(buf, 0x2A, sizeof(buf));

    for (curve_info = mbedtls_ecp_curve_list();
            curve_info->grp_id != MBEDTLS_ECP_DP_NONE && ret == 0;
            curve_info++) {
        mbedtls_ecdsa_init(&ecdsa);

        ret = mbedtls_ecdsa_genkey(&ecdsa, curve_info->grp_id, myrand, NULL);
        if (ret != 0) {
            mbedtls_printf("mbedtls_ecdsa_genkey() returned -0x%04X\n", -ret);
            goto exit;
        }

        ecp_clear_precomputed(&ecdsa.grp);

        ret = mbedtls_snprintf(title, sizeof(title), "ECDSA-%s",
                               curve_info->name);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        hash_len = (curve_info->bit_size + 7) / 8;
        BENCHMARK_PUBLIC(title, "sign",
                         ret = mbedtls_ecdsa_write_signature(&ecdsa,
                                 MBEDTLS_MD_SHA256,
                                 buf, hash_len,
                                 tmp, &sig_len,
                                 myrand, NULL));

        mbedtls_ecdsa_free(&ecdsa);
    }

    for (curve_info = mbedtls_ecp_curve_list();
            curve_info->grp_id != MBEDTLS_ECP_DP_NONE && ret == 0;
            curve_info++) {
        mbedtls_ecdsa_init(&ecdsa);

        ret = mbedtls_ecdsa_genkey(&ecdsa, curve_info->grp_id, myrand, NULL);
        if (ret != 0) {
            mbedtls_printf("mbedtls_ecdsa_genkey() returned -0x%04X\n", -ret);
            goto exit;
        }

        hash_len = (curve_info->bit_size + 7) / 8;
        ret = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, buf,
                                            hash_len, tmp, &sig_len, myrand,
                                            NULL);
        if (ret != 0) {
            mbedtls_printf("mbedtls_ecdsa_write_signature() returned "
                           "-0x%04X\n", -ret);
            goto exit;
        }

        ecp_clear_precomputed(&ecdsa.grp);

        ret = mbedtls_snprintf(title, sizeof(title), "ECDSA-%s",
                               curve_info->name);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        BENCHMARK_PUBLIC(title, "verify",
                         ret = mbedtls_ecdsa_read_signature(&ecdsa, buf,
                                 hash_len, tmp,
                                 sig_len));

exit:
        mbedtls_ecdsa_free(&ecdsa);
    }

    return ret;
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_SHA2565_C */

#if defined(MBEDTLS_ECDH_C)
MBED_NOINLINE static int benchmark_ecdh()
{
    int ret = 0;
    mbedtls_ecdh_context ecdh;
    const mbedtls_ecp_curve_info *curve_info;
    size_t olen;

    for (curve_info = mbedtls_ecp_curve_list();
            curve_info->grp_id != MBEDTLS_ECP_DP_NONE && ret == 0;
            curve_info++) {
        mbedtls_ecdh_init(&ecdh);

        ret = mbedtls_ecp_group_load(&ecdh.grp, curve_info->grp_id);
        if (ret != 0) {
            mbedtls_printf("mbedtls_ecp_group_load() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        ret = mbedtls_ecdh_make_public(&ecdh, &olen, buf, sizeof(buf),
                                       myrand, NULL);
        if (ret != 0) {
            mbedtls_printf("mbedtls_ecdh_make_public() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        ret = mbedtls_ecp_copy(&ecdh.Qp, &ecdh.Q);
        if (ret != 0) {
            mbedtls_printf("mbedtls_ecp_copy() returned -0x%04X\n", -ret);
            goto exit;
        }

        ecp_clear_precomputed(&ecdh.grp);

        ret = mbedtls_snprintf(title, sizeof(title), "ECDHE-%s",
                               curve_info->name);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }

        BENCHMARK_PUBLIC(title, "handshake",
                         ret  = mbedtls_ecdh_make_public(&ecdh, &olen, buf,
                                 sizeof(buf), myrand,
                                 NULL);
                         ret |= mbedtls_ecdh_calc_secret(&ecdh, &olen, buf,
                                 sizeof(buf), myrand,
                                 NULL));
        mbedtls_ecdh_free(&ecdh);
    }

    for (curve_info = mbedtls_ecp_curve_list();
            curve_info->grp_id != MBEDTLS_ECP_DP_NONE && ret == 0;
            curve_info++) {
        mbedtls_ecdh_init(&ecdh);

        ret = mbedtls_ecp_group_load(&ecdh.grp, curve_info->grp_id);
        if (ret != 0) {
            mbedtls_printf("mbedtls_ecp_group_load() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        ret = mbedtls_ecdh_make_public(&ecdh, &olen, buf, sizeof(buf), myrand,
                                       NULL);
        if (ret != 0) {
            mbedtls_printf("mbedtls_ecdh_make_public() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        ret = mbedtls_ecp_copy(&ecdh.Qp, &ecdh.Q);
        if (ret != 0) {
            mbedtls_printf("mbedtls_ecp_copy() returned -0x%04X\n", -ret);
            goto exit;
        }

        ret = mbedtls_ecdh_make_public(&ecdh, &olen, buf, sizeof(buf), myrand,
                                       NULL);
        if (ret != 0) {
            mbedtls_printf("mbedtls_ecdh_make_public() returned -0x%04X\n",
                           -ret);
            goto exit;
        }

        ecp_clear_precomputed(&ecdh.grp);

        ret = mbedtls_snprintf(title, sizeof(title), "ECDH-%s",
                               curve_info->name);
        if (ret < 0 || static_cast<size_t>(ret) >= sizeof(title)) {
            mbedtls_printf("Failed to compose title string using "
                           "mbedtls_snprintf(): %d\n", ret);
            goto exit;
        }
        BENCHMARK_PUBLIC(title, "handshake",
                         ret = mbedtls_ecdh_calc_secret(&ecdh, &olen, buf,
                                 sizeof(buf), myrand,
                                 NULL));

exit:
        mbedtls_ecdh_free(&ecdh);
    }

    return ret;
}
#endif /* MBEDTLS_ECDH_C */

#if defined(MBEDTLS_ECDH_C) && defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
/* Curve25519 needs to be handled separately */
MBED_NOINLINE static int benchmark_ecdh_curve22519()
{
    int ret = 0;
    mbedtls_ecdh_context ecdh;
    mbedtls_mpi z;

    mbedtls_ecdh_init(&ecdh);
    mbedtls_mpi_init(&z);

    ret = mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ecp_group_load() returned -0x%04X\n",
                       -ret);
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Qp, myrand,
                                  NULL);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ecdh_gen_public() returned -0x%04X\n",
                       -ret);
        goto exit;
    }

    BENCHMARK_PUBLIC("ECDHE-Curve25519", "handshake",
                     ret  = mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d,
                             &ecdh.Q, myrand, NULL);
                     ret |= mbedtls_ecdh_compute_shared(&ecdh.grp, &z,
                             &ecdh.Qp, &ecdh.d,
                             myrand, NULL));

    mbedtls_ecdh_free(&ecdh);
    mbedtls_mpi_free(&z);

    mbedtls_ecdh_init(&ecdh);
    mbedtls_mpi_init(&z);

    ret = mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ecp_group_load() returned -0x%04X\n", -ret);
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Qp, myrand, NULL);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ecdh_gen_public() returned -0x%04X\n", -ret);
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Q, myrand, NULL);
    if (ret != 0) {
        mbedtls_printf("mbedtls_ecdh_gen_public() returned -0x%04X\n", -ret);
        goto exit;
    }

    BENCHMARK_PUBLIC("ECDH-Curve25519", "handshake",
                     ret = mbedtls_ecdh_compute_shared(&ecdh.grp, &z,
                             &ecdh.Qp, &ecdh.d,
                             myrand, NULL));

exit:
    mbedtls_ecdh_free(&ecdh);
    mbedtls_mpi_free(&z);

    return ret;
}
#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECP_DP_CURVE25519_ENABLED */

int main()
{
    mbedtls_platform_context platform_ctx;
    int exit_code = MBEDTLS_EXIT_SUCCESS;

    memset(buf, 0xAA, sizeof(buf));
    memset(tmp, 0xBB, sizeof(tmp));

    if ((exit_code = mbedtls_platform_setup(&platform_ctx)) != 0) {
        mbedtls_printf("Platform initialization failed with error %d\r\n",
                       exit_code);
        return MBEDTLS_EXIT_FAILURE;
    }

#if defined(MBEDTLS_MD4_C)
    if (benchmark_md4() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_MD4_C */

#if defined(MBEDTLS_MD5_C)
    if (benchmark_md5() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_MD5_C */

#if defined(MBEDTLS_RIPEMD160_C)
    if (benchmark_ripemd160() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_RIPEMD160_C */

#if defined(MBEDTLS_SHA1_C)
    if (benchmark_sha1() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_SHA1_C */

#if defined(MBEDTLS_SHA256_C)
    if (benchmark_sha256() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA256_C)
    if (benchmark_sha512() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_SHA512_C */

#if defined(MBEDTLS_ARC4_C)
    if (benchmark_arc4() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_ARC4_C */

#if defined(MBEDTLS_DES_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if (benchmark_des3() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_DES_C && MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_DES_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if (benchmark_des() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_DES_C && MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_DES_C) && defined(MBEDTLS_CIPHER_MODE_CBC) && \
    defined(MBEDTLS_CMAC_C)
    if (benchmark_des3_cmac() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_DES_C && MBEDTLS_CIPHER_MODE_CBC && MBEDTLS_CMAC_C */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if (benchmark_aes_cbc() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_AES_C && MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CIPHER_MODE_CTR)
    if (benchmark_aes_ctr() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_AES_C && MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_GCM_C)
    if (benchmark_aes_gcm() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_AES_C && MBEDTLS_GCM_C */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CCM_C)
    if (benchmark_aes_ccm() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_AES_C && MBEDTLS_CCM_C */

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_CMAC_C)
    if (benchmark_aes_cmac() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_AES_C && MBEDTLS_CMAC_C */

#if defined(MBEDTLS_CAMELLIA_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if (benchmark_camellia() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_CAMELLIA_C && MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_BLOWFISH_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
    if (benchmark_blowfish() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_BLOWFISH_C && MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_HAVEGE_C)
    if (benchmark_havege() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_HAVEGE_C */

#if defined(MBEDTLS_CTR_DRBG_C)
    if (benchmark_ctr_drbg() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_CTR_DRBG_C */

#if defined(MBEDTLS_HMAC_DRBG_C)
    if (benchmark_hmac_drbg() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_HMAC_DRBG_C */

#if defined(MBEDTLS_RSA_C) && \
    defined(MBEDTLS_PEM_PARSE_C) && defined(MBEDTLS_PK_PARSE_C)
    if (benchmark_rsa() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_RSA_C && MBEDTLS_PEM_PARSE_C && MBEDTLS_PK_PARSE_C */

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_BIGNUM_C)
    if (benchmark_dhm() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_DHM_C && MBEDTLS_BIGNUM_C */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_SHA256_C)
    if (benchmark_ecdsa() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_SHA2565_C */

#if defined(MBEDTLS_ECDH_C)
    if (benchmark_ecdh() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    if (benchmark_ecdh_curve22519() != 0) {
        exit_code = MBEDTLS_EXIT_FAILURE;
    }
#endif /* MBEDTLS_ECP_DP_CURVE25519_ENABLED */
#endif /* MBEDTLS_ECDH_C */

    mbedtls_printf("DONE\n");

    mbedtls_platform_teardown(&platform_ctx);

    return exit_code;
}
