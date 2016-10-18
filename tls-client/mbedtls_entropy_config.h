/*
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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

#if !defined(MBEDTLS_ENTROPY_HARDWARE_ALT) && !defined(MBEDTLS_ENTROPY_NV_SEED)

#if !defined(MBEDTLS_TEST_NULL_ENTROPY)
#warning                                                                \
    "THIS HARDWARE DOES NOT HAVE ENTROPY. DISABLING MBED TLS SECURITY " \
    "FEATURE."
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#define MBEDTLS_TEST_NULL_ENTROPY
#endif /* !MBEDTLS_TEST_NULL_ENTROPY */

#warning                                                                    \
    "MBED TLS SECURITY FEATURE IS DISABLED. THE TESTS WILL NOT BE SECURE! " \
    "PLEASE IMPLEMENT HARDWARE ENTROPY FOR YOUR SELECTED HARDWARE."

#endif /* !MBEDTLS_ENTROPY_HARDWARE_ALT && !MBEDTLS_ENTROPY_NV_SEED */

#define MBEDTLS_SHA1_C
#define MBEDTLS_MPI_WINDOW_SIZE 1
