# mbed TLS Benchmark example on mbed OS

This application benchmarks the various cryptographic primitives offered by mbed TLS.

# Getting started

Set up your environment if you have not done so already. For instructions, refer to the [main readme](../README.md).

## Monitoring the application

The output in the terminal window should be similar to this:

```
  SHA-256                  :       1673 Kb/s,         70 cycles/byte
  SHA-512                  :        546 Kb/s,        215 cycles/byte
  AES-CBC-128              :       1428 Kb/s,         82 cycles/byte
  AES-CBC-192              :       1260 Kb/s,         93 cycles/byte
  AES-CBC-256              :       1127 Kb/s,        104 cycles/byte
  AES-GCM-128              :        486 Kb/s,        242 cycles/byte
  AES-GCM-192              :        464 Kb/s,        253 cycles/byte
  AES-GCM-256              :        445 Kb/s,        264 cycles/byte
  AES-CCM-128              :        610 Kb/s,        192 cycles/byte
  AES-CCM-192              :        547 Kb/s,        214 cycles/byte
  AES-CCM-256              :        496 Kb/s,        237 cycles/byte
  CTR_DRBG (NOPR)          :       1139 Kb/s,        102 cycles/byte
  CTR_DRBG (PR)            :        826 Kb/s,        142 cycles/byte
  HMAC_DRBG SHA-256 (NOPR) :        193 Kb/s,        611 cycles/byte
  HMAC_DRBG SHA-256 (PR)   :        170 Kb/s,        695 cycles/byte
  RSA-2048                 :      28 ms/ public
  RSA-2048                 :     953 ms/private
  RSA-4096                 :      93 ms/ public
  RSA-4096                 :    5327 ms/private
  ECDSA-secp384r1          :     451 ms/sign
  ECDSA-secp256r1          :     304 ms/sign
  ECDSA-secp384r1          :     863 ms/verify
  ECDSA-secp256r1          :     594 ms/verify
  ECDHE-secp384r1          :     829 ms/handshake
  ECDHE-secp256r1          :     566 ms/handshake
  ECDHE-Curve25519         :     533 ms/handshake
  ECDH-secp384r1           :     407 ms/handshake
  ECDH-secp256r1           :     281 ms/handshake
  ECDH-Curve25519          :     268 ms/handshake

DONE
```
