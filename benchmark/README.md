# mbed TLS Benchmark example on mbed OS

This application benchmarks the various cryptographic primitives offered by mbed TLS.

## Getting started

Set up your environment if you have not done so already. For instructions, refer to the [main readme](../README.md).

You can also compile this example with the [mbed Online Compiler](https://developer.mbed.org/compiler/) by using [this project](https://developer.mbed.org/teams/mbed-os-examples/code/mbed-os-example-tls-benchmark).

## Monitoring the application

The output in the terminal window should be similar to this:

```
  SHA-256                  :       1673 KB/s,         70 cycles/byte
  SHA-512                  :        546 KB/s,        215 cycles/byte
  AES-CBC-128              :       1428 KB/s,         82 cycles/byte
  AES-CBC-192              :       1260 KB/s,         93 cycles/byte
  AES-CBC-256              :       1127 KB/s,        104 cycles/byte
  AES-GCM-128              :        486 KB/s,        242 cycles/byte
  AES-GCM-192              :        464 KB/s,        253 cycles/byte
  AES-GCM-256              :        445 KB/s,        264 cycles/byte
  AES-CCM-128              :        610 KB/s,        192 cycles/byte
  AES-CCM-192              :        547 KB/s,        214 cycles/byte
  AES-CCM-256              :        496 KB/s,        237 cycles/byte
  CTR_DRBG (NOPR)          :       1139 KB/s,        102 cycles/byte
  CTR_DRBG (PR)            :        826 KB/s,        142 cycles/byte
  HMAC_DRBG SHA-256 (NOPR) :        193 KB/s,        611 cycles/byte
  HMAC_DRBG SHA-256 (PR)   :        170 KB/s,        695 cycles/byte
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
