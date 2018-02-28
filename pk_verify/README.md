# PK Verify sample
This sample demonstrates signature creation and verification using Mbed TLS opaque keys feature. This demo version demonstrates only ECDSA signing using hardware crypto engine ATCAECC508A. This example requires commissioning ATCAECC508A.

## Commission ATCAECC508A
For this example an ATCAECC508A device must be commissioned and connected to the Mbed target on I2C interface. Please see documentation [here](https://github.com/ARMmbed/mbed-os/tree/feature-opaque-keys/features/atcryptoauth#commissioning-application) about it. 
**Note:** The error reporting is not propoer in case of the device not connected or not commissioned. Example may report a memory allocation failure in these situations. Also, the Atmel Crypto Auth Pro device that comes with ATCAECC508A needs a jumper change before use.
