# PK Verify sample
This sample demonstrates signature creation and verification using Mbed TLS opaque keys feature. This demo version demonstrates only ECDSA signing using hardware crypto engine ATCAECC508A. This example requires commissioning ATCAECC508A.

## Commission ATCAECC508A
For this example an ATCAECC508A device must be commissioned and connected to the Mbed target on I2C interface. Please see documentation [here](https://github.com/ARMmbed/mbed-os/tree/feature-opaque-keys/features/atcryptoauth#commissioning-application) about it. 
**Note:** The error reporting is not propoer in case of the device not connected or not commissioned. Example may report a memory allocation failure in these situations. Also, the Atmel Crypto Auth Pro device that comes with ATCAECC508A needs a jumper change before use.

## Building the sample
ATECC508A requires I2C interface. It is present in most of the Mbed Platforms. However, not all platforms define I2C_SDA and I2C_SCL pins uniformaly. Hence, code in [mbed-os/features/atcryptoauth/ATCAFactory.cpp](https://github.com/ARMmbed/mbed-os/blob/feature-opaque-keys/features/atcryptoauth/ATCAFactory.cpp#L23) limits the feature to platform K64F. In order to build for any other target please enable it in the code and provide target specific I2C_SDA and I2C_SCL pin names.
