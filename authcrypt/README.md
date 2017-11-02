# Mbed TLS Authenticated Encryption example on Mbed OS

This application performs authenticated encryption and authenticated decryption of a buffer. It serves as a tutorial for the basic authenticated encryption functions of Mbed TLS.

## Getting started

Set up your environment if you have not done so already. For instructions, refer to the [main readme](../README.md).

You can also compile this example with the [Mbed Online Compiler](https://os.mbed.com/compiler/) by using [this project](https://os.mbed.com/teams/mbed-os-examples/code/mbed-os-example-tls-authcrypt).

## Monitoring the application

The output in the terminal window should be similar to this:

```
plaintext message: 536f6d65207468696e67732061726520626574746572206c65667420756e7265616400
ciphertext: c57f7afb94f14c7977d785d08682a2596bd62ee9dcf216b8cccd997afee9b402f5de1739e8e6467aa363749ef39392e5c66622b01c7203ec0a3d14
decrypted: 536f6d65207468696e67732061726520626574746572206c65667420756e7265616400

DONE
```
