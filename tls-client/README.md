# HTTPS File Download Example for TLS Client on Mbed OS

This application downloads a file from an HTTPS server (os.mbed.com) and looks for a specific string in that file.

## Getting started

Set up your environment if you have not done so already. For instructions, refer to the [main readme](../README.md).

You can also compile this example with the [Mbed Online Compiler](https://os.mbed.com/compiler/) by using [this project](https://os.mbed.com/teams/mbed-os-examples/code/mbed-os-example-tls-tls-client).

## Requirements

This example uses the default network connection available to the target development board. Where that board uses ethernet, no further configuration is necessary, but where the board uses Wifi, the SSID, password and WiFi security protocol will need to be defined in your `mbed_app.json` file.

The networking stack used in this example requires TLS functionality to be enabled on Mbed TLS. On devices where hardware entropy is not present, TLS is disabled by default. Building the example withou an entropy source will result in a build time failure.

To learn why entropy is required, read the [TLS Porting guide](https://docs.mbed.com/docs/mbed-os-handbook/en/latest/advanced/tls_porting/).

## Monitoring the application

__NOTE:__ Make sure that the network is functional before running the application.

The output in the terminal window should be similar to this:

```
Starting mbed-os-example-tls/tls-client
Using Mbed OS 5.11.5
Successfully connected to os.mbed.com at port 443
Starting the TLS handshake...
Successfully completed the TLS handshake
Server certificate:
  cert. version     : 3
  serial number     : 09:48:30:25:4C:0E:DD:47:E3:73:A7:AE:17:AE:1A:92
  issuer name       : C=US, O=Amazon, OU=Server CA 1B, CN=Amazon
  subject name      : CN=*.mbed.com
  issued  on        : 2019-01-31 00:00:00
  expires on        : 2020-02-29 12:00:00
  signed using      : RSA with SHA-256
  RSA key size      : 2048 bits
  basic constraints : CA=false
  subject alt name  : *.mbed.com, mbed.com, *.mbed.org, mbed.org, *.core.mbed.cm
  key usage         : Digital Signature, Key Encipherment
  ext key usage     : TLS Web Server Authentication, TLS Web Client Authenticatn

Certificate verification passed
Established TLS connection to os.mbed.com
HTTP: Received 320 chars from server
HTTP: Received '200 OK' status ... OK
HTTP: Received message:
HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: max-age=36000
Content-Type: text/plain
Date: Wed, 24 Apr 2019 18:57:54 GMT
ETag: "5bf0036d-e"
Expires: Thu, 25 Apr 2019 04:57:54 GMT
Last-Modified: Sat, 17 Nov 2018 12:02:53 GMT
Server: nginx/1.15.6
Content-Length: 14
Connection: keep-alive

Hello world!


DONE
```

## Debugging the TLS connection

To print out more debug information about the TLS connection, edit the file `main.cpp` and change the definition of `DEBUG_LEVEL` (near the top of the file) from 0 to a positive number:

* Level 1 only prints non-zero return codes from SSL functions and information about the full certificate chain being verified.

* Level 2 prints more information about internal state updates.

* Level 3 is intermediate.

* Level 4 (the maximum) includes full binary dumps of the packets.


The TLS connection can fail with an error similar to:

    mbedtls_ssl_write() failed: -0x2700 (-9984): X509 - Certificate verification failed, e.g. CRL, CA or signature check failed
    Failed to fetch /media/uploads/mbed_official/hello.txt from os.mbed.com:443

This probably means you need to update the contents of the `SSL_CA_PEM` constant (this can happen if you modify `HTTPS_SERVER_NAME`, or when `os.mbed.com` switches to a new CA when updating its certificate).

Another possible reason for this error is a proxy providing a different certificate. Proxies can be used in some network configurations or for performing man-in-the-middle attacks. If you choose to ignore this error and proceed with the connection anyway, you can change the definition of `UNSAFE` near the top of the file from 0 to 1.

**Warning:** this removes all security against a possible active attacker, so use at your own risk or for debugging only!

## Troubleshooting

If you have problems, you can review the [documentation](https://os.mbed.com/docs/latest/tutorials/debugging.html) for suggestions on what could be wrong and how to fix it.
