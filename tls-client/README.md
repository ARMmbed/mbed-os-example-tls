# HTTPS File Download Example for TLS Client on Mbed OS

This application downloads a file from an HTTPS server (os.mbed.com) and looks for a specific string in that file.

## Getting started

Set up your environment if you have not done so already. For instructions, refer to the [main readme](../README.md).

You can also compile this example with the [Mbed Online Compiler](https://os.mbed.com/compiler/) by using [this project](https://os.mbed.com/teams/mbed-os-examples/code/mbed-os-example-tls-tls-client).

## Requirements

This example uses by default an Ethernet connection to the internet.
It's possible to switch to another network interface by using [the Mbed OS NetworkInterface](https://os.mbed.com/docs/latest/apis/network-interfaces.html).

The networking stack used in this example requires TLS functionality to be enabled on Mbed TLS. On devices where hardware entropy is not present, TLS is disabled by default. This would result in compile time or linking failures.

To learn why entropy is required, read the [entropy Porting guide](https://os.mbed.com/docs/latest/porting/entropy-sources.html).

## Monitoring the application

__NOTE:__ Make sure that the network is functional before running the application.

The output in the terminal window should be similar to this:

```
Starting mbed-os-example-tls/tls-client
Using Mbed OS 5.11.1
Successfully connected to os.mbed.com at port 443
Starting the TLS handshake...
Successfully completed the TLS handshake
Server certificate:
  cert. version     : 3
  serial number     : 0F:22:3C:45:F9:9B:25:DA:B5:A0:E9:E4:C3:F9:5F:9D
  issuer name       : C=US, O=Amazon, OU=Server CA 1B, CN=Amazon
  subject name      : CN=mbed.com
  issued  on        : 2018-03-16 00:00:00
  expires on        : 2019-04-16 12:00:00
  signed using      : RSA with SHA-256
  RSA key size      : 2048 bits
  basic constraints : CA=false
  subject alt name  : mbed.com, *.mbed.com, mbed.org, *.mbed.org
  key usage         : Digital Signature, Key Encipherment
  ext key usage     : TLS Web Server Authentication, TLS Web Client Authentication

Certificate verification passed
Established TLS connection to os.mbed.com
HTTP: Received 320 chars from server
HTTP: Received '200 OK' status ... OK
HTTP: Received message:
HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: max-age=36000
Content-Type: text/plain
Date: Thu, 10 Jan 2019 13:45:27 GMT
ETag: "5bf0036d-e"
Expires: Thu, 10 Jan 2019 23:45:27 GMT
Last-Modified: Sat, 17 Nov 2018 12:02:53 GMT
Server: nginx/1.15.3
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
