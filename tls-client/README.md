# HTTPS File Download Example for TLS Client on mbed OS

This application downloads a file from an HTTPS server (developer.mbed.org) and looks for a specific string in that file.

# Getting started

Set up your environment if you have not done so already. For instructions, refer to the [main readme](../README.md).

## Required hardware

This example also requires an Ethernet cable an connection to the internet additional to the hardware requirements in the [main readme](../README.md).

## Monitoring the application

__NOTE:__ Make sure that the Ethernet cable is plugged in correctly before running the application.

The output in the terminal window should be similar to this:

```
    {{timeout;120}}
    {{host_test_name;default}}
    {{description;mbed TLS example HTTPS client}}
    {{test_id;MBEDTLS_EX_HTTPS_CLIENT}}
    {{start}}

    Client IP Address is 192.168.0.2
    Starting DNS lookup for developer.mbed.org
    DNS Response Received:
    developer.mbed.org: 217.140.101.30
    Connecting to 217.140.101.30:443
    Connected to 217.140.101.30:443
    Starting the TLS handshake...
    TLS connection to developer.mbed.org established
    Server certificate:
        cert. version     : 3
        serial number     : 11:21:4E:4B:13:27:F0:89:21:FB:70:EC:3B:B5:73:5C:FF:B9
        issuer name       : C=BE, O=GlobalSign nv-sa, CN=GlobalSign Organization Validation CA - SHA256 - G2
        subject name      : C=GB, ST=Cambridgeshire, L=Cambridge, O=ARM Ltd, CN=*.mbed.com
        issued  on        : 2015-03-05 10:31:02
        expires on        : 2016-03-05 10:31:02
        signed using      : RSA with SHA-256
        RSA key size      : 2048 bits
        basic constraints : CA=false
        subject alt name  : *.mbed.com, *.mbed.org, mbed.org, mbed.com
        key usage         : Digital Signature, Key Encipherment
        ext key usage     : TLS Web Server Authentication, TLS Web Client Authentication
    Certificate verification passed

    HTTPS: Received 473 chars from server
    HTTPS: Received 200 OK status ... [OK]
    HTTPS: Received 'Hello world!' status ... [OK]
    HTTPS: Received message:

    HTTP/1.1 200 OK
    Server: nginx/1.7.10
    Date: Tue, 18 Aug 2015 18:34:04 GMT
    Content-Type: text/plain
    Content-Length: 14
    Connection: keep-alive
    Last-Modified: Fri, 27 Jul 2012 13:30:34 GMT
    Accept-Ranges: bytes
    Cache-Control: max-age=36000
    Expires: Wed, 19 Aug 2015 04:34:04 GMT
    X-Upstream-L3: 172.17.42.1:8080
    X-Upstream-L2: developer-sjc-indigo-2-nginx
    X-Upstream-L1-next-hop: 217.140.101.86:8001
    X-Upstream-L1: developer-sjc-indigo-border-nginx

    Hello world!
    {{success}}
    {{end}}
```

## Debugging the TLS connection

To print out more debug information about the TLS connection, edit the file `main.cpp` and change the definition of `DEBUG_LEVEL` (near the top of the file) from 0 to a positive number:

* Level 1 only prints non-zero return codes from SSL functions and information about the full certificate chain being verified.

* Level 2 prints more information about internal state updates.

* Level 3 is intermediate.

* Level 4 (the maximum) includes full binary dumps of the packets.


The TLS connection can fail with an error similar to:

    mbedtls_ssl_write() failed: -0x2700 (-9984): X509 - Certificate verification failed, e.g. CRL, CA or signature check failed
    Failed to fetch /media/uploads/mbed_official/hello.txt from developer.mbed.org:443

This probably means you need to update the contents of the `SSL_CA_PEM` constant (this can happen if you modify `HTTPS_SERVER_NAME`, or when `developer.mbed.org` switches to a new CA when updating its certificate).

Another possible reason for this error is a proxy providing a different certificate. Proxies can be used in some network configurations or for performing man-in-the-middle attacks. If you choose to ignore this error and proceed with the connection anyway, you can change the definition of `UNSAFE` near the top of the file from 0 to 1.

**Warning:** this removes all security against a possible active attacker, so use at your own risk or for debugging only!

