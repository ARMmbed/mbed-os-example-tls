# Testing examples

Examples are tested using tool [mbedhtrun](https://github.com/ARMmbed/htrun) and templated print log. The templated logs represents expected behaviour of the example.

## How to create templated log

The idea is to check that repeated execution of the example produces serial output that matches expected pattern. An example produces serial output when code contains ```printf``` statements. Serial output may change for legitimate reasons like use of random data or date and time stamps. That's why the log is converted to a template. This means that either the text/lines that differ in every execution are removed or they are converted into regular expressions. See the example below:

```

							      >	Using Ethernet LWIP
								
							      >	Client IP Address is 10.2.203.139
								
							      >	Connecting with developer.mbed.org
								
Starting the TLS handshake...								Starting the TLS handshake...
								
							      >	TLS connection to developer.mbed.org established
								
Server certificate:								Server certificate:
								
							      >	
								    cert. version     : 3
							      >	
								    serial number     : 11:21:B8:47:9B:21:6C:B1:C6:AF:BC:5D:0
							      >	
								    issuer name       : C=BE, O=GlobalSign nv-sa, CN=GlobalSi
							      >	
								    subject name      : C=GB, ST=Cambridgeshire, L=Cambridge,
							      >	
								    issued  on        : 2016-03-03 12:26:08
							      >	
								    expires on        : 2017-04-05 10:31:02
							      >	
								    signed using      : RSA with SHA-256
							      >	
								    RSA key size      : 2048 bits
							      >	
								    basic constraints : CA=false
							      >	
								    subject alt name  : *.mbed.com, mbed.org, *.mbed.org, mbe
							      >	
								    key usage         : Digital Signature, Key Encipherment
							      >	
								    ext key usage     : TLS Web Server Authentication, TLS We

Certificate verification passed								Certificate verification passed
								

								
								
							      >	HTTPS: Received 439 chars from server
								
							      >	HTTPS: Received 200 OK status ... [OK]
								
HTTPS: Received 'Hello world!' status ... [OK]								HTTPS: Received 'Hello world!' status ... [OK]
								
HTTPS: Received message:								HTTPS: Received message:
								

								
								
							      >	HTTP/1.1 200 OK
								
							      >	Server: nginx/1.7.10
								
							      >	Date: Thu, 01 Dec 2016 13:56:32 GMT
								
							      >	Content-Type: text/plain
								
							      >	Content-Length: 14
								
							      >	Connection: keep-alive
								
							      >	Last-Modified: Fri, 27 Jul 2012 13:30:34 GMT
								
							      >	Accept-Ranges: bytes
								
							      >	Cache-Control: max-age=36000
								
							      >	Expires: Thu, 01 Dec 2016 23:56:32 GMT
								
							      >	X-Upstream-L3: 172.17.0.3:80
								
							      >	X-Upstream-L2: developer-sjc-indigo-2-nginx
								
							      >	Strict-Transport-Security: max-age=31536000; includeSubdomain
								

								
								
Hello world!								Hello world!

```

Please observe above that all the lines that have data that changes from execution to execution (on right) have been removed enabling htrun to compare these logs. htrun matches lines from the compare log (on left) one by one. It keeps on looking for a line until it matches. Once matched it moves on to match the next line. If it finds all lines from the compare log in the target serial output stream. Then it halts and the test passes.

Another example with regular examples is shown below:

```
  SHA-256                  :\s*\d+ KB/s         |   SHA-256                  :       1922 KB/s
  SHA-512                  :\s*\d+ KB/s         |   SHA-512                  :        614 KB/s
  AES-CBC-128              :\s*\d+ KB/s         |   AES-CBC-128              :       1401 KB/s
  AES-CBC-192              :\s*\d+ KB/s         |   AES-CBC-192              :       1231 KB/s
  AES-CBC-256              :\s*\d+ KB/s         |   AES-CBC-256              :       1097 KB/s
  AES-GCM-128              :\s*\d+ KB/s         |   AES-GCM-128              :        429 KB/s
  AES-GCM-192              :\s*\d+ KB/s         |   AES-GCM-192              :        412 KB/s
  AES-GCM-256              :\s*\d+ KB/s         |   AES-GCM-256              :        395 KB/s
  AES-CCM-128              :\s*\d+ KB/s         |   AES-CCM-128              :        604 KB/s
  AES-CCM-192              :\s*\d+ KB/s         |   AES-CCM-192              :        539 KB/s
  AES-CCM-256              :\s*\d+ KB/s         |   AES-CCM-256              :        487 KB/s
  CTR_DRBG \(NOPR\)          :\s*\d+ KB/s       |   CTR_DRBG (NOPR)          :       1145 KB/s
  CTR_DRBG \(PR\)            :\s*\d+ KB/s       |   CTR_DRBG (PR)            :        821 KB/s
  HMAC_DRBG SHA-256 \(NOPR\) :\s*\d+ KB/s       |   HMAC_DRBG SHA-256 (NOPR) :        219 KB/s
  HMAC_DRBG SHA-256 \(PR\)   :\s*\d+ KB/s       |   HMAC_DRBG SHA-256 (PR)   :        193 KB/s
  RSA-2048                 :\s*\d+ ms/ public   |   RSA-2048                 :      30 ms/ public
  RSA-2048                 :\s*\d+ ms/private   |   RSA-2048                 :    1054 ms/private
  RSA-4096                 :\s*\d+ ms/ public   |   RSA-4096                 :     101 ms/ public
  RSA-4096                 :\s*\d+ ms/private   |   RSA-4096                 :    5790 ms/private
  ECDHE-secp384r1          :\s*\d+ ms/handshake |   ECDHE-secp384r1          :    1023 ms/handshake
  ECDHE-secp256r1          :\s*\d+ ms/handshake |   ECDHE-secp256r1          :     678 ms/handshake
  ECDHE-Curve25519         :\s*\d+ ms/handshake |   ECDHE-Curve25519         :     580 ms/handshake
  ECDH-secp384r1           :\s*\d+ ms/handshake |   ECDH-secp384r1           :     503 ms/handshake
  ECDH-secp256r1           :\s*\d+ ms/handshake |   ECDH-secp256r1           :     336 ms/handshake
  ECDH-Curve25519          :\s*\d+ ms/handshake |   ECDH-Curve25519          :     300 ms/handshake
DONE                                            | DONE
```

More details about ```htrun``` are [here](https://github.com/ARMmbed/htrun#testing-mbed-os-examples).

