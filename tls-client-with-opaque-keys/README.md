# TLS Client with Opaque keys
This sample demonstrates a TLS client sample application that uses a HW Crypto engine with Opaque keys feature. In this first version this sample is tied to specific device [ATCAECC508A](https://www.microchip.com/wwwproducts/en/ATECC508A). It's driver is developed inside [mbed-os](https://github.com/ARMmbed/mbed-os/pull/6104).
In future the Opaque keys interface will be generic to interface any Crypto engine with this sample.

## Execution environment
This sample demonstrates use of HW Crypto engines that can not have same hard coded private key for testing. Hence for executing this sample new set of keys, certificates and host setup is required. Since ATCAECC508A only supports ECDSA and SHA256, this sample runs against an SSL server configured with ECDSA and SHA256 cipher suite. Following things are required for the test setup:

- Client certificate
- Server CA cert.
- Server certificate signed by CA.
- Server certificate private key.

## Client certificate
A self signed certificate can be generated using [modified](https://github.com/ARMmbed/mbedtls/pull/1360) ```cert_write.exe``` application. Steps are as follows:
- Connect ATCAECC508A shield on an Mbed platform.
- Flash Mbed Platform with the [sample commissioning application](https://github.com/mazimkhan/mbed-os/blob/b1329cf711d1264a1f6e35924cd2cbde2cc3f703/features/atcryptoauth/README.md#commissioning-application). Reset the board.
- Run modified ```cert_write.exe``` with parameters shown below:

```
mbedtls/programs/x509/cert_write.exe subject_key=remote0COM18 issuer_key=remote0COM18 issuer_name=CN=Cert,O=mbed TLS,C=UK authority_identifier=0 output_file=cert.pem
```
Above command on success generates a certificate in ```cert.pem``` file. This certificate can be inspected with following command:
```
openssl x509 -in cert.pem -noout -text
```

Modified ```cert_write.exe``` takes parameters ```subject_key``` and ```issuer_key``` formatted in a special way to identify HW keys. 
The format is ```remote0COM18```. Here:
- ```remote``` indiates a keys accessible via serial interface.
- ```0``` indicates the key Id. It can be any key identifier supported by the device.
- ```COM18``` is the serial port to communicate with the sample commissioning app running on the mbed-os platform.

### Server CA cert
In order to obtain a CA cert for testing and signing server certificate(s) it is easy to setup local CA authority using ```openssl```. Following steps are executed on an Ubuntu machine to setup a local CA:

#### Creat local CA workspace:
```sh
mkdir CA
cd CA
mkdir newcerts certs crl private requests foreign_keys
touch index.txt
echo "1234" > serial
```

#### Open ```/usr/lib/ssl/openssl.cnf``` and update section ```[CA_default]```
```
dir             = <path to CA dir>      # Where everything is kept
database        = $dir/CA/index.txt     # database index file.
certificate     = $dir/certs/cacert.pem # The CA certificate
serial          = $dir/CA/serial        # The current serial number
private_key     = $dir/private/cakey.pem# The private key
```

#### Generate CA private key:
```
openssl ecparam -name prime256v1 -genkey -out private/cakey.pem
```
Remember that this setup is for demonstrating ATCAECC508A that only do ECDSA with ECC NIST P256 curve. For this reason the CA key should also be of type ECC NIST P256 curve.

#### Generate CA certificate:
```
openssl req -new -x509 -key ./private/cakey.pem -out cacert.pem -days 3650 -set_serial 0
```
Answer appropriately to openssl prompts.

#### Generate a server key(again an ECC NIST P256 curve):
```
openssl ecparam -name prime256v1 -genkey -out foreign_keys/server_prime256v1_priv.pem
```

#### Generate server certificate signing request:
```
openssl req -new -key foreign_keys/server_prime256v1_priv.pem -out requests/server_prime256v1.csr
```
Answer appropriately to openssl prompts. Remember to put *Common Name* same as the host name that will be used by the client to connect to the server. It can be the host name that is visible on the network or it could be the server IP address.

#### Sign server certificate:
```
openssl ca -in requests/server_prime256v1.csr -out certs/server_prime256v1.pem
```

### Modifying SSL Client
SSL Client needs following changes to run successfully with the ad hoc SSL server:
- Change server address (same as used in server certificate) in macro ```SERVER_NAME```.
- Change client certificate in variable ```client_cert_pem```.
- Change CA certificate in variable ```ca_cert_pem```.

### Running SSL server
```ssl_server2.exe``` can be used with following parameters:
- ```server_addr=``` should be same as entered in the certificate.
- ```auth_mode=required``` to enable client authentication.
- ```crt_file=server_prime256v1.pem``` server certificate.
- ```key_file=server_prime256v1_priv.pem``` server private key.
- ```ca_file=cert.pem``` self signed client certificate.
- ```force_ciphersuite=TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256``` force ECDSA with SHA256.

Full command:
```
mbedtls/programs/ssl/ssl_server2.exe server_addr=<IP Addr> debug_level=4 auth_mode=required crt_file=server_prime256v1.pem key_file=server_prime256v1_priv.pem ca_file=cert.pem  force_ciphersuite=TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
```

### Running SSL Client
Run the SSL server as shown above. Flash updated SSL Client and reset the board. Following output on client console indicates a successful run:
```
GET / HTTP/1.0

  < Read from server: 152 bytes read

HTTP/1.0 200 OK
Content-Type: text/html

<h2>mbed TLS Test Server</h2>
<p>Successful connection using: TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256</p>
```
