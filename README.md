# vpn

Virtual private network using AES session key, performing secure handshake with X.509 certificates.

## Getting started

Clone:

* clone with SSH: `$ git lcone git@github.com:GaPhil/vpn.git`
or 
* clone with HTTPS: `$ git clone https://github.com/GaPhil/vpn.git`

`$ cd vpn`

In order for the handshake to work, three certificates are needed; one for the CA as well as one for the server and client (`cert_ca.pem`, `cert_server.pem` and `cert_client.pem`):
* create three certificates: `$ sh create_certs.sh "<name> <email>"`
* verify certificates: 
  * compile: `$ javac src/verifyCertificate.java` 
  * run: `$ java src/verifyCertificate cert_ca.pem cert_server.pem`
  * run: `$ java src/verifyCertificate cert_ca.pem cert_client.pem`
