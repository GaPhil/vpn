# vpn

Virtual private network using AES session key, performing secure handshake with X.509 certificates.

## Getting started

In order for the handshake to work, three certificates will be needed; one for the CA as well as one for the server and client (`cert_ca.pem`, `cert_server.pem` and `cert_client.pem`):
* create CA certificate: `$ sh create_ca.sh "<name> <email>"`
* create server and client certificate: `$ sh create_user.sh "<name> <email>"`
* verify certificates: 
  * compile: `$ javac src/verifyCertificate.java` 
  * run: `$ java src/verifyCertificate cert_ca.pem cert_server.pem`
  * run: `$ java src/verifyCertificate cert_ca.pem cert_client.pem`