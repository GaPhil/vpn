# vpn

Virtual private network using AES session key, performing secure handshake with X.509 certificates.

## Getting started

In order for the handshake to work, two certificates will be needed; one for the CA and one for the user (cert_ca.pem and cert_user.pem):
* create CA certificate: `$ sh create_ca.sh "<name> <email>"`
* create user certificate: `$ sh create_user.sh "<name> <email>"`
* verify certificates: 
  * compile: `$ javac src/verifyCertificate.java` 
  * run: `$ java src/verifyCertificate cert_ca.pem cert_user.pem`