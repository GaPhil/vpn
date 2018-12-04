# vpn

Virtual Private Network with AES/CTR session key, performing secure handshake using X.509 certificates. 

## Getting started

In order for the handshake to work, two certificates will be needed; one for the CA and one for the user (cert_ca.pem and cert_user.pem):
* create CA certificate `$ sh create_ca.sh "<name> <email>"`
* create user certificate `$ sh create_user.sh "<name> <email>"`
