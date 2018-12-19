# vpn
Secure TCP port forwarding application; using AES session key, performing secure handshake with X.509 certificates.

## Getting started

* clone with SSH: `$ git clone git@github.com:GaPhil/vpn.git`<br>*(or clone with HTTPS: `$ git clone https://github.com/GaPhil/vpn.git`)*
* `$ cd vpn`

### Create certificates
In order for the handshake to work, three certificates are needed; one for the CA as well as one for the server and client (`ca.pem`, `server.pem` and `client.pem`):
* create three certificates: `$ sh create_certs.sh "<email>"`
* verify certificates: 
  * compile: `$ javac src/verifyCertificate.java` 
  * run: `$ java src/crypto_utils/verifyCertificate ca.pem server.pem`
  * run: `$ java src/crypto_utils/verifyCertificate ca.pem client.pem`
  
### Start the server:
* compile: `$ javac $(find ./src/* | grep .java) && cd src`
* run:
```
$ java ForwardServer --handshakeport=2206 --usercert=../server.pem \
       --cacert=../ca.pem --key=../server-private.der
```

### Start the client:
* compile: `$ javac $(find ./src/* | grep .java) && cd src`
* run: 
```
$ java ForwardClient --handshakehost=localhost --handshakeport=2206 \
       --targethost=localhost --targetport=6789 \
       --usercert=../client.pem --cacert=../ca.pem --key=../client-private.der
```

## Handshake Protocol 
* Client and server authenticate each other
  * X.509 certificate exchange
* Client requests forwarding to a target server
* Server creates symmetric session key for session encryption
  * Session key is securely exchanged using public-key cryptography
* Server creates server port; a new TCP endpoint to which the client connects
  * Communication over this connection is encrypted using symmetric encryption
```
  CLIENT                                                                  SERVER
    |                                                                       |
 1  |                      ClientHello, Certificate                         |
    |------>----------->----------->----------->----------->----------->----|
    |                                                                       |
 2  |                      ServerHello, Certificate                         |
    |------<-----------<-----------<-----------<-----------<-----------<----|
    |                                                                       |
 3  |                    Forward, TargetHost, TargetPort                    |
    |------>----------->----------->----------->----------->----------->----|
    |                                                                       |
 4  |        Session, SessionKey, SessionIV, ServerHost, ServerPort         |
    |------<-----------<-----------<-----------<-----------<-----------<----|
    |                                                                       |
  CLIENT                                                                  SERVER
```

## Key Specifications

### Asymmetric Keys
* Server key pair: 2048-bit RSA key, created with openssl
* Client key pair: 2048-bit RSA key, created with openssl
* CA key pair:     2048-bit RSA key, created with openssl

### Symmetric Keys
* Session key:     AES 128-bit key, used in CTR mode, created with SunJCE Provider
