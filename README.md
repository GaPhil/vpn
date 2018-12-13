# vpn

Virtual private network using AES session key, performing secure handshake with X.509 certificates.

## Getting started

* clone with SSH: `$ git lcone git@github.com:GaPhil/vpn.git`<br>*(or clone with HTTPS: `$ git clone https://github.com/GaPhil/vpn.git`)*
* `$ cd vpn`

In order for the handshake to work, three certificates are needed; one for the CA as well as one for the server and client (`ca.pem`, `server.pem` and `client.pem`):
* create three certificates: `$ sh create_certs.sh "<name> <email>"`
* verify certificates: 
  * compile: `$ javac src/verifyCertificate.java` 
  * run: `$ java src/crypto_utils/verifyCertificate ca.pem server.pem`
  * run: `$ java src/crypto_utils/verifyCertificate ca.pem client.pem`
  
Start the server:
* compile: `$ javac $(find ./src/* | grep .java)`
* run: 
```bash
$ java ForwardServer --handshakeport=2206 --usercert=server.pem \
   --cacert=ca.pem --key=server-private.der
```

Start the client:
* compile: `$ javac $(find ./src/* | grep .java)`
* run: 
```bash
$ java ForwardClient --handshakehost=portfw.kth.se  --handshakeport=2206 \
   --targethost=server.kth.se --targetport=6789 \
   --usercert=client.pem --cacert=ca.pem --key=client-private.der
```
