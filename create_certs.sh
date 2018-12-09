#!/bin/bash
# creates CA, server and client certificates
# use with $ sh create_certs "Bob Smith bob@smith.com"

name_and_mail=$1

subj="/C=SE\
/ST=Stockholm\
/OU=KTH Royal Institute of Technology\
/CN=$name_and_mail"

# create CA certificate with RSA key (not encrypted [-nodes])
openssl req \
   -days 60 \
   -new \
   -x509 \
   -newkey rsa:2048 \
   -nodes \
   -subj "$subj Certificate Authority" \
   -keyout private_key_ca.pem \
   -out cert_ca.pem

# extract public key
openssl rsa \
   -in private_key_ca.pem \
   -pubout \
   -out public_key_ca.pem


# create server certificate signing request (CSR) with RSA key
openssl req \
   -days 60 \
   -new \
   -newkey rsa:2048 \
   -nodes \
   -subj "$subj Server" \
   -keyout private_key_server.pem \
   -out cert_server.csr

# create client certificate signing request (CSR) with RSA key
openssl req \
   -days 60 \
   -new \
   -newkey rsa:2048 \
   -nodes \
   -subj "$subj Client" \
   -keyout private_key_client.pem \
   -out cert_client.csr


# sign server CSR with CA key and certificate
openssl x509 \
   -req \
   -in cert_server.csr \
   -CA cert_ca.pem \
   -CAkey private_key_ca.pem \
   -CAcreateserial \
   -out cert_server.pem

# sign client CSR with CA key and certificate
openssl x509 \
   -req \
   -in cert_client.csr \
   -CA cert_ca.pem \
   -CAkey private_key_ca.pem \
   -CAcreateserial \
   -out cert_client.pem
