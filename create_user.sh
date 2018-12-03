#!/bin/bash
# use with $ sh create_user "Bob Smith bob@smith.com"

name_and_mail=$1

subj="/C=SE\
/ST=Stockholm\
/OU=KTH Royal Institute of Technology\
/CN=$name_and_mail User"

# create user certificate signing request (CSR) with RSA key
openssl req \
   -days 60 \
   -new \
   -newkey rsa:2048 \
   -nodes \
   -subj "$subj" \
   -keyout private_key_user.pem \
   -out cert_user.csr

# sign CSR with CA key and certificate
openssl x509 \
   -req \
   -in cert_user.csr \
   -CA cert_ca.pem \
   -CAkey private_key_ca.pem \
   -CAcreateserial \
   -out cert_user.pem
