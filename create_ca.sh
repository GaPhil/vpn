#!/bin/bash
# use with $ sh create_ca "Bob Smith bob@smith.com"

name_and_mail=$1

subj="/C=SE\
/ST=Stockholm\
/OU=KTH Royal Institute of Technology\
/CN=$name_and_mail Certificate Authority"

# create CA certificate with RSA key (not encrypted [-nodes])
openssl req \
   -days 60 \
   -new \
   -x509 \
   -newkey rsa:2048 \
   -nodes \
   -subj "$subj" \
   -keyout private_key_ca.pem \
   -out cert_ca.pem

# extract public key
openssl rsa \
   -in private_key_ca.pem \
   -pubout \
   -out public_key_ca.pem
