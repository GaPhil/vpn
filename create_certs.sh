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
   -keyout ca-private.pem \
   -out ca.pem

# extract public key
openssl rsa \
   -in ca-private.pem \
   -pubout \
   -out ca-public.pem


# create server certificate signing request (CSR) with RSA key
openssl req \
   -days 60 \
   -new \
   -newkey rsa:2048 \
   -nodes \
   -subj "$subj Server" \
   -keyout server-private.pem \
   -out server.csr

# create client certificate signing request (CSR) with RSA key
openssl req \
   -days 60 \
   -new \
   -newkey rsa:2048 \
   -nodes \
   -subj "$subj Client" \
   -keyout client-private.pem \
   -out client.csr


# sign server CSR with CA key and certificate
openssl x509 \
   -req \
   -in server.csr \
   -CA ca.pem \
   -CAkey ca-private.pem \
   -CAcreateserial \
   -out server.pem

# sign client CSR with CA key and certificate
openssl x509 \
   -req \
   -in client.csr \
   -CA ca.pem \
   -CAkey ca-private.pem \
   -CAcreateserial \
   -out client.pem
