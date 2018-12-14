#!/bin/bash
# creates CA, server and client certificates
# use with $ sh create_certs "bob@smith.com"

mail=$1

subj="/C=SE\
/L=Stockholm\
/O=KTH\
/OU=IK2206 Internet Security and Privacy\
/CN"

# create CA certificate with RSA key (not encrypted [-nodes])
openssl req \
   -days 60 \
   -new \
   -x509 \
   -newkey rsa:2048 \
   -nodes \
   -subj "$subj=ca-pf.ik2206.kth.se/emailAddress=$mail" \
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
   -subj "$subj=server-pf.ik2206.kth.se/emailAddress=$mail" \
   -keyout server-private.pem \
   -out server.csr

# create client certificate signing request (CSR) with RSA key
openssl req \
   -days 60 \
   -new \
   -newkey rsa:2048 \
   -nodes \
   -subj "$subj=client-pf.ik2206.kth.se/emailAddress=$mail" \
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

# export private keys to DER format
openssl pkcs8 \
   -nocrypt \
   -topk8 \
   -inform PEM \
   -in server-private.pem \
   -outform DER \
   -out server-private.der

openssl pkcs8 \
   -nocrypt \
   -topk8 \
   -inform PEM \
   -in client-private.pem \
   -outform DER \
   -out client-private.der
