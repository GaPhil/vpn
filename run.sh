#!/bin/bash

cat << "EOF"
   ____         ____   _      _  _
  / ___|  __ _ |  _ \ | |__  (_)| |
 | |  _  / _` || |_) || '_ \ | || |
 | |_| || (_| ||  __/ | | | || || |
  \____| \__,_||_|    |_| |_||_||_|

EOF

CERTS="ca.pem
server.pem
client.pem
server-private.der
client-private.der"

for FILE in $CERTS
do
   [ -f $FILE ] && echo "Found $FILE" ||  { echo "$FILE NOT FOUND - RUN 'create_cert.sh'" ; exit 1 ;}
done

rm $(find ./src/* | grep .class)

javac $(find ./src/* | grep .java)

cd src

lsof -ti:2206 | xargs kill

java ForwardServer --handshakeport=2206 --usercert=../server.pem \
   --cacert=../ca.pem --key=../server-private.der &

java ForwardClient --handshakehost=localhost --handshakeport=2206 \
   --targethost=localhost --targetport=6789 \
   --usercert=../client.pem --cacert=../ca.pem --key=../client-private.der

rm $(find ./src/* | grep .class)
