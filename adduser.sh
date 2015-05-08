#!/bin/bash
if [ $# -ne 2 ]
    then
        echo 'Usage: adduser.sh username password';
else
        salt=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
        hash=$((echo -n $salt$1$2 | sha256sum) | sed 's/  -//g')
        echo $salt:$hash >> /usr/share/duress/hashes
fi
