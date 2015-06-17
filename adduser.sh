#!/bin/bash
if [ $# -ne 2 ]
    then
        echo 'Usage: adduser.sh username password';
else
        salt=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9./' | fold -w 16 | head -n 1)
        userhash=$(echo -n $1 | sha256sum | sed 's/  -//g')
        hash=$(echo -n $salt$userhash$2 | sha256sum | sed 's/  -//g')
        echo $salt:$hash >> /usr/share/duress/hashes
fi
