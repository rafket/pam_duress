#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
elif [ $# -ne 3 ]
    then
        echo 'Usage: adduser.sh username password path';
else
        salt=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9./' | fold -w 16 | head -n 1)
        userhash=$(echo -n $1 | sha256sum | sed 's/  -//g')
        hash=$(echo -n $salt$userhash$2 | sha256sum | sed 's/  -//g')
        echo $salt:$hash >> /usr/share/duress/hashes

        encsalt=$(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 16 | head -n 1)
        openssl aes128 -in $3 -out /usr/share/duress/scripts/$hash -k $2 -md sha256 -S $encsalt
fi
