#!/bin/bash
if [ $# -ne 2 ]
    then
        echo 'Usage: adduser.sh username password';
else
        hash=$((echo -n $1$2 | sha256sum) | sed 's/  -//g')
        echo -n $hash >> /usr/share/duress/hashes
        mkdir /usr/share/duress/$hash/
fi
