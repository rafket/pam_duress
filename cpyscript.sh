#!/bin/bash
if [ $# -ne 3 ]
    then
        echo 'Please provide username and password and path to script (in this order)';
else
        hash=$((echo -n $1$2 | sha256sum) | sed 's/  -//g')
        cp $3 /usr/share/duress/$hash/script
        chmod 744 /usr/share/duress/$hash/script
fi
