#!/bin/bash
if [ $# -ne 3 ]
    then
        echo 'Usage: cpyscript.sh username password path';
else
        hash=$((echo -n $1$2 | sha256sum) | sed 's/  -//g')
        cp $3 /usr/share/duress/scripts/$hash
        chmod 744 /usr/share/duress/scripts/$hash
fi
