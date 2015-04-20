#!/bin/bash
if [ $# -ne 2 ]
    then
        echo 'Please provide username and password (in this order)';
else
        ((echo -n $1$2 | sha256sum) | sed 's/  -//g') >> /usr/share/duress/hashes
fi
