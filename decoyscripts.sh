#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
elif [ $# -ne 1 ]
    then
        echo "Usage: decoyscripts.sh numberOfScripts";
else
    for i in `seq 1 $1`;
    do
        username=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9./' | fold -w 8 | head -n 1)
        password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9./' | fold -w 8 | head -n 1)
        size=$RANDOM
        let "size %= 3072"
        dd if=/dev/zero of=./tmpscript bs=1K count=$size
        bash ./adduser.sh $username $password ./tmpscript
        rm ./tmpscript
    done
fi

