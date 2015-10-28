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
	salt=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9./' | fold -w 16 | head -n 1)
	hash=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 64 | head -n 1)
	echo $salt:$hash >> /usr/share/duress/hashes

        size=$RANDOM
        let "size %= 10240"
	size+=16
	openssl rand -out /usr/share/duress/scripts/$hash -rand /dev/urandom $size
	sed -i "1s/^/Salted__/" /usr/share/duress/scripts/$hash
    done
fi

