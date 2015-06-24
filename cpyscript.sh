#!/bin/bash
if [ $# -ne 3 ]
    then
        echo 'Usage: cpyscript.sh username password path';
else
    while read line
        do
            salt=${line%:*}
            hsh=${line##*:}
            userhash=$(echo -n $1 | sha256sum | sed 's/  -//g')
            hash=$(echo -n $salt$userhash$2 | sha256sum | sed 's/  -//g')
            if [ $hsh == $hash ]
                then
                    encsalt=$(cat /dev/urandom | tr -dc 'A-F0-9' | fold -w 16 | head -n 1)
                    openssl aes128 -in $3 -out /usr/share/duress/scripts/$hash -k $2 -md sha256 -S $encsalt -p
            fi
        done < "/usr/share/duress/hashes"
fi
