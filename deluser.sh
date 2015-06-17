#!/bin/bash
if [ $# -ne 2 ]
    then
        echo 'Usage: deluser.sh username password';
else
    ln=1
    found=0
    while read line
        do
            salt=${line%:*}
            hsh=${line##*:}
            userhash=$(echo -n $1 | sha256sum | sed 's/  -//g')
            hash=$(echo -n $salt$userhash$2 | sha256sum | sed 's/  -//g')
            if [ $hsh == $hash ]
                then
                    found=1
                    break
            fi
            ((ln++))
    done < "/usr/share/duress/hashes"

    if [ $found == 1 ]
        then
            sed -i $ln'd' /usr/share/duress/hashes
            rm /usr/share/duress/scripts/$hash
    fi
fi
