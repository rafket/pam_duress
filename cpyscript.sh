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
                    cp $3 /usr/share/duress/scripts/$hash
                    chmod 744 /usr/share/duress/scripts/$hash
            fi
        done < "/usr/share/duress/hashes"
fi
