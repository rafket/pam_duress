#!/bin/bash
if [ $# -ne 3 ]
    then
        echo 'Usage: cpyscript.sh username password path';
else
    while read line
        do
            salt=${line%:*}
            hsh=${line##*:}
            hash=$((echo -n $salt$1$2 | sha256sum) | sed 's/  -//g')
            if [ $hsh == $hash ]
                then
                    cp $3 /usr/share/duress/scripts/$hash
                    chmod 754 /usr/share/duress/scripts/$hash
            fi
        done < "/usr/share/duress/hashes"
fi
