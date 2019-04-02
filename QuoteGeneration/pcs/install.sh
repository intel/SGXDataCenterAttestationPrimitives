#!/bin/bash

# check if nodejs is installed
function checkNodeJs() {
    echo "Checking if nodejs is installed ..."
    if which node > /dev/null 
    then
        echo "nodejs is installed, continue..."
    else
        echo "Please install nodejs first..."
        exit 0
    fi
}

checkNodeJs
npm install

if which pm2 > /dev/null 
then 
    echo "pm2 is installed, continue ..."
else
    sudo npm install -g pm2
fi

#Ask for administrator password
admintoken1=""
admintoken2=""
pass_set=false
while [ "$pass_set" == false ]
do
    while test "$admintoken1" == ""
    do
        read -s -p "Set PCS server administrator password:" admintoken1
        printf "\n"
    done

    while test "$admintoken2" == ""
    do
        read -s -p "Re-enter administrator password:" admintoken2
        printf "\n"
    done

    if test "$admintoken1" != "$admintoken2"
    then
        echo "Passwords don't match."
        admintoken1=""
        admintoken2=""
    else
        HASH="$(echo -n "$admintoken1" | sha512sum | tr -d '[:space:]-')"
        sed "/\"AdminToken\"*/c\ \ \ \ \"AdminToken\" \: \"${HASH}\"" -i config.json
        pass_set=true
    fi
done

pm2 update
pm2 start pcs_server.js

pm2cfg=`pm2 startup systemd | grep 'sudo'` 
eval $pm2cfg
