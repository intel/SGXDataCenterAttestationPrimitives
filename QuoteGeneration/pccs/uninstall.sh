#!/bin/bash

if which pm2 > /dev/null
then
    pm2 stop pccs_server 
    pm2 delete pccs_server
    pm2cfg=`pm2 unstartup | grep 'sudo'`
    eval $pm2cfg
fi

rm -rf node_modules
