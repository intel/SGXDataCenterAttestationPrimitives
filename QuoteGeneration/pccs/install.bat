@ echo off

call mkdir logs

echo Install npm packages ......

call npm ci

call npm install pm2 -g

call pm2 update

call pm2 start pccs_server.config.js

call pm2 save