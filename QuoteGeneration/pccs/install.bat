@ echo off

echo Install npm packages ......

call npm install

call npm install pm2 -g

call pm2 update

call pm2 start pccs_server.config.js
