@ echo off

call mkdir logs

echo Install npm packages ......

call npm install

call npm install node-windows -g

call npm link node-windows

call node pccs.service.win
