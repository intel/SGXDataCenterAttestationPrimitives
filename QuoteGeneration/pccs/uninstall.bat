@ echo off

echo Uninstall npm packages ......

call pm2 stop pccs

call pm2 delete pccs

call npm uninstall pm2 -g

call rd /s /q node_modules



