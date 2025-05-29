@ echo off

echo Uninstall npm packages ......

call node pccs.winsvc.uninst.cjs

@ call rd /s /q node_modules




