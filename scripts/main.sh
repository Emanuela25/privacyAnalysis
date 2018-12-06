#!/bin/sh

#usage: sudo ./main.sh apkname appname
packname=$1
filename=$2

#set up mitmdump with our script 'flow_processor.py' loaded
mitmdump -s flow_processor.py $filename & 
dump=$!

#run adb shell monkey command to generate random input of the app
monkey="$(adb shell monkey -p $packname --throttle 500 -v 200)"
echo "${monkey}"
#when monkey finished, kill mitmdump 
kill -9 $dump

#use command 'aapt d permissions' command to get app's permission
pack_path="$(adb shell pm list packages -f | grep $packname)"
real_pack_path="$(echo $pack_path | cut -d'=' -f1 | cut -d':' -f2)"
download="$(adb pull $real_pack_path tmp.apk)"
permissions="$(aapt d permissions tmp.apk)"
echo "${permissions}" >> logs/"$filename"/"$filename"_permissions.txt
sudo rm tmp.apk





