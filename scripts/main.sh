#!/bin/sh

packname=$1
filename="${packname##*.}"
#echo $filename
mitmdump -s flow_processor.py $filename & 
dump=$!
monkey="$(adb shell monkey -p $packname --throttle 500 -v 200)"
echo "${monkey}"
kill -9 $dump

#TODO: adb get permission lists of the apk and store it into log file
pack_path="$(adb shell pm list packages -f | grep $packname)"
real_pack_path="$(echo $pack_path | cut -d'=' -f1 | cut -d':' -f2)"
download="$(adb pull $real_pack_path tmp.apk)"
permissions="$(aapt d permissions tmp.apk)"
echo "${permissions}" >> logs/"$filename"/"$filename"_permissions.txt
sudo rm tmp.apk





