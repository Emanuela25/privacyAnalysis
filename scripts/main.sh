#!/bin/sh

#TODO: adb get permission lists of the apk and store it into log file

packname="com.roblox.client"
filename="${packname##*.}"
#echo $filename
mitmdump -s flow_processor.py $filename & 
dump=$!
monkey="$(adb shell monkey -p $packname --throttle 500 -v 200)"
echo "${monkey}"
kill -9 $dump



