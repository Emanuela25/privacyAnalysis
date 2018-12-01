#!/bin/sh

packname="com.duolingo"
filename="${packname##*.}"
#echo $filename
mitmdump -s flow_processor.py $filename & 
dump=$!
monkey="$(adb shell monkey -p $packname --throttle 500 -v 200)"
echo "${monkey}"
kill -9 $dump



