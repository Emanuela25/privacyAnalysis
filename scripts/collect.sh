#!/bin/sh

#TODO: adb get permission lists of the apk and store it into log file

packname="com.duolingo"
#com.sx.puzzingo
#com.applicaster.il.babyfirsttv
#com.movile.playkids"
#com.sinyee.education.shape
#com.rvappstudios.abc_kids_toddler_tracing_phonics
#com.lego.duplo.trains
#com.sagosago.Friends.googleplay"
#com.animocabrands.google.ThomasAndFriendsEngineKingdom"


filename="${packname##*.}"
#echo $filename
mitmdump -s collect.py $filename & 
dump=$!
monkey="$(adb shell monkey -p $packname --throttle 500 -v 500)"
echo "${monkey}"
kill -9 $dump



