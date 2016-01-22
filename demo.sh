#!/bin/bash

if [ `id -u` -ne 0 ]; then
	echo "please run this script via sudo"
	exit 1
fi

/sbin/rmmod siglog >/dev/null 2>&1

SMAP=/boot/System.map-`uname -r`
ADDR=`grep " R sys_call_table" $SMAP | cut -d " " -f 1`

/sbin/insmod siglog.ko sctaddress=0x$ADDR

if [ $? -ne 0 ]; then
	echo "failed to insert module, check dmesg for errors"
	exit 1
fi


echo "creating some signals ..."

sleep 10 & >/dev/null 2>&1
spid=$!
kill -0  $spid >/dev/null 2>&1
kill -15 $spid >/dev/null 2>&1
kill -9  $spid >/dev/null 2>&1
wait
echo "done, logged signals in /proc/siglog:"
cat /proc/siglog

/sbin/rmmod siglog

