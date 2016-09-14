#!/bin/bash
# POC-script to test PortBunny rate-limit-detection

rmmod portbunny;
modprobe portbunny;
sleep 1

echo "create_scanjob $1 RLIMIT_DETECT" > /dev/portbunny;
echo "set_batch_size $1 $2" > /dev/portbunny
echo "execute_scanjob $1" > /dev/portbunny;

tail -n 3 -f /var/log/syslog | grep responses



