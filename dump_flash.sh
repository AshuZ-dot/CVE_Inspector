#!/bin/bash

command="flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed="
speed="8000"


echo "GETTING $1 $2 $3"

if [[ $# -eq 1 ]]; then
    speed=$1
elif [[ $# -gt 1 ]]; then
    echo "error"
    exit
fi

echo "dump flash called"
command=$command$speed
device_list=`$command -r $3/$2`
if [[ $device_list == *"Reading flash... done."* ]]; then
    echo "success reading flash"
else
    echo "failed dump"
fi

