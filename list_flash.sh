#!/bin/sh

command="flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed="
speed="4096"

if [[ $# -eq 0 ]]; then
    echo "no speed is specified, using default speed $speed"
elif [[ $# -eq 1 ]]; then
    speed=$1
    echo "Using speed $speed"
elif [[ $# -gt 1 ]]; then
    echo "error"
    exit
fi
command=$command$speed
device_list=`$command`
if [[ $device_list == *"No operations were specified"* ]]; then
    echo "debug : found devices"
else
    echo "debug : no device attached"
    # echo "debug : found devices"
    # echo "vendor : GD"
    # echo "size : 2MB"
    # exit
fi
vendor_detail=`$command --flash-name | tail -1`
flash_size=`$command --flash-size | tail -1`

echo "vendor : $vendor_detail"
echo "size : $flash_size"

# echo "excute $command$speed"

