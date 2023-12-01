from time import time
import serial
import RPi.GPIO as GPIO
import sys
from time import sleep, time
from os import remove

relay_pin = 6
output_file = "uart_logs/uart_boot_log"
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)
GPIO.setup(relay_pin, GPIO.OUT)


def check_baud_output(baud_rate, delay, power_delay, power_thread):
    power_thread.set_state(0)
    sleep(power_delay)
    ser = serial.Serial("/dev/ttyS0", baud_rate)
    # GPIO.output(relay_pin, GPIO.HIGH)
    power_thread.set_state(1)
    start = time()
    output = ""
    while(True):
        end = time()
        received_data = ser.read()              #read serial port
        sleep(0.03)
        data_left = ser.inWaiting()
        received_data += ser.read(data_left)
        try:
            print (received_data.decode("ascii"))
            output += received_data.decode("ascii")
        except:
            pass  
        if(end - start > delay): 
            break
    # writing thtings to get login console
    
    with open(output_file, "a") as f:
        f.write(output)
    # print(len(output))

def main(baud_rate, sampling_time, power_cycle_delay, power_thread):
    try:
        remove(output_file)
    except:
        print("no file")
    check_baud_output(int(baud_rate), int(sampling_time), int(power_cycle_delay), power_thread)
