import serial
import sys
from time import sleep
from os import remove

output_file = "uart_logs/uart_console_log"
trigger_words = ["password", "username", "login", "invalid", "user"]
def check_log_for_console(file):
    with open(output_file, "r") as f:
        for line in f:
            line = line.rstrip().lower()
            for w in trigger_words:
                if(w in line):
                    print("There is a console because ", line, "got", w)
                    return True
        
        

def check_console(baud_rate):
    ser = serial.Serial("/dev/ttyS0", baud_rate)
    output = ""
    for i in range(0,2):
        ser.write(bytes("hello", encoding="ascii"))
        ser.write(b"\r")
        ser.write(b'swomm')
        ser.write(b"\r")
        received_data = ser.read()              #read serial port
        sleep(0.03)
        data_left = ser.inWaiting()
        received_data += ser.read(data_left)
        try:
            print (received_data.decode("ascii"))
            output += received_data.decode("ascii")
        except:
            pass 
    with open(output_file, "a+") as f:
        f.write(output)
    

def main(baud_rate):
    try:
        remove(output_file)
    except:
        print("no file")
    baud_rate = int(baud_rate)
    check_console(baud_rate)
    return check_log_for_console(output_file)
