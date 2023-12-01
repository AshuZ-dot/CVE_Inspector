import serial
import sys
from time import sleep
from os import remove

output_file = "uart_logs/uart_bin_logs"
bin_listing_cmds = ["ls", "ls /sbin", "ls .local", "ls /usr/bin", "ls /bin", "help", "h", "?"]


def check_log_for_bin(file):
    with open(output_file, "r") as f:
        for line in f:
            line = line.rstrip().lower()
            print(line)
        
        

def check_bins(baud_rate):
    ser = serial.Serial("/dev/ttyS0", baud_rate)
    output = ""
    for cmd in bin_listing_cmds:
        ser.write(bytes(cmd, encoding="ascii"))
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
    

def main():
    try:
        remove(output_file)
    except:
        print("no file")
    baud_rate = int(sys.argv[1])
    check_bins(baud_rate)
    return check_log_for_bin(output_file)

main()