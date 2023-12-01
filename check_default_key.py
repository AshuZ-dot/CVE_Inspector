import serial
import sys
from time import sleep
from os import remove

output_file = "uart_logs/uart_boot_log"
trigger_words = ["press", "enter", "wait", "default", "key", "boot", "console"]


def check_default_keys(file):
    imp_lines = []
    with open(file, "r") as f:
        for line in f:
            line = line.rstrip().lower()
            for w in trigger_words:
                if(w in line):
                    print(line)
                    imp_lines.append(line)
    return imp_lines
        
            

def main():
    return check_default_keys(output_file)

