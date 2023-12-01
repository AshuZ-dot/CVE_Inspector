import threading
import RPi.GPIO as GPIO
from time import sleep

class PowerMod(threading.Thread):
    def __init__(self, switching_pin, channel_pin):
        # self.delay = 10
        self.power_on = 1000
        self.power_off = 1000
        self.flg = True
        self.switching_pin = switching_pin
        self.channel_pin = channel_pin
        GPIO.setwarnings(False) # Ignore warning for now
        GPIO.setmode(GPIO.BCM) # Use physical pin numbering
        GPIO.setup(channel_pin, GPIO.OUT, initial=GPIO.HIGH) # Set pin 8 to be an output pin and set initial value to low (off)
        GPIO.setup(switching_pin, GPIO.OUT, initial=GPIO.LOW) # Set pin 8 to be an output pin and set initial value to low (off)
        threading.Thread.__init__(self)
    
    def run(self) -> None:
        while 1:
            if self.flg:
                GPIO.output(self.switching_pin, GPIO.HIGH)
                sleep(self.power_on/100)
            if self.flg:
                GPIO.output(self.switching_pin,GPIO.LOW)
                sleep(self.power_off/100)
            # print("Power Delay on is ", self.power_on, " off", self.power_off)

    def set_delay(self, d):
        self.set_poweroff(d)
        self.set_poweron(d)

    def set_state(self, st):
        self.flg = False
        if st == 0:
            GPIO.output(self.switching_pin,GPIO.LOW)
        else:
            GPIO.output(self.switching_pin,GPIO.HIGH)

    def unset_state(self):
        self.flg = True

    def set_poweron(self, d):
        GPIO.output(self.switching_pin,GPIO.HIGH)
        self.power_on = d


    def set_poweroff(self, d):
        GPIO.output(self.switching_pin,GPIO.LOW)
        self.power_off = d

    def set_channel(self, c):
        if c == 1:
             GPIO.output(self.channel_pin, GPIO.HIGH)
        else:
             GPIO.output(self.channel_pin, GPIO.LOW)


# test_pin1 = 6 
# test_pin2 = 26
# GPIO.setwarnings(False) # Ignore warning for now
# GPIO.setmode(GPIO.BCM) # Use physical pin numbering
# GPIO.setup(test_pin1, GPIO.OUT, initial=GPIO.LOW) # Set pin 8 to be an output pin and set initial value to low (off)
# GPIO.setup(test_pin2, GPIO.OUT, initial=GPIO.LOW) # Set pin 8 to be an output pin and set initial value to low (off)

# while True: # Run forever
#     print("hii")
#     GPIO.output(test_pin1, GPIO.HIGH) # Turn on
#     GPIO.output(test_pin2, GPIO.HIGH) # Turn on

#     sleep(1) # Sleep for 1 second
#     GPIO.output(test_pin1, GPIO.LOW) # Turn off
#     GPIO.output(test_pin2, GPIO.LOW) # Turn on

#     sleep(1) # Sleep for 1 second

# thread1 = PowerMod(channel_pin=26, switching_pin=6)
# thread1.start()
# thread1.set_delay(2)
# sleep(4)
# thread1.set_channel(1)
# sleep(4)
# # thread1.set_channel(2)

