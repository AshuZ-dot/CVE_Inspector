from itertools import dropwhile
from fastapi import FastAPI, Path
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import RPi.GPIO as GPIO
from time import sleep
import threading
import os
import helper
import detect_baud, check_uart_console, check_default_key, capture_uart_boot
from cv_scanner import find_cve
from power_module import PowerMod
from pydantic import BaseModel

switching_pin = 19
volt_pin = 20
relay_pin = 21


GPIO.setmode(GPIO.BCM) 
GPIO.setup(volt_pin, GPIO.OUT)
FIRM_DIR = "extracted_firm"
LOG_DIR = "uart_logs"
GPIO.setup(relay_pin, GPIO.OUT)
GPIO.output(relay_pin, GPIO.HIGH)
power_thread = PowerMod(channel_pin=26, switching_pin=6)
power_thread.start()

app = FastAPI()


origins = [
    "http://localhost",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class BootLog(BaseModel):
    boot_log: str


@app.get('/')
def getHome():
    print('Hello world')
    content = {'message': 'hello'}
    headers={'Access-Control-Allow-Origin':'*',
             'Access-Control-Allow-Origin':'GET, POST, PUT, DELETE, OPTIONS',
             'Access-Control-Allow-Headers':'Content-Type, Authorization'}
    return JSONResponse(content=content, headers=headers)


@app.get("/set_volt/{freq}")
async def volt_glitch(freq):
    print(freq)
    power_thread.unset_state()
    power_thread.set_delay(int(freq))
    return {"data":"OK"}

@app.get("/set_volt_custom/{pon}/{poff}")
async def volt_glitch_custom(pon,poff):
    print('pon : ',pon)
    print('poff ; ' ,poff)
    power_thread.unset_state()
    print(f"setting on {pon} poff {poff}")
    power_thread.set_poweroff(int(poff))
    power_thread.set_poweron(int(pon))
    return {"data":"OK _pon"}

@app.get("/set_channel/{channel}")
async def volt_glitch_channel(channel):
    power_thread.set_channel(int(channel))
    return {"data":"OK Channel set"}

@app.get("/switch_power/{flg}")
async def switch_power(flg):
    if flg == "0":
        print("set of ")
        power_thread.set_state(0)

    else:
        print("set on")
        power_thread.set_state(1)
        #power_thread.set_poweron(10000)
     #power_thread.set_channel(int(channel))
    return {"data":"OF q"}

@app.get("/check_uart_console/{baud}")
async def uart_console(baud = 115200):
    print('uart_console')
    check = await check_uart_console.main(baud)
    if check:
        return {"data":"Console Found"}
    return {"data":"No Console Found"}
    
@app.get("/boot_log_analyse/{file_name}")
async def boot_log(file_name = None):
    if file_name is not None:
        check_default_key.output_file = "uart_logs/"+file_name
    imp = await check_default_key.main()
    imp_output = "\n".join(imp)
    # output=""
    # with open("uart_logs/"+file_name, "r") as f:
    #     for i in f:
    #         output+=i
    return {"data":imp_output}

@app.get("/capture_boot_logs/{sampling_rate}/{power_cycle}/{baud_rate}")
async def cap_boot(sampling_rate,power_cycle,baud_rate):
    print(sampling_rate,power_cycle,baud_rate)
    output=""
    capture_uart_boot.main(baud_rate, sampling_rate, power_cycle, power_thread)
    with open(capture_uart_boot.output_file, "r") as f:
        for i in f:
            output+=i
    print(output)
    return {"data" : output}

@app.get("/show_raw_boot_logs/{log_name}")
async def cap_boot_show(log_name = None):
    output=""
    if log_name is None:
        log_name = "uart_boot_log"
    with open("uart_logs/"+log_name, "r") as f:
        for i in f:
            output+=i
    print(output)
    return {"data" : output}

@app.get("/detect_baudrate/{sampling_rate}/{power_cycle_delay}")
async def baud_detect(sampling_rate,power_cycle_delay):
    print(sampling_rate, power_cycle_delay, "baud detect")
    detect_baud.main(sampling_rate, power_cycle_delay, power_thread)
    bauds = ""
    
    with open(detect_baud.output_file, "r") as f:
        for i in f:
            bauds+=i
    
    return {"data": bauds}

@app.post("/cv_scan/")
async def cv_scan(boot_log : BootLog):
    output = find_cve(boot_log.boot_log)
    print(boot_log.boot_log)
    print('output : ',output)
    if output == '':
        output = 'Analysis Done'
    return {'data' : output}


@app.get("/list_devices/{speed}")
async def list_devices(speed:str = '4096'):
    list_output = await helper.list_device_call(speed)
    return {"data": list_output}


@app.get("/download_firm/{filename}")
def down_firm(filename: str = "test"):
    fname = filename
    print("downloading "+fname)
    return FileResponse(FIRM_DIR+"/"+fname+".bin")



@app.get("/dump_firm/{filename}")
def dump_firm(filename:str = 'test'):
    firm_name = filename
    return {"data":helper.dump_firm_call("8000", firm_name+".bin", FIRM_DIR)}




@app.get("/get_strings/{file_name}")
def analyse_firm(file_name):
    filename = file_name
    return {"data" :{"invoked_data":"none", "data": "\n".join(helper.get_strings(FIRM_DIR+"/"+filename))}}
    
@app.get("/get_binwalk/{file_name}")
def analyse_firm_binwalk(file_name):
    filename = file_name
    output = helper.binwalk_des(FIRM_DIR+"/"+filename)
    print(output)
    return {"data": output}


