from fastapi import FastAPI
import asyncio

app = FastAPI()


test = 1

async def function_one():
    global test 
    test += 100
    print(test)
    await asyncio.sleep(5)
    print("hello from function one")
    test += 500
    print(test)
    return {"message": "Function one completed."}

async def function_two():
    global test 
    test += 100
    print(test)
    await asyncio.sleep(3)
    print("hello from function two")
    test += 300
    print(test)
    return {"message": "Function two completed."}

@app.get("/")
async def index():
    result = await asyncio.gather(function_one(), function_two())
    return {"result": result}
