import asyncio
import websockets
import json


async def hello():
    uri = "ws://localhost:8000/ws/ws-test/"
    async with websockets.connect(uri) as websocket:
        await websocket.send(json.dumps({'message': "I am from packet analyzer"}))
        response = await websocket.recv()
        print(response)

asyncio.run(hello())
