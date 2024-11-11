import json
import websockets


class Communication:
    # def __init__(self, uri):
    #     self.uri = uri
    #     self.websocket = None
    #
    # async def connect(self):
    #     self.websocket = await websockets.connect(self.uri)
    #
    # async def disconnect(self):
    #     await self.websocket.close()
    #     self.websocket = None
    #
    # async def communicate(self, data):
    #     if self.websocket is None:
    #         raise RuntimeError("WebSocket connection is not established.")
    #     await self.websocket.send(json.dumps({'message': data}))
    #     response = await self.websocket.recv()
    #     print(response)

    async def communicate(self, data):
        uri = "ws://localhost:8000/ws/flow_data/"
        async with websockets.connect(uri) as websocket:
            await websocket.send(json.dumps({'data': data}))
            response = await websocket.recv()
            print(response)
