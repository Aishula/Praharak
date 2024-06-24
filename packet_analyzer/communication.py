import json
import websockets


class Communication:
    @staticmethod
    async def communicate(self, data):
        print(data)
        uri = "ws://localhost:8000/ws/flow_data/"
        async with websockets.connect(uri) as websocket:
            await websocket.send(json.dumps({'message': "I am from packet analyzer"}))
            response = await websocket.recv()
            print(response)
