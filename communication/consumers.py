import json
from channels.generic.websocket import AsyncWebsocketConsumer


class PacketFlowDataConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']

        self.send(text_data=json.dumps({
            'message': message
        }))

    # async def receive(self, text_data):
    #     data = json.loads(text_data)
    #     message = data["message"]
    #
    #     await self.send(text_data=json.dumps({
    #         "message": "I am from django consumers"
    #     }))
