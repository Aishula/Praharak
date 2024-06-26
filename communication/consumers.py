import json
from channels.generic.websocket import AsyncWebsocketConsumer


class PacketFlowDataConsumer(AsyncWebsocketConsumer):
    sender = None
    receiver = None
    pending_data = []

    async def connect(self):
        await self.accept()
        print("connected")

        # Determine if the client will be a sender or receiver
        if PacketFlowDataConsumer.receiver is None:
            PacketFlowDataConsumer.receiver = self
            print("Receiver assigned")
        elif PacketFlowDataConsumer.sender is None:
            PacketFlowDataConsumer.sender = self
            print("Sender assigned")
            # Send any pending messages to the receiver
            if PacketFlowDataConsumer.pending_data:
                for msg in PacketFlowDataConsumer.pending_data:
                    await self.send_to_receiver(msg)
                PacketFlowDataConsumer.pending_data = []

    async def disconnect(self, close_code):
        if self == PacketFlowDataConsumer.receiver:
            PacketFlowDataConsumer.receiver = None
            print("Receiver disconnected")
        elif self == PacketFlowDataConsumer.sender:
            PacketFlowDataConsumer.sender = None
            print("Sender disconnected")

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        data = text_data_json.get('data')

        if self == PacketFlowDataConsumer.sender:
            # Forward message to the receiver
            if PacketFlowDataConsumer.receiver:
                await self.send_to_receiver(data)
            else:
                # Store message if receiver is not yet connected
                PacketFlowDataConsumer.pending_data.append(data)
            await PacketFlowDataConsumer.sender.send(text_data=json.dumps({
                'message': "Data sent to receiver"
            }))

    async def send_to_receiver(self, data):
        if PacketFlowDataConsumer.receiver:
            await PacketFlowDataConsumer.receiver.send(text_data=json.dumps({
                'data': data
            }))


class WsTestConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        print("connected")
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        data = json.loads(text_data)
        message = data["message"]

        await self.send(text_data=json.dumps({
            "message": message
        }))
