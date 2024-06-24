import json
from channels.generic.websocket import AsyncWebsocketConsumer


class PacketFlowDataConsumer(AsyncWebsocketConsumer):
    sender = None
    receiver = None
    pending_messages = []

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
            if PacketFlowDataConsumer.pending_messages:
                for msg in PacketFlowDataConsumer.pending_messages:
                    await self.send_to_receiver(msg)
                PacketFlowDataConsumer.pending_messages = []

    async def disconnect(self, close_code):
        if self == PacketFlowDataConsumer.receiver:
            PacketFlowDataConsumer.receiver = None
            print("Receiver disconnected")
        elif self == PacketFlowDataConsumer.sender:
            PacketFlowDataConsumer.sender = None
            print("Sender disconnected")

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json.get('message')

        if self == PacketFlowDataConsumer.sender:
            # Forward message to the receiver
            if PacketFlowDataConsumer.receiver:
                await self.send_to_receiver(message)
            else:
                # Store message if receiver is not yet connected
                PacketFlowDataConsumer.pending_messages.append(message)

    async def send_to_receiver(self, message):
        if PacketFlowDataConsumer.receiver:
            await PacketFlowDataConsumer.receiver.send(text_data=json.dumps({
                'message': message
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
