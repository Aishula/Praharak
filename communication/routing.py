from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/ws-test/', consumers.PacketFlowDataConsumer.as_asgi()),
]
