from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/flow_data/', consumers.PacketFlowDataConsumer.as_asgi()),
]
