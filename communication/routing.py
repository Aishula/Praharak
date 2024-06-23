from django.urls import re_path
from .consumers import PacketFlowDataConsumer

websocket_urlpatterns = [
    re_path(r'ws/flow_data/$', PacketFlowDataConsumer.as_asgi()),
]
