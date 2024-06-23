import os
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
import WebApp.communication.routing as ws_routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Praharak.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": URLRouter(
        ws_routing.websocket_urlpatterns
    ),
})
