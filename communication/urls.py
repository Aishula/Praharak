from django.urls import path, include
from .views import ws_test


urlpatterns = [
    path("test/", ws_test, name="ws_test"),
    path("flow_data/", ws_test, name="flow_data"),
]
