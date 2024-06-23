from django.urls import path
from .views import homepage, ws_test

urlpatterns = [
    path("", homepage, name="home"),
    path("ws-test/", ws_test, name="ws_test"),
]
