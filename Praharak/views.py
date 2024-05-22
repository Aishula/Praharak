from django.http import HttpResponse
from django.shortcuts import render 


def home(request):
    return HttpResponse("home")

def homepage(request):
    return render (request,"index.html")