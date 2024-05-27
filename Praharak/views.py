from django.http import HttpResponse
from django.shortcuts import render 


def home(request):
    return HttpResponse("home")

def homepage(request):
    return render (request, "dashboard.html")

from django.shortcuts import render
import json

def index(request):
    # Sample data for demonstration
    log_sources = [
        {'source': 'Firewall', 'ip': '192.168.1.1', 'protocol': 'TCP', 'remarks': 'Normal'},
        {'source': 'Router', 'ip': '192.168.1.2', 'protocol': 'UDP', 'remarks': 'Suspicious'},
        
    ]
    time_stamps = ['2023-01-01', '2023-01-02', '2023-01-03', '2023-01-04', '2023-01-05']
    attack_data = [5, 10, 15, 10, 5]
    normal_data = [15, 10, 5, 10, 15]
    packet_flow_rate = [10, 20, 15, 25, 30]

    context = {
        'log_sources': log_sources,
        'time_stamps': json.dumps(time_stamps),
        'attack_data': json.dumps(attack_data),
        'normal_data': json.dumps(normal_data),
        'packet_flow_rate': json.dumps(packet_flow_rate),
    }
    return render(request, 'dashboard.html', context)
