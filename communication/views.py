from django.shortcuts import render


def ws_test(request):
    return render(request, 'ws_test.html')