# views.py
from django.shortcuts import render
from django.http import JsonResponse
import razorpay

def create_order(request):
    client = razorpay.Client(auth=("rzp_test_nIosTZUUfmixQH", "U93BHhDQvxRJOhAyia6mk6R8"))

    data = {
        "amount": 100,
        "currency": "INR",
        "receipt": "receipt#1",
        "notes": {
            "key1": "value3",
            "key2": "value2"
        }
    }
    
    order = client.order.create(data=data)
    
    return JsonResponse(order)
