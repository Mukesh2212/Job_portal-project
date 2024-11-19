import razorpay
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))




@csrf_exempt
def payment_page(request):
    if request.method == 'POST':
        amount = '1'
        currency = 'INR'
        if amount and amount.strip():
            order = client.order.create({'amount': int(amount) * 100, 'currency': currency})
            return JsonResponse(order)
        else:
            return JsonResponse({'error': 'Amount is required.'}, status=400)

    return render(request, 'payment.html')



class PaymentAPIView(APIView):
    def post(self, request, *args, **kwargs):
        amount = request.data.get('amount') 
        currency = 'INR'
        if amount and amount.strip():
            order = client.order.create({'amount': int(amount) * 100, 'currency': currency})
            return Response(order, status=status.HTTP_201_CREATED)
        else:
            return Response({'error': 'Amount is required.'}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
        return Response({'message': 'This is the payment API. Use POST to create an order.'})
