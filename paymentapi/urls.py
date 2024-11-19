# urls.py
from django.urls import path
from paymentapi.views import * 
urlpatterns = [
    # path('create-order/', create_order, name='create_order'),
    path('payments/', PaymentAPIView.as_view(), name='payment'),
    path('payment/', payment_page, name='payment'),
    # Add other URLs as needed
]
