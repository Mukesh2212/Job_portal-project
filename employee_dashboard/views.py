from django.shortcuts import render
from employee_dashboard.serializers import * 
from employee_dashboard.models import * 
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class EmployeeApiView(APIView):
    def post(self, request, format=None):
        try:
            serializer = EmployeeSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"Msg": "Created successfully"}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class EmployeeApiViewImg(APIView):
    def post(self, request, format=None):
        try:
            serializer = EmployeeSerializerImg(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"Msg": "Created successfully"}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class EmployerApiView(APIView):
    def post(self, request, format=None):
        try:
            serializer = EmployeeSerializerImg(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"Msg": "Created successfully"}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class EmployerScheduleApiView(APIView):
    def post(self, request, format=None):
        try:
            serializer = EmployerSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({"Msg": "Created successfully"}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
