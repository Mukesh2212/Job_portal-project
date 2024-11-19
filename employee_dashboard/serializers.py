from rest_framework import serializers 
from employee_dashboard.models import * 

class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployeeDashboard
        fields = ['name','email','phone_number','message','upload_file']

class EmployeeSerializerImg(serializers.ModelSerializer):
    class Meta:
        model = EmployeeDashboard 
        fields = ['name','email','phone_number','message','upload_img'] 


class EmployerSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployerDashboard
        fields = ['select_date','select_time','problem_type','explain_the_problem']

