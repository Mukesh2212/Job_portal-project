from django.contrib import admin
from employee_dashboard.models import * 

@admin.register(EmployeeDashboard)
class EmployeeDashboardAdmin(admin.ModelAdmin):
    list_display = ['id','name','email','phone_number','message','upload_file','upload_img']
    
@admin.register(EmployerDashboard)
class EmployerDashboardAdmin(admin.ModelAdmin):
    list_display = ['id','select_date','select_time','problem_type','explain_the_problem']
    




