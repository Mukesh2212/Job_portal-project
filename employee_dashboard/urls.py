from django.contrib import admin
from employee_dashboard import views 
from django.urls import path,include
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [
   
    path("employee/", views.EmployeeApiView.as_view(),name="employee"),
    path("employeeimg/", views.EmployeeApiViewImg.as_view(),name="employeeimg"),
    path("feedback-employer/", views.EmployerApiView.as_view(),name="feedback-employer"),
    path("whatapps-support-api/", views.EmployerApiView.as_view(),name="whatapps-support-api"),
    path("employer-schedule/", views.EmployerScheduleApiView.as_view(),name="employer-schedule"),
    path("jsnondata/",views.export_data_as_json_text ,name="jsnondata"),
  

 

]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) 