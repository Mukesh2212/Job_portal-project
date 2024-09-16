from django.db import models

class EmployeeDashboard(models.Model):
    name = models.CharField(max_length=150,blank=True,null=True) 
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=13,null=True,blank=True) 
    message = models.TextField(null=True,blank=True) 
    upload_file = models.FileField(upload_to='uploads/') 
    upload_img = models.ImageField(upload_to='uploadsimg/')



class EmployerDashboard(models.Model):
    PROBLEM_TYPE_CHOICES = [
        ('bug', 'Bug'),
        ('feature', 'Feature Request'),
        ('support', 'Support'),
        ('other', 'Other'),
    ]
    select_date = models.DateField(auto_created=True,null=True,blank=True) 
    select_time = models.TimeField(auto_now=True,blank=True,null=True) 
    problem_type = models.CharField(max_length=200,choices=PROBLEM_TYPE_CHOICES,null=True,blank=True) 
    explain_the_problem = models.TextField(null=True,blank=True) 
    