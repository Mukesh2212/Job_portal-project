from django.db import models

class EmployeeDashboard(models.Model):
    name = models.CharField(max_length=150,blank=False,null=False) 
    email = models.EmailField(unique=True,blank=False,null=False)
    phone_number = models.CharField(max_length=13,blank=False,null=False) 
    message = models.TextField(blank=False,null=False) 
    upload_file = models.FileField(upload_to='uploads/',blank=False,null=False) 
    upload_img = models.ImageField(upload_to='uploadsimg/',blank=False,null=False)



class EmployerDashboard(models.Model):
    PROBLEM_TYPE_CHOICES = [
        ('bug', 'Bug'),
        ('feature', 'Feature Request'),
        ('support', 'Support'),
        ('other', 'Other'),
    ]
    select_date = models.DateField(auto_created=True,blank=False,null=False) 
    select_time = models.TimeField(auto_now=True,blank=False,null=False) 
    problem_type = models.CharField(max_length=200,choices=PROBLEM_TYPE_CHOICES,blank=False,null=False) 
    explain_the_problem = models.TextField(blank=False,null=False) 
    