from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone




class CustomUserManager(BaseUserManager):
    def create_user(self, email, full_name, password=None):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, full_name=full_name)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, password=None):
        user = self.create_user(email, full_name, password)
        user.is_admin = True
        user.is_staff = True
        user.save(using=self._db)
        return user

class CustomUser(AbstractBaseUser):
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255, default="null")
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    terms_and_conditions = models.BooleanField(default=False,blank=True,null=True)
    otp_register = models.CharField(max_length=6, blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True


class Employer(models.Model):
    username = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)  # Securely hash and store passwords
    terms_and_conditions = models.BooleanField(default=False)


class EmailUsername(models.Model):
    username = models.CharField(max_length=255)
    passowrd = models.CharField(max_length=128) 
    email = models.EmailField(unique=True)

class MyProfile(models.Model):              #### employer dashboard
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    upload_resume = models.FileField(upload_to='resumes/')
    degree = models.CharField(max_length=100)
    university = models.CharField(max_length=100)
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    description_1 = models.TextField()
    job_title = models.CharField(max_length=100)
    company = models.CharField(max_length=100)
    job_start_date = models.DateField(null=True, blank=True)
    job_end_date = models.DateField(null=True, blank=True)
    description_2 = models.TextField()
    skill_set = models.TextField()

    def __str__(self):
        return self.name




class EmpMyProfile(models.Model): # dashboard
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('N', 'Non-Binary'),
        ('O', 'Other'),
    ]
    profile_pics = models.ImageField(upload_to='uploads/', blank=False, null=False)
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=13)
    education = models.TextField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, blank=False, null=False)
    current_ctc = models.CharField(max_length=100, blank=False, null=False)
    experience = models.IntegerField(blank=False, null=False)
    expected_ctc = models.CharField(max_length=100, blank=False, null=False)
    preferred_location = models.CharField(max_length=100, blank=False, null=False)
    currenet_location = models.CharField(max_length=100, blank=False, null=False) 
    skill_set = models.TextField(blank=False, null=False)
    previours_employer = models.CharField(max_length=100, blank=False, null=False) 
    current_employer = models.CharField(max_length=100, blank=False, null=False) 
    upload_resume = models.FileField(upload_to='resumes/', blank=False, null=False)
    # otp = models.CharField(max_length=6, blank=True, null=True)
    job_role_dashboard = models.CharField(max_length=100, blank=False, null=False)

    def __str__(self):
        return self.name

class Course(models.Model):
    course_name = models.CharField(max_length=100)
    certification = models.CharField(max_length=100)
    completion_date = models.DateField()

    def __str__(self):
        return self.course_name

class ProfileHighlighter(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    education = models.TextField()
    work_experience = models.TextField()

    def __str__(self):
        return self.name

class BoostnowProfileForm(models.Model):
    full_name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    education = models.TextField()
    work_experience = models.TextField()

    def __str__(self):
        return self.full_name

class AdvancedJobSearch(models.Model):
    # pass
    jobRole = models.CharField(max_length=100,null=True,blank=True)  
    jobType = models.CharField(max_length=100,null=True,blank=True)  
    minExp = models.CharField(max_length=100,null=True,blank=True)
    maxExp = models.CharField(max_length=100,null=True,blank=True)  
    minSal = models.CharField(max_length=100,null=True,blank=True)
    maxSal = models.CharField(max_length=100,null=True,blank=True)
    location = models.CharField(max_length=100,null=True,blank=True)
    industry = models.CharField(max_length=100,null=True,blank=True)
    workMode = models.CharField(max_length=100,null=True,blank=True)
    education = models.CharField(max_length=100,null=True,blank=True)
    companyType = models.CharField(max_length=100,null=True,blank=True)
    companyName = models.CharField(max_length=100,null=True,blank=True)
    



class Job(models.Model):
    # pass
    jobType = models.CharField(max_length=100)
    jobRole = models.CharField(max_length=100)
    companyType = models.CharField(max_length=100)
    companyName = models.CharField(max_length=100)
    workMode = models.CharField(max_length=100)
    minExp = models.CharField(max_length=100)
    maxExp = models.CharField(max_length=100)
    minSal = models.CharField(max_length=100)
    maxSal = models.CharField(max_length=100)
    location = models.CharField(max_length=100)
    industry = models.CharField(max_length=100)
    jobDescription = models.CharField(max_length=1000)
    educationRequirement = models.CharField(max_length=100)
    applicationLink = models.CharField(max_length=200)
    companyDescription = models.CharField(max_length=1000)
    contactInfo = models.CharField(max_length=100)
    postingDate = models.CharField(max_length=100)
    expiringDate = models.CharField(max_length=100)





class Blog(models.Model):
    # CATEGORY_CHOICES = [
    #     ('technology', 'Technology'),
    #     ('marketing', 'Marketing'),
    #     ('finance', 'Finance'),
    #     # Add more choices as needed
    # ]

    title = models.CharField(max_length=255)
    author_name = models.CharField(max_length=255)
    author_email = models.CharField(max_length=255)
    date_of_submission = models.CharField(max_length=255)
    blog_content = models.TextField()
    # category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    category = models.TextField()
    keywords_tags = models.CharField(max_length=255, blank=True, null=True)
    author_bio = models.TextField()
    author_profile_picture = models.ImageField(upload_to='author_profile_pics/', null=True, blank=True)
    media_files =models.FileField(upload_to='blog_files/', max_length=255, default="null")
    def __str__(self):
        return self.title

class ContactDetails(models.Model):
    fullname = models.CharField(max_length=255,null=False,blank=False)    
    phonenNumber = models.CharField(max_length=20,null=False,blank=False)
    email= models.CharField(max_length=255,null=False,blank=False)
    subject=models.CharField(max_length=255,null=True,blank=True)
    description=models.CharField(max_length=255,null=True,blank=True)
   
    def __str__(self):
        return self.fullname
    
class ReviewOnJobs(models.Model):
    full_name =models.CharField(max_length=255,null=True,blank=True)
    emailphone = models.CharField(max_length=255,null=True,blank=True)
    descriptions = models.CharField(max_length=255,null=True,blank=True)
    rating = models.CharField(max_length=255,null=True,blank=True)
    def __str__(self):
        return self.full_name



class Review(models.Model):
    user_id = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    job_id = models.CharField(max_length=255,null=True,blank=True)  # Assuming job_id is an integer field
    message = models.TextField()
    rating = models.IntegerField()  # Assuming rating is an integer field



class BookDemo(models.Model):
    full_name = models.CharField(max_length=255)
    company_name = models.CharField(max_length=255)
    business_name = models.CharField(max_length=255)
    number_of_employees = models.PositiveIntegerField()
    mobile_number = models.CharField(max_length=15)  # Assuming mobile number as string

    def __str__(self):
        return self.full_name
    
    
class EmployerRegistration(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=255, unique=True)
    company_name = models.CharField(max_length=255)
    company_type = models.CharField(max_length=20, choices=[
        ('Freelancer', 'Freelancer'),
        ('Proprietorship', 'Proprietorship'),
        ('Partnership', 'Partnership'),
        ('LLP', 'LLP'),
        ('Pvt Ltd', 'Private Limited'),
    ])
    upload_document_1 = models.FileField(upload_to='documents/',null=False,blank=False)
    upload_document_2 = models.FileField(upload_to='documents/',null=False,blank=False)
    upload_document_3 = models.FileField(upload_to='documents/',null=False,blank=False)
    comany_pan_card = models.FileField(upload_to='pan_cards/',null=False,blank=False)
    phonpe_number = models.CharField(max_length=15)
    contact_person_name = models.CharField(max_length=100)
    contact_person_phone_number = models.CharField(max_length=15)
    otp = models.CharField(max_length=6, blank=True, null=True,default="") 

    def __str__(self):
        return self.company_name 
    






class EmployerRegistrationProfile(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=255, unique=True)
    company_name = models.CharField(max_length=255)
    company_type = models.CharField(max_length=20, choices=[
        ('Freelancer', 'Freelancer'),
        ('Proprietorship', 'Proprietorship'),
        ('Partnership', 'Partnership'),
        ('LLP', 'LLP'),
        ('Pvt Ltd', 'Private Limited'),
    ])
    upload_document_1 = models.FileField(upload_to='documents/',null=False,blank=False)
    upload_document_2 = models.FileField(upload_to='documents/',null=False,blank=False)
    upload_document_3 = models.FileField(upload_to='documents/',null=False,blank=False)
    comany_pan_card = models.FileField(upload_to='pan_cards/',null=False,blank=False)
    phonpe_number = models.CharField(max_length=15)
    contact_person_name = models.CharField(max_length=100)
    contact_person_phone_number = models.CharField(max_length=15)
    

    def __str__(self):
        return self.company_name
    
    
import datetime
# * Table that stores the OTP and is verfied or not
class OTPVerifiaction(models.Model):
    phone_number = models.IntegerField()
    otp = models.CharField(max_length=4)
    is_verfied = models.BooleanField(default=False)
    date = models.CharField(max_length=10,blank=False ,default=datetime.datetime.now().strftime('%Y-%m-%d'))
    
    

from django.utils import timezone
class OTP(models.Model):
    email = models.EmailField()
    otp_code = models.CharField(max_length=6)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)




class RandomPass(models.Model):
    email = models.EmailField()
    passwordname = models.CharField(max_length=128) 
    otp = models.IntegerField(null=True, blank=True)


class AccountUserOtp(models.Model):
    email = models.EmailField()
    user_otp = models.IntegerField(null=True, blank=True)
    registeredpassword = models.CharField(max_length=128)


class EmployeeRegistrationOtp(models.Model):
    email = models.EmailField()
    otp = models.IntegerField(null=False, blank=False)
    password = models.CharField(max_length=128)



# class JobEmployeeDashboard(models.Model):
#     job_id = models.ForeignKey(Job, on_delete=models.CASCADE)
#     emp_profile_id = models.ForeignKey(EmpMyProfile, on_delete=models.CASCADE)  










# models.py
from django.db import models

class JobEmployeeProfile(models.Model):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('N', 'Non-Binary'),
        ('O', 'Other'),
    ]

    # Job fields
    jobType = models.CharField(max_length=100)
    jobRole = models.CharField(max_length=100)
    companyType = models.CharField(max_length=100)
    companyName = models.CharField(max_length=100)
    workMode = models.CharField(max_length=100)
    minExp = models.CharField(max_length=100)
    maxExp = models.CharField(max_length=100)
    minSal = models.CharField(max_length=100)
    maxSal = models.CharField(max_length=100)
    location = models.CharField(max_length=100)
    industry = models.CharField(max_length=100)
    jobDescription = models.CharField(max_length=100)
    educationRequirement = models.CharField(max_length=100)
    applicationLink = models.CharField(max_length=200)
    companyDescription = models.CharField(max_length=100)
    contactInfo = models.CharField(max_length=100)
    postingDate = models.CharField(max_length=100)
    expiringDate = models.CharField(max_length=100)

    # Profile fields
    profile_pics = models.ImageField(upload_to='uploads/', blank=False, null=False)
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=13)
    education = models.TextField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, blank=False, null=False)
    current_ctc = models.CharField(max_length=100, blank=False, null=False)
    experience = models.IntegerField(blank=False, null=False)
    expected_ctc = models.CharField(max_length=100, blank=False, null=False)
    preferred_location = models.CharField(max_length=100, blank=False, null=False)
    currenet_location = models.CharField(max_length=100, blank=False, null=False)
    skill_set = models.TextField(blank=False, null=False)
    previours_employer = models.CharField(max_length=100, blank=False, null=False)
    current_employer = models.CharField(max_length=100, blank=False, null=False)
    upload_resume = models.FileField(upload_to='resumes/', blank=False, null=False)
    otp = models.CharField(max_length=6, blank=True, null=True)






class ChatMessage(models.Model):
    sender_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    write_message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    link = models.URLField(max_length=200, null=True, blank=True)

    def __str__(self):
        return f"{self.sender_user.email}: {self.write_message[:99999999]}"
    




class CompanyReview(models.Model):
    rating = models.CharField(max_length=10,null=False, blank=False)
    description = models.TextField(null=False, blank=False)    

# this is comment line