# registration/views.py
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import *
from .models import *
from django.contrib.auth import authenticate, login
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Job
from .serializers import JobSerializer
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Blog
from .serializers import BlogSerializer
from django.shortcuts import get_object_or_404

class RegistrationView(APIView):
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            if request.data.get('terms_and_conditions', False) is not True:
                return Response({'terms_and_conditions': ['You must accept the terms and conditions.']}, status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        users = CustomUser.objects.all()
        serializer = CustomUserSerializer(users, many=True)
        return Response(serializer.data)

@api_view(['POST'])
def login_view(request):
    if request.method == 'POST':
        email = request.data.get('email')
        password = request.data.get('password')

        if email is not None and password is not None:
            user = authenticate(request, email=email, password=password)

            if user is not None:
                # Ensure you return a Django HttpResponse when logging in
                login(request, user)
                return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.permissions import AllowAny
# from rest_framework_simplejwt.tokens import RefreshToken


# @api_view(['POST'])
# @permission_classes([AllowAny])
# def login_view(request):
#     if request.method == 'POST':
#         email = request.data.get('email')
#         password = request.data.get('password')

#         if email is not None and password is not None:
#             user = authenticate(request, email=email, password=password)

#             if user is not None:
#                 login(request, user)
#                 refresh = RefreshToken.for_user(user)
#                 access_token = str(refresh.access_token)

#                 return Response({
#                     'access_token': access_token,
#                     'refresh_token': str(refresh)
#                 }, status=status.HTTP_200_OK)
#             else:
#                 return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
#         else:
#             return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

class EmployerSignUpView(APIView):
    def post(self, request):
        serializer = EmployerSignUpSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmployerLoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            employer = Employer.objects.get(email=email)

            # Check if the provided password matches the stored password
            if employer.password == password:
                return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        except Employer.DoesNotExist:
            return Response({'error': 'Employer not found'}, status=status.HTTP_404_NOT_FOUND)


from rest_framework import generics

class MyProfileListCreateView(generics.ListCreateAPIView):
    queryset = MyProfile.objects.all()
    serializer_class = MyProfileSerializer
    
# class UpdateMyProfileView(generics.RetrieveUpdateDestroyAPIView):
#     queryset = MyProfile.objects.all()
#     serializer_class = MyProfileSerializer
from django.http import Http404

class UpdateMyProfileView(APIView):
    def get_object(self, pk):
        try:
            return MyProfile.objects.get(pk=pk)
        except MyProfile.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        # Retrieve a single user profile
        profile = self.get_object(pk)
        serializer = MyProfileSerializer(profile)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        profile = self.get_object(pk)
        serializer = MyProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
        
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        profile = self.get_object(pk)
        profile.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class MyProfileUpdateView(APIView):
    def get_object(self, register_id):
        try:
            # Assuming register_id is the ID of the associated CustomUser
            return MyProfile.objects.get(email=CustomUser.objects.get(id=register_id).email)
        except MyProfile.DoesNotExist:
            return None

    def get(self, request, register_id):
        myprofile = self.get_object(register_id)
        if myprofile is not None:
            serializer = MyProfileSerializer(myprofile)
            return Response(serializer.data)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def put(self, request, register_id):
        myprofile = self.get_object(register_id)
        if myprofile is not None:
            serializer = MyProfileSerializer(myprofile, data=request.data,partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)
 

class CourseList(generics.ListCreateAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer

class ProfileHighlighterList(generics.ListCreateAPIView):
    queryset = ProfileHighlighter.objects.all()
    serializer_class = ProfileHighlighterSerializer

class BoostnowProfileFormList(generics.ListCreateAPIView):
    queryset = BoostnowProfileForm.objects.all()
    serializer_class = BoostnowProfileFormSerializer

class AdvancedJobSearchList(generics.ListCreateAPIView):
    queryset = AdvancedJobSearch.objects.all()
    serializer_class = AdvancedJobSearchSerializer

class CourseDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer

class ProfileHighlighterDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = ProfileHighlighter.objects.all()
    serializer_class = ProfileHighlighterSerializer

class BoostnowProfileFormDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = BoostnowProfileForm.objects.all()
    serializer_class = BoostnowProfileFormSerializer

class AdvancedJobSearchDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = AdvancedJobSearch.objects.all()
    serializer_class = AdvancedJobSearchSerializer
    



class JobListCreateAPIView(APIView):
    def get(self, request):
        jobs = Job.objects.all()
        serializer = JobSerializer(jobs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = JobSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class JobDetailAPIView(APIView):
    def get_object(self, pk):
        return get_object_or_404(Job, pk=pk)

    def get(self, request, pk):
        job = self.get_object(pk)
        serializer = JobSerializer(job)
        return Response(serializer.data)

    def put(self, request, pk):
        job = self.get_object(pk)
        serializer = JobSerializer(job, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        job = self.get_object(pk)
        job.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)




class BlogListCreateAPIView(APIView):
    def get(self, request):
        blogs = Blog.objects.all()
        serializer = BlogSerializer(blogs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = BlogSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class BlogDetailAPIView(APIView):
    def get_object(self, pk):
        return get_object_or_404(Blog, pk=pk)

    def get(self, request, pk):
        blog = self.get_object(pk)
        serializer = BlogSerializer(blog)
        return Response(serializer.data)

    def put(self, request, pk):
        blog = self.get_object(pk)
        serializer = BlogSerializer(blog, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        blog = self.get_object(pk)
        blog.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ContactDetailView(APIView):
    def get(self,request,format=None):
        contacts = ContactDetails.objects.all()
        serializer = ContactDetailsSerializer(contacts,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)    
   
    def post(self,request,format=None):
        serializer = ContactDetailsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class ReviewOnJObsViews(APIView):
    def get(self, request, format=None):
        limit = request.query_params.get("limit")


        if limit is not None:
            reviews = ReviewOnJobs.objects.all().order_by('-id')[:int(limit)]
        else:
            reviews = ReviewOnJobs.objects.all()


        # Serialize the queryset using the serializer
        serializer = ReviewOnJobsSerializer(reviews, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


    def post(self,request,format=None):
       serializer = ReviewOnJobsSerializer (data=request.data)
       if serializer.is_valid():
           serializer.save()
           return Response(serializer.data,status=status.HTTP_201_CREATED)  
       return Response (serializer.errors,status=status.HTTP_400_BAD_REQUEST)



###################### reset password  for register user ######################        
class SendPasswordResetEmailView(APIView):
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)


class UserPasswordResetView(APIView):
 
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)  

class SendPasswordResetEmailEmployeerView(APIView):
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailEmployeerSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)


class UserPasswordResetEmployeerView(APIView):
 
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetEmployeerSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)   

class EmployerProfileUpdateView(APIView):
    def get_object(self, employer_id):
        try:
            # Assuming register_id is the ID of the associated CustomUser
            # employer_user=Employer.objects.get(id=employer_id).email
            return MyProfile.objects.get(email=Employer.objects.get(id=employer_id).email)
           
        except MyProfile.DoesNotExist:
            return None
       
    def get(self, request, employer_id):
        myprofile = self.get_object(employer_id)
        if myprofile is not None:
            serializer = MyProfileSerializer(myprofile)
            return Response(serializer.data)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)


    def put(self, request, employer_id):
        myprofile = self.get_object(employer_id)
        if myprofile is not None:
            serializer = MyProfileSerializer(myprofile, data=request.data,partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)       
        
        
class ReviewListCreateAPIView(APIView):
    def get(self, request):
        reviews = Review.objects.all()
        serializer = ReviewSerializer(reviews, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ReviewSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ReviewRetrieveUpdateDestroyAPIView(APIView):
    def get_object(self, pk):
        try:
            return Review.objects.get(pk=pk)
        except Review.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def get(self, request, pk):
        review = self.get_object(pk)
        serializer = ReviewSerializer(review)
        return Response(serializer.data)

    def put(self, request, pk):
        review = self.get_object(pk)
        serializer = ReviewSerializer(review, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        review = self.get_object(pk)
        review.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class BookDemoListCreateAPIView(generics.ListCreateAPIView):
    queryset = BookDemo.objects.all()
    serializer_class = BookDemoSerializer

# class BookDemoRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
#     queryset = BookDemo.objects.all()
#     serializer_class = BookDemoSerializer

class BookDemoRetrieveUpdateDestroyAPIView(APIView):
    def get_object(self, pk):
        try:
            return BookDemo.objects.get(pk=pk)
        except Review.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def get(self, request, pk):
        review = self.get_object(pk)
        serializer = BookDemoSerializer(review)
        return Response(serializer.data)

    def put(self, request, pk):
        review = self.get_object(pk)
        serializer = BookDemoSerializer(review, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        review = self.get_object(pk)
        review.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ******************************************************************************************* 
# from django.contrib.auth.models import User
from django.core.mail import send_mail
from .models import CustomUser
import secrets
import string


def generate_random_password(length=12):
    alphabet = string.ascii_letters  # This includes both uppercase and lowercase letters
    password = ''.join(random.choice(alphabet) for _ in range(length))
    return password

class EmployerRegistrationAPIView(APIView):
    def get(self, request):
        employers = EmployerRegistration.objects.all()
        serializer = EmployerRegistrationSerializer(employers, many=True)
        return Response(serializer.data)

    
    def post(self, request):
        serializer = EmployerRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            # Generate a random password
            password = generate_random_password()

            # Combine first_name and last_name to create full_name
            full_name = f"{request.data.get('first_name', '')} {request.data.get('last_name', '')}"

            # Create a new user account with email as username, generated password, and full_name
            user = CustomUser.objects.create_user(email=request.data['email'], password=password, full_name=full_name)

            # Save EmployerRegistration instance
            employer_registration = serializer.save()

            # Send email with login credentials
            email_message = f"Your login credentials:\nUsername: {user.email}\nPassword: {password}"
            send_mail(
                'Login Credentials',
                email_message,
                'hruday9.kumar@gmail.com',  # Change this to your email address
                [request.data['email']],
                fail_silently=False,
            )

        
            
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ************************************************************************************************ 
import random
import math

def generateOTP():
    digits = "0123456789"
    OTP = ""
    for i in range(4):
        OTP += digits[math.floor(random.random() * 10)]

    return OTP

def generatingOTP(number):
    OTP = generateOTP()

    return OTP


  
url = "https://www.fast2sms.com/dev/bulkV2"
@api_view(['GET', 'POST'])
def otpGeneration(request):
    number = request.data['number']
    print(number)
    generatedOTP = generatingOTP(number)
    print(generatedOTP)
    s=OTPVerifiaction.objects.filter(phone_number=number).delete()
    print("end")
    # querystring = {"authorization":"NYUAGPHmCO27kq39ir8WB6txeTuFXhEIsSdcoMp0gfyvJ1aDwLQbBluGHPZeV0iOCjLwfxvsYyoWgTaM","variables_values":generatedOTP,"route":"otp","numbers":number}
    querystring = {"authorization":"j7VCDKwiSolWJM8Q6YqLUhgnApZaxcOBNIPt9k1yRmGF2bzu5d4YCF25mlIc3gJ0hVe9BiMrp16KPvS8","variables_values":generatedOTP,"route":"otp","numbers":number}

    headers = {
    'cache-control': "no-cache"
    }

    response = requests.request("GET", url, headers=headers, params=querystring)
    print("start")
    print(response.text)
    if generatedOTP:
        data = OTPVerifiaction(phone_number=number, otp=generatedOTP)
        data.save()
        print(generatedOTP)
        return Response({"OTPSent": True})
    else:
        return Response({"OTPSent": False})


@api_view(['PUT'])
def checkOTP(request):
    number = request.data['number']
    otp = request.data['otp']
    print("checking time",number,otp)
    generatedOTP = OTPVerifiaction.objects.filter(
        phone_number=number).values_list('otp')
    print(generatedOTP)
    if generatedOTP[0][0] == otp:
        data = OTPVerifiaction.objects.get(phone_number=number)
        data.is_verfied = True
        data.save()
        return Response({"status": True})

    else:
        return Response({"status": False})
    
    


# **************************************************************************
# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import OTP
from .serializers import OTPSerializer
from django.core.mail import send_mail
from django.conf import settings
import random

class SendOTP(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP
        otp_code = ''.join(random.choices('0123456789', k=6))

        # Save OTP to database
        otp_instance = OTP.objects.create(email=email, otp_code=otp_code)

        # Send OTP via email
        send_mail(
            'Your OTP',
            f'Your OTP is: {otp_code}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )

        return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)

class VerifyOTP(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp_code = request.data.get('otp_code')

        if not email or not otp_code:
            return Response({'error': 'Email and OTP code are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if OTP exists
        try:
            otp_instance = OTP.objects.get(email=email, otp_code=otp_code)
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        # If OTP is valid, delete it from the database
        # otp_instance.delete()
        otp_instance.is_verified = True
        otp_instance.save()

        return Response({'message': 'OTP verified successfully'}, status=status.HTTP_200_OK)
