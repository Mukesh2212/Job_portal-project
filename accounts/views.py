# registration/views.py
from rest_framework import status
from .serializers import *
from .models import *
from django.contrib.auth import authenticate, login
from rest_framework.decorators import api_view
from rest_framework import status
from rest_framework.views import APIView
from rest_framework import status
from .models import Job
from .serializers import JobSerializer
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import status
from .models import Blog
from .serializers import BlogSerializer
from django.contrib.auth.tokens import default_token_generator
import random
import string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.core.cache import cache
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken


class RegistrationView(APIView):
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
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



class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, id=None):
        try:
            user = get_object_or_404(CustomUser, id=id)
            if user.email != request.data.get('email'):
                return Response({"error": "You are not authorized to logout this user"}, status=status.HTTP_403_FORBIDDEN)
            refresh_token = request.data.get("refresh_token")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)   
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
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



class EmpMyprofleApiview(APIView):
    def post(self, request):
        serializer = EmpMyProfileSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request, pk=None):
        if pk:
            try:
                profile = EmpMyProfile.objects.get(pk=pk) 
            except EmpMyProfile.DoesNotExist:
                return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
            serializer = EmpMyProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            profiles = EmpMyProfile.objects.all()  
            serializer = EmpMyProfileSerializer(profiles, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk=None):
        if pk is None:
            return Response({'error': 'Profile ID is required for update'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            profile = EmpMyProfile.objects.get(pk=pk)  
        except EmpMyProfile.DoesNotExist:
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = EmpMyProfileSerializer(profile, data=request.data, partial=False)  
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
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
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class LoginAPIView(APIView):

    def post(self, request):
        # Get username and password from request data
        username = request.data.get('username')
        password = request.data.get('password')

        # Check if both fields are provided
        if not username or not password:
            return Response({"error": "Username and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate user
        user = authenticate(username=username, password=password)

        # Check if authentication was successful
        if user is not None:
            # Return a success response (e.g., with token or user details)
            return Response({"message": "Login successful", "user_id": user.id, "username": user.username}, status=status.HTTP_200_OK)
        else:
            # Return error if authentication failed
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
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

# ####################################################### new code for reset password by mukesh ###################################


# class ForgotPasswordView(APIView):
#     def post(self, request):
#         email = request.data.get('email')
#         if not email:
#             return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
#         try:
#             user = CustomUser.objects.get(email=email)
#         except CustomUser.DoesNotExist:
#             return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
#         token = default_token_generator.make_token(user)
#         uid = urlsafe_base64_encode(force_bytes(user.pk))
#         base_url = request.build_absolute_uri('/')  # Get the base URL
#         reset_url = f"{base_url}accounts/api/reset-password-confirm/{uid}/{token}/"
#         send_mail(
#             'Password Reset Request',
#             f'Click the link below to reset your password:\n{reset_url}',
#             'mk2648054@gmail.com',
#             [user.email],
#             fail_silently=False,
#         )
#         return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)
    
class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        # base_url = 'https://jobadmin.hola9.com/accounts/'  # Set your desired base URL
        base_url = 'https://jobportal-42193.web.app/PasswordChange/'
        # reset_url = f"{base_url}api/reset-password-confirm/{uid}/{token}/"
        # reset_url = f"{base_url}PasswordChange/{uid}/{token}/"
        reset_url = f"{base_url}{uid}/{token}/"
        send_mail(
            'Password Reset Request',
            f'Click the link below to reset your password:\n{reset_url}',
            'mk2648054@gmail.com',
            [user.email],
            fail_silently=False,
        )
        return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)

    
    
class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None
        if user is not None and default_token_generator.check_token(user, token):
            new_password = request.data.get('new_password')
            confirm_new_password = request.data.get('confirm_new_password')
            if not new_password or not confirm_new_password:
                return Response({'error': 'Both new password and confirm password are required'}, status=status.HTTP_400_BAD_REQUEST)
            if new_password != confirm_new_password:
                return Response({'error': 'New password and confirm password do not match'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password has been reset successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)



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


# def generate_random_password(length=12):
#     alphabet = string.ascii_letters  # This includes both uppercase and lowercase letters
#     password = ''.join(random.choice(alphabet) for _ in range(length))
#     return password

# class EmployerRegistrationAPIView(APIView):
#     def get(self, request):
#         employers = EmployerRegistration.objects.all()
#         serializer = EmployerRegistrationSerializer(employers, many=True)
#         return Response(serializer.data)

#     def generate_random_password(length=8):
#         """Generate a random password with letters and digits."""
#         characters = string.ascii_letters + string.digits
#         return ''.join(random.choice(characters) for _ in range(length))
    

#     def post(self, request):
#         serializer = EmployerRegistrationSerializer(data=request.data)
#         if serializer.is_valid():
#             password = generate_random_password()
#             first_name = request.data.get('first_name', '')
#             last_name = request.data.get('last_name', '')
#             random_digit = random.randint(000, 999)
#             full_name = f"{first_name[:3]}{last_name[:3]}{random_digit}"
#             user = CustomUser.objects.create_user(email=request.data['email'], password=password, full_name=full_name)
#             employer_registration = serializer.save()
#             email_message = f"Your login credentials:\nUsername: {user.full_name}\nPassword: {password}"
#             send_mail(
#                 'Login Credentials',
#                 email_message,
#                 'mk2648054@gmail.com',  
#                 [request.data['email']],
#                 fail_silently=False,
#             )
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


### new code of employregistration 
# def generate_random_password(length=12):
#     alphabet = string.ascii_letters  # This includes both uppercase and lowercase letters
#     password = ''.join(random.choice(alphabet) for _ in range(length))
#     return password
# class EmployerRegistrationAPIView(APIView):
#     def get(self, request):
#         employers = EmployerRegistration.objects.all()
#         serializer = EmployerRegistrationSerializer(employers, many=True)
#         return Response(serializer.data)
    
#     @staticmethod
#     def generate_random_password(length=12):
#         alphabet = string.ascii_letters 
#         password1 = ''.join(random.choice(alphabet) for _ in range(length))
#         return password1
#     def post(self, request):
#         serializer = EmployerRegistrationSerializer(data=request.data)
#         if serializer.is_valid():
#             password = self.generate_random_password()
#             first_name = request.data.get('first_name', '')
#             last_name = request.data.get('last_name', '')
#             random_digit = random.randint(000, 999)
#             full_name = f"{first_name[:3]}{last_name[:3]}{random_digit}"
#             user = CustomUser.objects.create_user(email=request.data['email'], password=password, full_name=full_name)
#             user.save()
#             employer_registration = serializer.save()
#             email_message = f"Your login credentials:\nUsername: {user.full_name}\nPassword: {password}"
#             send_mail(
#                 'Login Credentials',
#                 email_message,
#                 'mk2648054@gmail.com',  
#                 [request.data['email']],
#                 fail_silently=False,
#             )
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    




class EmployerRegistrationAPIView(APIView):
    def get(self, request):
        employers = EmployerRegistration.objects.all()
        serializer = EmployerRegistrationSerializer(employers, many=True)
        return Response(serializer.data)
    
    @staticmethod
    def generate_random_password(length=12):
        alphabet = string.ascii_letters
        password1 = ''.join(random.choice(alphabet) for _ in range(length))
        return password1

    def post(self, request):
        serializer = EmployerRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            password = self.generate_random_password()
            email = request.data.get('email', '')
            user = CustomUser.objects.create_user(email=email, password=password, full_name=email)
            user.save()
            employer_registration = serializer.save()
            email_message = f"Your login credentials:\nUsername: {user.full_name}\nPassword: {password}"
            send_mail(
                'Login Credentials',
                email_message,
                'mk2648054@gmail.com',  
                [email],                
                fail_silently=False,
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


        
class EmployerRegisteredProfileAPIView(APIView):
    def get(self, request, id=None):
        if id:
            employer = get_object_or_404(EmployerRegistration, id=id)
            otp = random.randint(100000, 999999)
            employer.otp = otp
            employer.save()
            subject = 'otp for employee register profile'
            message = f'Hello {employer.email},\n\nYour OTP code is: {otp}\n\nPlease use this code to proceed.'
            from_email = 'mk2648054@gmail.com'
            recipient_list = [employer.email] 
            try:
                send_mail(subject, message, from_email, recipient_list)
            except Exception as e:
                return Response({"error": f"Failed to send email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response({"message": f"OTP sent to {employer.email}"}, status=status.HTTP_200_OK)
        else:
            employers = EmployerRegistration.objects.all()
            serializer = EmployerRegistrationSerializer(employers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
    def put(self, request, id=None):
        if id is None:
            return Response({"error": "ID is required for updating an employer."}, status=status.HTTP_400_BAD_REQUEST)
        employer = get_object_or_404(EmployerRegistration, id=id)
        otp_from_request = request.data.get('otp')
        if not otp_from_request:
            return Response({"error": "OTP is required to update the employer."}, status=status.HTTP_400_BAD_REQUEST)
        if otp_from_request != employer.otp:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        serializer = EmployerRegistrationSerializer(employer, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class LoginAPIViewEmail(APIView):
#     def post(self, request):
#         serializer = LoginSerializerEmail(data=request.data)
#         if serializer.is_valid():
#             username = serializer.validated_data['username']
#             password = serializer.validated_data['password']
#             user = authenticate(request , username=username, password=password)
#             if user is  None:
#                 return Response({
#                     "message": "Login successful",
#                 }, status=status.HTTP_200_OK)
#             else:
#                 return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class LoginEmialAPIView(APIView):
    def post(self, request):
        password = request.data.get('password')
        email = request.data.get('email')
        if not email or not password:
            return Response({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)
        email = authenticate(request, username=email, password=password)
        if email is not None:
            return Response({
                'message': 'Login successful'
            }, status=status.HTTP_200_OK)
        else:
            raise AuthenticationFailed('Invalid credentials')


# class LoginEmailsAPIView(APIView):
#     def post(self, request):
#         serializer = EmailLoginSerializer(data=request.data)
#         if serializer.is_valid():
#             # user = serializer.validated_data
#             # login(request, user)
#             # token, created = Token.objects.get_or_create(user=user)
#             return Response({
#                 # "token": token.key,
#                 "message": "Login successful."
#             }, status=status.HTTP_200_OK)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class RstPwdEmployerAPIView(APIView):
#     def post(self, request):
#         serializer = ResetPasswordRequestSerializer(data=request.data)
#         if serializer.is_valid():
#             try:
#                 # Fetch the related CustomUser from EmployerRegistration
#                 employer = EmployerRegistration.objects.get(email=serializer.validated_data['email'])
#                 user = CustomUser.objects.get(email=employer.email)  # Assuming email is in CustomUser
                
#                 token = default_token_generator.make_token(user)
#                 uid = urlsafe_base64_encode(force_bytes(user.pk))
                
#                 # Updated reset URL
#                 reset_url = f"http://127.0.0.1:8000/accounts/restpwdemployerconfirm/{uid}/{token}/"
#                 email_message = f"Click the following link to reset your password: {reset_url}"

#                 send_mail(
#                     'Password Reset Request for employer registration',
#                     email_message,
#                     'mk2648054@gmail.com',
#                     [user.email],
#                     fail_silently=False,
#                 )
#                 return Response({'message': 'Password reset link sent to your email.'}, status=status.HTTP_200_OK)
#             except EmployerRegistration.DoesNotExist:
#                 return Response({'error': 'Employer not found'}, status=status.HTTP_404_NOT_FOUND)
#             except CustomUser.DoesNotExist:
#                 return Response({'error': 'Associated user not found'}, status=status.HTTP_404_NOT_FOUND)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

# class RstPwdEmployerAPIView(APIView):
#     def generate_otp(self):
#         """Generate a 6-digit random OTP (optional)."""
#         return random.randint(100000, 999999)
#     def post(self, request):
#         serializer = ResetPasswordRequestSerializer(data=request.data)
#         if serializer.is_valid():
#             try:
#                 employer = EmployerRegistration.objects.get(email=serializer.validated_data['email'])
#                 user = CustomUser.objects.get(email=employer.email)  
#                 token = default_token_generator.make_token(user)
#                 uid = urlsafe_base64_encode(force_bytes(user.pk))
#                 reset_url = f"https://jobadmin.hola9.com/accounts/restpwdemployerconfirm/{uid}/"
#                 otp = self.generate_otp()
#                 cache.set(f"otp_{user.pk}", otp, timeout=200)  # Store OTP in cache for 15 minutes
#                 email_message = f"Click the following link to reset your password: {reset_url}\nYour OTP is: {otp} (optional)."
                
#                 send_mail(
#                     'Password Reset for Employer Registration',
#                     email_message,
#                     'mk2648054@gmail.com',
#                     [user.email],
#                     fail_silently=False,
#                 )
#                 return Response({'message': 'Password reset link sent to your email.'}, status=status.HTTP_200_OK)
#             except EmployerRegistration.DoesNotExist:
#                 return Response({'error': 'Employer not found'}, status=status.HTTP_404_NOT_FOUND)
#             except CustomUser.DoesNotExist:
#                 return Response({'error': 'Associated user not found'}, status=status.HTTP_404_NOT_FOUND)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class RstPwdEmployerAPIView(APIView):
    def generate_otp(self):
        """Generate a 6-digit random OTP."""
        return random.randint(100000, 999999)
    
    def post(self, request):
        serializer = ResetPasswordRequestSerializer(data=request.data)
        if serializer.is_valid():
            try:
                employer = EmployerRegistration.objects.get(email=serializer.validated_data['email'])
                user = CustomUser.objects.get(email=employer.email) 
                otp = self.generate_otp()
                cache.set(f"otp_{user.pk}", otp, timeout=900) 
                email_message = f"Your OTP for resetting your password is: {otp}. It will expire in 5 minutes."                
                send_mail(
                    'Password Reset OTP',
                    email_message,
                    'mk2648054@gmail.com',
                    [user.email],
                    fail_silently=False,
                )
                return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)
            except EmployerRegistration.DoesNotExist:
                return Response({'error': 'Employer not found'}, status=status.HTTP_404_NOT_FOUND)
            except CustomUser.DoesNotExist:
                return Response({'error': 'Associated user not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class PasswordResetConfirmAPIView(APIView):
#     def post(self, request, uidb64, token):
#         serializer = PasswordResetConfirmSerializer(data=request.data)
#         if serializer.is_valid():
#             try:
#                 uid = urlsafe_base64_decode(uidb64).decode()
#                 user = get_object_or_404(CustomUser, pk=uid)
#             except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
#                 return Response({'error': 'Invalid token or user'}, status=status.HTTP_400_BAD_REQUEST)

#             if default_token_generator.check_token(user, token):
#                 user.set_password(serializer.validated_data['new_password'])
#                 user.save()
#                 return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
#             return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OTPPasswordResetAPIView(APIView):
    def post(self, request, uidb64):
        serializer = OTPPasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            try:
                uid = urlsafe_base64_decode(uidb64).decode()
                user = CustomUser.objects.get(pk=uid)
                stored_otp = cache.get(f"otp_{user.pk}")
                input_otp = request.data.get('otp')
                if stored_otp is None:
                    return Response({'error': 'OTP has expired or is invalid.'}, status=status.HTTP_400_BAD_REQUEST)
                if str(stored_otp) != str(input_otp):
                    return Response({'error': 'Incorrect OTP.'}, status=status.HTTP_400_BAD_REQUEST)
                user.set_password(serializer.validated_data['new_password'])
                user.save()               
                cache.delete(f"otp_{user.pk}")                
                return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({'error': 'Invalid user.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# class OTPPasswordResetAPIView(APIView):
#     def post(self, request, uidb64):
#         serializer = OTPPasswordResetSerializer(data=request.data)
#         if serializer.is_valid():
#             try:
#                 uid = urlsafe_base64_decode(uidb64).decode()
#                 user = CustomUser.objects.get(pk=uid)
#                 stored_otp = cache.get(f"otp_{user.pk}")
#                 # stored_otp = cache.get(f"otp_{user.email}")
#                 print(stored_otp,'*********************************')
#                 input_otp = request.data.get('otp')
#                 if stored_otp is None:
#                     return Response({'error': 'OTP has expired or is invalid.'}, status=status.HTTP_400_BAD_REQUEST)
#                 if str(stored_otp) != str(input_otp):
#                     return Response({'error': 'Incorrect OTP.'}, status=status.HTTP_400_BAD_REQUEST)
#                 new_password = request.data.get('new_password')
#                 confirm_new_password = request.data.get('confirm_new_password')
#                 if new_password != confirm_new_password:
#                     return Response({'error': 'Passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)
#                 user.set_password(new_password)
#                 user.save()
#                 cache.delete(f"otp_{user.pk}")
#                 # cache.delete(f"otp_{user.email}")
#                 return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
#             except CustomUser.DoesNotExist:
#                 return Response({'error': 'Invalid user.'}, status=status.HTTP_400_BAD_REQUEST)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

################  update password of employer 


class ChangePasswordAPIView(APIView):
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            return Response({'detail': 'Password changed successfully.'}, status=status.HTTP_200_OK)
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


