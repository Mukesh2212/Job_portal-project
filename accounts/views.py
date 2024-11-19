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
from rest_framework.exceptions import NotFound
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter
from django.db.models import Q 
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password









class AdvancedsJobSearchAPIView(APIView):
    def get(self, request):
        job_type = request.query_params.get('jobType')
        job_role = request.query_params.get('jobRole')
        company_name = request.query_params.get('companyName')
        company_type = request.query_params.get('companyType')
        industry = request.query_params.get('industry')
        queryset = AdvancedJobSearch.objects.all()
        if job_type:
            queryset = queryset.filter(jobType__icontains=job_type)
        if job_role:
            queryset = queryset.filter(jobRole__icontains=job_role)
        if company_name:
            queryset = queryset.filter(companyName__icontains=company_name)
        if company_type:
            queryset = queryset.filter(companyType__icontains=company_type)
        if industry:
            queryset = queryset.filter(industry__icontains=industry)
        serializer = AdvancedJobSearchSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class RegistrationView(APIView):
    def post(self, request):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()  # This will call the create method in the serializer
            return Response({'Message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        users = CustomUser.objects.all()
        serializer = CustomUserSerializer(users, many=True)
        return Response(serializer.data)

# class LoginView(APIView):
#     def post(self, request):
#         email = request.data.get('email')
#         password = request.data.get('password')

#         # Authenticate the user using email as the identifier
#         user = authenticate(request, username=email, password=password)

#         if user is not None:
#             # User is authenticated successfully
#             return Response({
#                 'message': 'Login successful!',
#                 # 'email': user.email,
#                 # 'full_name': user.full_name,
#                 # Optionally, return a token or other data
#             }, status=status.HTTP_200_OK)
#         else:
#             # Authentication failed
#             return Response({'error': 'Invalid email or password.'}, status=status.HTTP_400_BAD_REQUEST)











class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            # Fetch the user from AccountUserOTP model
            user = CustomUser.objects.filter(email=email).last()
            print(user.email,'*********************')
            print(user.password,'&&&&&&&&&&&&&&&&&&&&')

            # Check if the provided password matches
            if user.email == email and user.password == password:
                # Authentication successful
                return Response({
                    'message': 'Login successful!',
                    # 'email': user.email,
                    # Include other user data if needed
                }, status=status.HTTP_200_OK)
            else:
                # Incorrect password
                return Response({'error': 'Invalid email or password.'}, status=status.HTTP_400_BAD_REQUEST)
        except AccountUserOtp.DoesNotExist:
            # User not found
            return Response({'error': 'Invalid email or password.'}, status=status.HTTP_400_BAD_REQUEST)






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
    




class EmpMyProfileSendOtpApiView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        profiles = CustomUser.objects.filter(email=email)

        if not profiles.exists():
            return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)
        for profile in profiles:
            otp = random.randint(100000, 999999)
            profile.otp_register = otp  
            profile.save()
            send_mail(
                'Your OTP for Profile Access',
                f'Your OTP for accessing your profile is: {otp}. It will expire in 15 minutes.',
                'mk2648054@gmail.com',
                [profile.email],
                fail_silently=False,
            )
        
        return Response({'message': 'OTP sent to the registered email(s).'}, status=status.HTTP_200_OK)





class EmpMyprofleVerifyotpApiview(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        

        if not email or not otp:
            return Response({'error': 'Email and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            profile = CustomUser.objects.get(email=email)
                
            if profile.otp_register == otp:
                # Optionally, clear the OTP after successful verification
                profile.otp_register = None  # Clear OTP to prevent reuse
                profile.save()
                return Response({'message': 'OTP verified successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        except EmpMyProfile.DoesNotExist:
            return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)

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
    # filter_backends = [DjangoFilterBackend, SearchFilter]
    
    # # Specify the fields you want to filter on
    # filterset_fields = ['companyType', 'companyName', 'jobRole', 'jobType', 'industry']

    # # Specify the fields you want to be searchable
    # search_fields = ['companyType', 'companyName', 'jobRole', 'jobType', 'industry']


class JobListCreateAPIView(APIView):
    def get(self, request, id=None):
        if id is not None:
            # Fetch individual job
            try:
                job = Job.objects.get(id=id)
                serializer = JobSerializer(job)
                return Response(serializer.data)
            except Job.DoesNotExist:
                return Response({"error": "Job not found."}, status=status.HTTP_404_NOT_FOUND)
        
        # Fetch all jobs
        jobs = Job.objects.all()
        serializer = JobSerializer(jobs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = JobSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, id):
        try:
            job = Job.objects.get(id=id)
        except Job.DoesNotExist:
            return Response({"error": "Job not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = JobSerializer(job, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, id):
        try:
            job = Job.objects.get(id=id)
            job.delete()
            return Response({"message": "Job deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except Job.DoesNotExist:
            return Response({"error": "Job not found."}, status=status.HTTP_404_NOT_FOUND)



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
    def get(self, request, id=None, format=None):
        if id is not None:
            try:
                contact = ContactDetails.objects.get(id=id)
                serializer = ContactDetailsSerializer(contact)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except ContactDetails.DoesNotExist:
                return Response({'error': 'Contact not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            contacts = ContactDetails.objects.all()
            serializer = ContactDetailsSerializer(contacts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
   
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
#         # base_url = 'https://jobadmin.hola9.com/accounts/'  # Set your desired base URL
#         base_url = 'https://jobportal-42193.web.app/PasswordChange/'
#         # reset_url = f"{base_url}api/reset-password-confirm/{uid}/{token}/"
#         # reset_url = f"{base_url}PasswordChange/{uid}/{token}/"
#         reset_url = f"{base_url}{uid}/{token}/"
#         send_mail(
#             'Password Reset Request',
#             f'Click the link below to reset your password:\n{reset_url}',
#             'mk2648054@gmail.com',
#             [user.email],
#             fail_silently=False,
#         )
#         return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)













# class ForgotPasswordView(APIView):
#     def generate_otp(self):
#         """Generate a 6-digit random OTP."""
#         return random.randint(100000, 999999)
    
#     def post(self, request):
#         serializer = CustomUserSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             try:
#                 # Get the CustomUser entry using the email
#                 user = CustomUser.objects.get(email=email)
                
#                 otp = self.generate_otp()
#                 # Store the OTP in cache for 15 minutes (900 seconds)
#                 cache.set(f"otp_{user.id}", otp, timeout=900) 
                
#                 email_message = f"Your OTP for resetting your password is: {otp}. It will expire in 15 minutes."                
#                 send_mail(
#                     'Password Reset OTP',
#                     email_message,
#                     'your_email@example.com',  # Replace with your email
#                     [user.email],
#                     fail_silently=False,
#                 )
#                 return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)
#             except CustomUser.DoesNotExist:
#                 return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)











# class ForgotPasswordView(APIView):
#     def post(self, request):
#         serializer = ForgotPasswordSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data['email']
#             try:
#                 # Get the CustomUser entry using the email
#                 user = CustomUser.objects.get(email=email)
                
#                 # Generate the password reset link
#                 uid = urlsafe_base64_encode(force_bytes(user.pk))
#                 token = default_token_generator.make_token(user)
#                 reset_link = f"http://127.0.0.1:8000/accounts/confirm-password/{uid}/" # Local path
#                 # reset_link = f"https://jobportal-42193.web.app/PasswordChange/:id/:token"

#                 # Prepare the email message
#                 email_message = (
#                     f"You can reset your password using the following link:\n{reset_link}"
#                 )
                
#                 send_mail(
#                     'Password Reset Link',
#                     email_message,
#                     'mk2648054@gmail.com',  # Replace with your email
#                     [user.email],
#                     fail_silently=False,
#                 )
#                 return Response({'message': 'Password reset link sent to your email.'}, status=status.HTTP_200_OK)
#             except CustomUser.DoesNotExist:
#                 return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)















class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                # Get the CustomUser entry using the email
                user = CustomUser.objects.get(email=email)
                print(user,'************')

                # Generate a random OTP
                otp = random.randint(100000, 999999)  # Generate a 6-digit OTP

                # Store the email and OTP in AccountUserOTP model
                account_user_otp = AccountUserOtp(
                    email=user,
                    user_otp=otp,  # Store the generated OTP
                    # registeredpassword=user.password  # Assuming you want to keep the current password
                )
                account_user_otp.save()

                # Prepare the email message
                email_message = (
                    f"Your OTP for password reset is: {otp}\n"
                    "Please use this OTP to proceed with your password reset."
                )

                # Send the email with the OTP
                send_mail(
                    'Password Reset OTP',
                    email_message,
                    'mk2648054@gmail.com',  # Replace with your email
                    [user.email],
                    fail_silently=False,
                )

                return Response({'message': 'OTP generated and sent to your email.'}, status=status.HTTP_200_OK)
            except CustomUser.DoesNotExist:
                return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)







    
# class PasswordResetConfirmView(APIView):
#     def post(self, request, uidb64, token):
#         try:
#             uid = urlsafe_base64_decode(uidb64).decode()
#             user = CustomUser.objects.get(pk=uid)
#         except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
#             user = None
#         if user is not None and default_token_generator.check_token(user, token):
#             new_password = request.data.get('new_password')
#             confirm_new_password = request.data.get('confirm_new_password')
#             if not new_password or not confirm_new_password:
#                 return Response({'error': 'Both new password and confirm password are required'}, status=status.HTTP_400_BAD_REQUEST)
#             if new_password != confirm_new_password:
#                 return Response({'error': 'New password and confirm password do not match'}, status=status.HTTP_400_BAD_REQUEST)
#             user.set_password(new_password)
#             user.save()
#             return Response({'message': 'Password has been reset successfully'}, status=status.HTTP_200_OK)
#         else:
#             return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)









# class PasswordResetConfirmView(APIView):
#     def post(self, request, uidb64):
#         serializer = CustomforgetPasswordSerializer(data=request.data)
#         if serializer.is_valid():
#             try:
#                 uid = urlsafe_base64_decode(uidb64).decode()
#                 user = CustomUser.objects.get(id=uid)  
                
#                 new_password = serializer.validated_data['new_password']
#                 confirm_password = serializer.validated_data['confirm_new_password']
                
#                 # Check if new password and confirm password match
#                 if new_password != confirm_password:
#                     return Response({'error': 'New password and confirm password do not match.'}, status=status.HTTP_400_BAD_REQUEST)
                
#                 # Set the new password
#                 user.set_password(new_password)  # Use set_password to hash the password
#                 user.save()

#                 return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
#             except CustomUser.DoesNotExist:
#                 return Response({'error': 'Invalid user.'}, status=status.HTTP_400_BAD_REQUEST)
        
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)













class PasswordResetConfirmView(APIView):
    def post(self, request):
        otp = request.data.get('otp')  
        new_password = request.data.get('new_password')  
        confirm_password = request.data.get('confirm_new_password')  
        
        if new_password != confirm_password:
            return Response({'error': 'New password and confirm password do not match.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            
            account_user_otp = AccountUserOtp.objects.get(user_otp=otp)  
            user = CustomUser.objects.get(email=account_user_otp.email)   
            user.password = new_password 
            user.save()
            return Response({'message': 'Password reset successful. Password stored in AccountUserOTP.'}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except AccountUserOtp.DoesNotExist:
            return Response({'error': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'error': 'Invalid request data.'}, status=status.HTTP_400_BAD_REQUEST)



















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




class EmployerRegistrationAPIView(APIView):
    def get(self, request, id=None):
        if id is not None:
            try:
                employer = EmployerRegistration.objects.get(id=id)
                serializer = EmployerRegistrationSerializer(employer)
                return Response(serializer.data)
            except EmployerRegistration.DoesNotExist:
                return Response({'error': 'Employer not found.'}, status=status.HTTP_404_NOT_FOUND)
        
        employers = EmployerRegistration.objects.all()
        serializer = EmployerRegistrationSerializer(employers, many=True)
        return Response(serializer.data)

    @staticmethod
    def generate_random_password(length=12):
        alphabet = string.ascii_letters + string.digits  # Use letters and digits for better security
        password = ''.join(random.choice(alphabet) for _ in range(length))
        return password

    def post(self, request):
        password = self.generate_random_password()
        serializer = EmployerRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            employer_registration = serializer.save()
            random_pass_entry = EmployeeRegistrationOtp(email=employer_registration.email, password=password)  
            random_pass_entry.save()
            email_message = f"Your login credentials:\nUsername: {employer_registration.email}\nPassword: {password}"
            send_mail(
                'Login Credentials',
                email_message,
                'mk2648054@gmail.com',  
                [employer_registration.email],                
                fail_silently=False,
            )
            return Response({'message': 'Employer registered successfully.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    def put(self, request, id=None):
        try:
            employer_registration = EmployerRegistration.objects.get(id=id)  # Get the existing employer
        except EmployerRegistration.DoesNotExist:
            return Response({'error': 'Employer not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = EmployerRegistrationSerializer(employer_registration, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
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




class LoginEmialAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        print(password,'**********')
        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)
        random_pass_entry = EmployerRegistration.objects.filter(email=email).last()
        passwordname = EmployeeRegistrationOtp.objects.filter(password=password).order_by('-id').first()
        if random_pass_entry is None:
            raise AuthenticationFailed('Invalid credentials')
        if password == passwordname.password and email == random_pass_entry.email:  
            return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        else:
            raise AuthenticationFailed('Invalid credentials')


from django.contrib.auth.tokens import default_token_generator 






# class RstPwdEmployerAPIView(APIView):
#     def generate_otp(self):
#         """Generate a 6-digit random OTP."""
#         return random.randint(100000, 999999)

#     def post(self, request):
#         serializer = ResetPasswordRequestSerializer(data=request.data)
#         if serializer.is_valid():
#             try:
#                 # Fetch the RandomPass entry using the provided email
#                 random_pass_entry = RandomPass.objects.get(email=serializer.validated_data['email'])
                
#                 # Generate and cache the OTP
#                 otp = self.generate_otp()
#                 cache.set(f"otp_{random_pass_entry.id}", otp, timeout=300)  # OTP valid for 5 minutes

#                 # Generate token and uid for password reset
#                 # token = default_token_generator.make_token(random_pass_entry)
#                 uid = urlsafe_base64_encode(force_bytes(random_pass_entry.id))  # Use the ID of the RandomPass entry
                
#                 # Updated reset URL
#                 # reset_url = f"http://127.0.0.1:8000/accounts/restpwdemployerconfirm/{uid}"
#                 # reset_url = f"https://jobportal-42193.web.app/PasswordChange/:MQ/:token"
#                 reset_url = f"https://jobportal-42193.web.app/PasswordChange/:id/:token"
                
                
#                 # Prepare email message
#                 email_message = (
#                     f"Your OTP for resetting your password is: {otp}\n"
#                     f"Click the following link to reset your password: {reset_url}"
#                 )

#                 # Send the email
#                 send_mail(
#                     'Password Reset Request for Employer Registration',
#                     email_message,
#                     'mk2648054@gmail.com',
#                     [random_pass_entry.email],
#                     fail_silently=False,
#                 )
                
#                 return Response({'message': 'OTP and password reset link sent to your email.'}, status=status.HTTP_200_OK)
#             except RandomPass.DoesNotExist:
#                 return Response({'error': 'Email not found in records.'}, status=status.HTTP_404_NOT_FOUND)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class RstPwdEmployerAPIView(APIView):
    def generate_otp(self):
        """Generate a 6-digit random OTP."""
        return random.randint(100000, 999999)

    def post(self, request):
        serializer = ResetPasswordRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                # Get the EmployerRegistration entry using the email
                random_pass_entry = EmployerRegistration.objects.filter(email=email).last()
                
                otp = self.generate_otp()
                
                # Store the OTP in the EmployerRegistrationOtp model
                empr = EmployeeRegistrationOtp.objects.update(email=email, otp=otp)
                # empr.save()
                
                email_message = f"Your OTP for resetting your password is: {otp}. It will expire in 15 minutes."
                send_mail(
                    'Password Reset OTP',
                    email_message,
                    'mk2648054@gmail.com',  # Replace with your email
                    [random_pass_entry.email],
                    fail_silently=False,
                )
                return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)
            except EmployerRegistration.DoesNotExist:
                return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmployerRegisteredProfileAPIView(APIView):
    def get(self, request, id=None):
        if id:
            employer = get_object_or_404(EmployerRegistrationProfile, id=id)
            serializer = EmployerRegistrationSerializerProfile(employer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            employers = EmployerRegistrationProfile.objects.all()
            serializer = EmployerRegistrationSerializerProfile(employers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
    
    def post(self, request):
        serializer = EmployerRegistrationSerializerProfile(data=request.data)
        if serializer.is_valid():
            serializer.save()  
            return Response({'message': 'Employer registration successfully'} ,status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    
    def put(self, request, id):
        employer = get_object_or_404(EmployerRegistrationProfile, id=id)  
        serializer = EmployerRegistrationSerializerProfile(employer, data=request.data)  
        
        if serializer.is_valid():
            serializer.save()  
            return Response({'message': 'Employer profile updated successfully'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class OTPPasswordResetAPIView(APIView):
    def post(self, request):
        # Get OTP, email, and new password details from the request data
        input_otp = request.data.get('otp')
        email = request.data.get('email')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_new_password')

        try:
            # Check if the email exists in the EmployerRegistration model
            if not EmployerRegistration.objects.filter(email=email).exists():
                return Response({'error': 'Email not found.'}, status=status.HTTP_404_NOT_FOUND)

            # Retrieve the RandomPass entry using the OTP
            random_pass_entry = EmployeeRegistrationOtp.objects.filter(otp=input_otp, email=email).last()

            # Check if the OTP is valid
            if random_pass_entry is None:
                return Response({'error': 'OTP has expired or is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

            # Check for new password and confirmation
            if new_password != confirm_password:
                return Response({'error': 'New password and confirm password do not match.'}, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password directly (not hashed)
            random_pass_entry.password = new_password
            random_pass_entry.save()

            # Clear the OTP from the cache (if using cache)
            cache.delete(f"otp_{random_pass_entry.id}")

            return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class EmployerSendOTPAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            employer = EmployerRegistration.objects.get(email=email)
            otp = random.randint(100000, 999999) 
            employer.otp = otp 
            employer.save()
            send_mail(
                'otp for edit ',
                f'Your OTP for edit: {otp}. It will expire in 15 minutes.',
                'mk2648054@gmail.com',  
                [email],
                fail_silently=False,
            )
            return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)
        
        except EmployerRegistration.DoesNotExist:
            return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)
        




class EmployerVerifyOTPAPIView(APIView):
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({'error': 'Email and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            employer = EmployerRegistration.objects.get(email=email)

            # Check if the OTP matches
            if employer.otp == otp:
                # Optionally, clear the OTP after successful verification
                employer.otp = None  # Clear OTP to prevent reuse
                employer.save()
                return Response({'message': 'OTP verified successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        except EmployerRegistration.DoesNotExist:
            return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)



class ChangePasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        if not email or not current_password or not new_password or not confirm_password:
            return Response({'error': 'All fields are required'}, status=status.HTTP_400_BAD_REQUEST)

        random_pass_entry = EmployeeRegistrationOtp.objects.filter(email=email,password=current_password).order_by('-id').first()

        if random_pass_entry is None:
            raise AuthenticationFailed('Invalid credentials')

        if current_password != random_pass_entry.password:
            raise AuthenticationFailed('Current password is incorrect')

        if new_password != confirm_password:
            return Response({'error': 'New password and confirm password do not match'}, status=status.HTTP_400_BAD_REQUEST)

        random_pass_entry.password = new_password
        random_pass_entry.save()

        return Response({'message': 'Password updated successfully'}, status=status.HTTP_200_OK)
        
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




class JobApplyView(APIView):
    def get(self, request, id=None):
        if id is not None:
            try:
                job = Job.objects.get(id=id)
                jobserializer = JobSerializer(job)
                myempprofile = EmpMyProfile.objects.get(id=id)
                proserializer = EmpMyProfileSerializer(myempprofile)
                combined_data = {
                    'job': jobserializer.data,
                    'Myprofile': proserializer.data
                }
                return Response(combined_data, status=status.HTTP_200_OK)
            except Job.DoesNotExist:
                raise NotFound({'detail': 'Job not found.'})
            except MyProfile.DoesNotExist:
                raise NotFound({'detail': 'Profile not found.'})
       


class JobEmployProfiledashobard(APIView):
    def post(self, request):
        serializer = JobEmployeeProfileSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, id=None):
        if id is not None:
            try:
                application = JobEmployeeProfile.objects.get(id=id)
                serializer = JobEmployeeProfileSerializer(application)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except JobEmployeeProfile.DoesNotExist:
                raise NotFound({'detail': 'Job application not found.'})

        # Fetch all applications if no ID is provided
        applications = JobEmployeeProfile.objects.all()
        serializer = JobEmployeeProfileSerializer(applications, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    






class ChatView(APIView):
    def post(self, request):
        email = request.data.get('email')  
        write_message = request.data.get('write_message')  
        if not email or not write_message:
            return Response({'error': 'Email and message content are required.'}, status=status.HTTP_400_BAD_REQUEST)
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            try:
                sender = CustomUser.objects.get(email=email) 
            except CustomUser.DoesNotExist:
                return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)
            message = serializer.save(sender_user=sender)  
            users = CustomUser.objects.all()
            for user in users:
                full_message = f"New Message from {sender.full_name}:\n\n{message.write_message}\n\nLink: {message.link or 'No link provided'}"
                send_mail(
                    subject=f'New Message from {sender.email , sender.full_name}',
                    message=full_message,
                    from_email='mk2648054@gmail.com',  
                    recipient_list=[user.email],
                    fail_silently=False,
                )
            return Response({'message': 'Message sent successfully!'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        messages = ChatMessage.objects.all()
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)




class JobRoleMatchAPIView(APIView):
    def get(self, request, id):
        try:
            user_profile = EmpMyProfile.objects.get(id=id)
        except EmpMyProfile.DoesNotExist:
            return Response({'error': 'User profile not found.'}, status=status.HTTP_404_NOT_FOUND)
        matched_jobs = Job.objects.filter(jobRole=user_profile.job_role_dashboard)

        if matched_jobs.exists():
            return Response({
                'message': 'Your job role is matched.',
                'matched_jobs': [
                    { 
                        'jobRole': job.jobRole 
                    } for job in matched_jobs
                ]
            }, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'No matching job roles found.'}, status=status.HTTP_200_OK)







class CompanyReviewAPIView(APIView):
    def get(self, request, id=None):
        if id is not None:
            try:
                review = CompanyReview.objects.get(id=id)
                serializer = CompanyReviewSerializer(review)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except CompanyReview.DoesNotExist:
                return Response({'error': 'Review not found.'}, status=status.HTTP_404_NOT_FOUND)

        reviews = CompanyReview.objects.all()
        serializer = CompanyReviewSerializer(reviews, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = CompanyReviewSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, id):
        try:
            review = CompanyReview.objects.get(id=id)
        except CompanyReview.DoesNotExist:
            return Response({'error': 'Review not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = CompanyReviewSerializer(review, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





