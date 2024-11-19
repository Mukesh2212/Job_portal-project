# registration/serializers.py
from rest_framework import serializers
from .models import *
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import requests
from django.core.mail import send_mail 
from django.contrib.auth.models import User 
from django.contrib.auth import authenticate 



# class CustomUserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = CustomUser
#         fields = ['email', 'full_name', 'password', 'terms_and_conditions']
#         extra_kwargs = {
#             'password': {'write_only': True}  # Ensure password is write-only
#         }

#     def create(self, validated_data):
#         # Create a new user instance with the provided data
#         user = CustomUser(
#             email=validated_data['email'],
#             full_name=validated_data['full_name'],
#             terms_and_conditions=validated_data.get('terms_and_conditions', False)
#         )
#         user.set_password(validated_data['password'])  # Hash the password
#         user.save()
#         return user

#     def validate_email(self, value):
#         if CustomUser.objects.filter(email=value).exists():
#             raise serializers.ValidationError("Email is already in use.")
#         return value 












class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'full_name', 'password', 'terms_and_conditions','otp_register']
        extra_kwargs = {
            'password': {'write_only': True}  # Ensure password is write-only
        }

    def create(self, validated_data):
        # Create a new user instance with the provided data
        user = CustomUser(
            email=validated_data['email'],
            full_name=validated_data['full_name'],
            terms_and_conditions=validated_data.get('terms_and_conditions', False)
        )
        user.password = validated_data['password']  # Store the password in plain text
        print(user.password,'##################################')
        user.save()

        # Save the email and password to the backup model
        backup = AccountUserOtp(
            email=validated_data['email'],
            registeredpassword=validated_data['password']  # Store as plaintext (not recommended)
        )
        backup.save()

        return user

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already in use.")
        return value





class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value




class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    class Meta:
        model = CustomUser
        fields = ['email', 'password']

    # def validate(self, attrs):
    #     email = attrs.get('email')
    #     password = attrs.get('password')

    #     # Authenticate user
    #     user = authenticate(email=email, password=password)
    #     if user is None:
    #         raise serializers.ValidationError("Invalid email or password.")
        
    #     attrs['user'] = user
    #     return attrs




class EmployerSignUpSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = Employer
        fields = ('id', 'username', 'email', 'password', 'confirm_password', 'terms_and_conditions')
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Password and Confirm Password must match")
        return data

    def create(self, validated_data):
        # Remove 'confirm_password' from 'validated_data'
        validated_data.pop('confirm_password', None)

        # Manually set the password field
        password = validated_data.pop('password')
        employer = Employer(**validated_data)
        employer.password = password  # Set the password field directly
        employer.save()
        return employer



######################### Reset password for Register user ############################
# url = "https://hourmailer.p.rapidapi.com/send"
url = "https://mail-sender-api1.p.rapidapi.com/"
# url =  "https://demo-project67614.p.rapidapi.com/catalog/product"


class SendPasswordResetEmailSerializer(serializers.Serializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    fields = ['email']


  def validate(self, attrs):
    email = attrs.get('email')
    if CustomUser.objects.filter(email=email).exists():
      user = CustomUser.objects.get(email = email)
      uid = urlsafe_base64_encode(force_bytes(user.id))
      print('Encoded UID', uid)
      token = PasswordResetTokenGenerator().make_token(user)
      print('Password Reset Token', token)
      # link = 'https://jobadmin.hola9.com/PasswordChange/'+uid+'/'+token
      link = 'http://127.0.0.1:8000/accounts/reset-password/'+uid+'/'+token

       
      # payload = {
      #     "toAddress":email,
      #     "title": "hola9 link",
      #     "message": link
      #     }
      payload = {
  "sendto": email,
  "ishtml": "false",
  "title": "hola9 link",
  "body": link
}
 
      headers = {
          "content-type": "application/json",
          # "X-RapidAPI-Key": "6ce72a7a7dmsh214ebefb254c11ap1ec502jsn5a1bfe3fd20a",
          # "X-RapidAPI-Host": "hourmailer.p.rapidapi.com"
          "X-RapidAPI-Key": "1606ead861msh1b5bcc178cc7894p163e10jsnc0a88a24283b",
          "X-RapidAPI-Host": "mail-sender-api1.p.rapidapi.com"
          # "X-RapidAPI-Key": "90e92901c8msh767dd29f7b4a7e3p147abajsncd8fab11a708",
          # "X-RapidAPI-Host": "demo-project67614.p.rapidapi.com"
        }


      response = requests.request("POST", url, json=payload, headers=headers)
      print('Password Reset Link', link)
      # Send EMail
      body = 'Click Following Link to Reset Your Password '+link
      data = {
        'subject':'Reset Your Password',
        'body':body,
        'to_email':user.email
      }
      # Util.send_email(data)
      return attrs
    else:
      raise serializers.ValidationError('You are not a Registered User')
  
class UserPasswordResetSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']


  def validate(self, attrs):
    try:
      password = attrs.get('password')
      password2 = attrs.get('password2')
      uid = self.context.get('uid')
      token = self.context.get('token')
      if password != password2:
        raise serializers.ValidationError("Password and Confirm Password doesn't match")
      id = smart_str(urlsafe_base64_decode(uid))
      user = CustomUser.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise serializers.ValidationError('Token is not Valid or Expired')
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
      PasswordResetTokenGenerator().check_token(user, token)
      raise serializers.ValidationError('Token is not Valid or Expired')
  
class MyProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyProfile
        fields = '__all__'



class CourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = '__all__'


class ProfileHighlighterSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProfileHighlighter
        fields = '__all__'

class BoostnowProfileFormSerializer(serializers.ModelSerializer):
    class Meta:
        model = BoostnowProfileForm
        fields = '__all__'

class AdvancedJobSearchSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdvancedJobSearch
        fields = '__all__'

class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = '__all__'
        
class BlogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blog
        fields = '__all__'

class ContactDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model=ContactDetails
        fields='__all__'
        
class ReviewOnJobsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReviewOnJobs
        fields='__all__'

########################### reset password for Employer user ###############################
# url = "https://hourmailer.p.rapidapi.com/send"
url = "https://mail-sender-api1.p.rapidapi.com/"
# url =  "https://demo-project67614.p.rapidapi.com/catalog/product"


class SendPasswordResetEmailEmployeerSerializer(serializers.Serializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    fields = ['email']


  def validate(self, attrs):
    email = attrs.get('email')
    if CustomUser.objects.filter(email=email).exists():
      user = CustomUser.objects.get(email = email)
      uid = urlsafe_base64_encode(force_bytes(user.id))
      print('Encoded UID', uid)
      token = PasswordResetTokenGenerator().make_token(user)
      print('Password Reset Token', token)
      link = 'https://jobs.hola9.info/PasswordChange2/'+uid+'/'+token
       
      # payload = {
      #     "toAddress":email,
      #     "title": "hola9 link",
      #     "message": link
      #     }
      payload = {
  "sendto": email,
  "ishtml": "false",
  "title": "hola9 link",
  "body": link
}
 
      headers = {
          "content-type": "application/json",
          # "X-RapidAPI-Key": "6ce72a7a7dmsh214ebefb254c11ap1ec502jsn5a1bfe3fd20a",
          # "X-RapidAPI-Host": "hourmailer.p.rapidapi.com"
          "X-RapidAPI-Key": "1606ead861msh1b5bcc178cc7894p163e10jsnc0a88a24283b",
          "X-RapidAPI-Host": "mail-sender-api1.p.rapidapi.com"
          # "X-RapidAPI-Key": "90e92901c8msh767dd29f7b4a7e3p147abajsncd8fab11a708",
          # "X-RapidAPI-Host": "demo-project67614.p.rapidapi.com"
        }


      response = requests.request("POST", url, json=payload, headers=headers)
      print('Password Reset Link', link)
      # Send EMail
      body = 'Click Following Link to Reset Your Password '+link
      data = {
        'subject':'Reset Your Password',
        'body':body,
        'to_email':user.email
      }
      # Util.send_email(data)
      return attrs
    else:
      raise serializers.ValidationError('You are not a Registered User')

class UserPasswordResetEmployeerSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']


  def validate(self, attrs):
    try:
      password = attrs.get('password')
      password2 = attrs.get('password2')
      uid = self.context.get('uid')
      token = self.context.get('token')
      if password != password2:
        raise serializers.ValidationError("Password and Confirm Password doesn't match")
      id = smart_str(urlsafe_base64_decode(uid))
      user = CustomUser.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise serializers.ValidationError('Token is not Valid or Expired')
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
      PasswordResetTokenGenerator().check_token(user, token)
      raise serializers.ValidationError('Token is not Valid or Expired')    
    

class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = '__all__'
        
class BookDemoSerializer(serializers.ModelSerializer):
    class Meta:
        model = BookDemo
        fields = ['id', 'full_name', 'company_name', 'business_name', 'number_of_employees', 'mobile_number']
        
        
class EmployerRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployerRegistration
        fields = '__all__'   




class EmployerRegistrationSerializerProfile(serializers.ModelSerializer):
    class Meta:
        model = EmployerRegistrationProfile
        fields = '__all__'  


class OTPSerializer(serializers.ModelSerializer):
    class Meta:
        model = OTP
        fields = ('email', 'otp_code')




############## Update employer registration  password 


# class ChangePasswordSerializer(serializers.Serializer):
#     new_password = serializers.CharField(required=True, write_only=True)
#     confirm_new_password = serializers.CharField(required=True, write_only=True)

#     def validate(self, data):
#         new_password = data.get('new_password')
#         confirm_new_password = data.get('confirm_new_password')
#         if new_password != confirm_new_password:
#             raise serializers.ValidationError("New password and confirm password do not match.")
#         if len(new_password) < 8:
#             raise serializers.ValidationError("New password must be at least 8 characters long.")        
#         return data

#     def save(self,request):
#         user = EmployerRegistration.objects.get(email=request.data['email'])
#         try:
#             employer = user.email
#         except EmployerRegistration.DoesNotExist:
#             raise serializers.ValidationError("Employer registration not found for this user.")
#         if not user.is_authenticated:
#             raise serializers.ValidationError("User must be authenticated to change password.")
#         new_password = self.validated_data['new_password']
#         user.set_password(new_password)
#         user.save()
#         return employer 
    




class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    confirm_new_password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        new_password = data.get('new_password')
        confirm_new_password = data.get('confirm_new_password')
        if new_password != confirm_new_password:
            raise serializers.ValidationError("New password and confirm password do not match.")
        if len(new_password) < 8:
            raise serializers.ValidationError("New password must be at least 8 characters long.")
        return data

    def save(self, request):
        user = EmployerRegistration.objects.get(email=request.data['email'])
        print(user,'************%%%%%%%%%%%%%%%%%%%%%%%%%%%%')
        if not user.is_authenticated:
            raise serializers.ValidationError("User must be authenticated to change password.")
        current_password = self.validated_data['current_password']
        print(current_password,'**************************')
        # Check if the current password is correct
        if not authenticate(username=user.email, password=current_password):
            raise serializers.ValidationError("Current password is incorrect.")
        new_password = self.validated_data['new_password']
        user.set_password(new_password)
        user.save()
        return user.email  # Return the email or any other relevant information


###########  reset password of employer registration 

class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        users = EmployeeRegistrationOtp.objects.filter(email=value)
        if not users.exists():
            raise serializers.ValidationError("User with this email does not exist.")
        
        # Optionally, return a specific user or handle accordingly
        return value
    




class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_new_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data


class OTPPasswordResetSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_new_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data
    


class CustomforgetPasswordSerializer(serializers.Serializer):
    # otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_new_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data


class EmpMyProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmpMyProfile
        fields = '__all__'


# class LoginSerializer(serializers.Serializer):
#    class Meta:
#       model = CustomUser 
#       fields = ['email','password']
    


class EmailLoginSerializer(serializers.Serializer):
   class Meta:
      model = EmailUsername
      fields = "__all__" 
   


class LoginSerializerEmail(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    class Meta:
       moedel = CustomUser
       fields = ['username','password']
	





# class JobEmployeeDashboardSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = JobEmployeeDashboard
#         fields = '__all__'





class JobEmployeeProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobEmployeeProfile
        fields = '__all__'  # or specify fields explicitly





class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatMessage
        fields = ['id', 'sender_user', 'write_message', 'timestamp','link']


class CompanyReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyReview
        fields = '__all__'