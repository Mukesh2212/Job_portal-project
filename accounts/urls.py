from django.urls import path
from .views import *
from accounts import views 



urlpatterns = [
    path('register/', RegistrationView.as_view(), name='register'),
    path('login11/', login_view, name='login'),
    path('employer_signup/', EmployerSignUpView.as_view(), name='employer-signup'),
    path('employer_login/', EmployerLoginView.as_view(), name='employer-login'),
    path('myprofile/', MyProfileListCreateView.as_view(), name='profile-list-create'),
    path('myprofile/<int:pk>/', UpdateMyProfileView.as_view(), name='update-user-profile'),
    path('edit-myprofile/<int:register_id>/', MyProfileUpdateView.as_view(), name='edit-myprofile'),
    path('courses/', CourseList.as_view(), name='course-list'),
    path('courses/<int:pk>/', CourseDetail.as_view(), name='course-detail'),
    path('profile-highlighters/', ProfileHighlighterList.as_view(), name='profile-highlighter-list'),
    path('profile-highlighters/<int:pk>/', ProfileHighlighterDetail.as_view(), name='profile-highlighter-detail'),
    path('boostnow-profile-forms/', BoostnowProfileFormList.as_view(), name='boostnow-profile-form-list'),
    path('boostnow-profile-forms/<int:pk>/', BoostnowProfileFormDetail.as_view(), name='boostnow-profile-form-detail'),
    path('advanced-job-searches/', AdvancedJobSearchList.as_view(), name='advanced-job-search-list'),
    path('advanced-job-searches/<int:pk>/', AdvancedJobSearchDetail.as_view(), name='advanced-job-search-detail'),
    
    path('jobs/', JobListCreateAPIView.as_view(), name='job-list-create'),
    path('jobs/<int:pk>/', JobDetailAPIView.as_view(), name='job-detail'),
    
    path('blogs/', BlogListCreateAPIView.as_view(), name='blog-list-create'),
    path('blogs/<int:pk>/', BlogDetailAPIView.as_view(), name='blog-detail'),
    
    path('contacts/', ContactDetailView.as_view(), name='contacts'),
    path('reviewjobs/', ReviewOnJObsViews.as_view(), name='reviewjobs'),
    
    path('sendemailresetpassword/', SendPasswordResetEmailView.as_view(), name='sendemailresetpassword'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    

    ###########  forget password solved by mukesh ################
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('api/reset-password-confirm/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),



    path('sendemailresetpasswordemployeer/', SendPasswordResetEmailEmployeerView.as_view(), name='sendemailresetpasswordemployeer'),
    path('reset-passwordemployeer/<uid>/<token>/', UserPasswordResetEmployeerView.as_view(), name='reset-passwordemploeer'),
    path('edit-employermyprofile/<int:employer_id>/', EmployerProfileUpdateView.as_view(), name='edit-employermyprofile'),
    
    
    path('reviews/', ReviewListCreateAPIView.as_view(), name='review-list-create'),
    path('reviews/<int:pk>/', ReviewRetrieveUpdateDestroyAPIView.as_view(), name='review-detail'),
    
    path('book-demo/', BookDemoListCreateAPIView.as_view(), name='book-demo-list-create'),
    path('book-demo/<int:pk>/', BookDemoRetrieveUpdateDestroyAPIView.as_view(), name='book-demo-detail'),
    
    path('employersregistration/', EmployerRegistrationAPIView.as_view(), name='employer-registration'),

    path('checkOTP/', checkOTP ),
    path('sendOTP/',otpGeneration),
    
    
    path('send-otp/', SendOTP.as_view(), name='send_otp'),
    path('verify-otp/', VerifyOTP.as_view(), name='verify_otp'),
    
]

