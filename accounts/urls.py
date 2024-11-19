from django.urls import path
from .views import *
from accounts import views 
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)



urlpatterns = [
    path('register/', RegistrationView.as_view(), name='register'),
    path('login11/', LoginView.as_view(), name='login'),
    path('logout/<int:id>/', LogoutAPIView.as_view(), name='logout'),
    path('employer_signup/', EmployerSignUpView.as_view(), name='employer-signup'),
    path('employer_login/', EmployerLoginView.as_view(), name='employer-login'),
    path('myprofile/', MyProfileListCreateView.as_view(), name='profile-list-create'),
    path('myprofile/<int:pk>/', UpdateMyProfileView.as_view(), name='update-user-profile'),
    path('edit-myprofile/<int:register_id>/', MyProfileUpdateView.as_view(), name='edit-myprofile'),
    path('myempprofile/', EmpMyprofleApiview.as_view(), name='profile-create'),
    path('myempprofile/<int:pk>/', EmpMyprofleApiview.as_view(), name='profile-detail'),  # To fetch a specific profile
    path('jobseditsendotp/',EmpMyProfileSendOtpApiView.as_view(), name='jobseditsendotp'),
    path('jobseditverifyotp/',EmpMyprofleVerifyotpApiview.as_view(), name='jobseditverifyotp'),
    path('courses/', CourseList.as_view(), name='course-list'),
    path('courses/<int:pk>/', CourseDetail.as_view(), name='course-detail'),
    path('profile-highlighters/', ProfileHighlighterList.as_view(), name='profile-highlighter-list'),
    path('profile-highlighters/<int:pk>/', ProfileHighlighterDetail.as_view(), name='profile-highlighter-detail'),
    path('boostnow-profile-forms/', BoostnowProfileFormList.as_view(), name='boostnow-profile-form-list'),
    path('boostnow-profile-forms/<int:pk>/', BoostnowProfileFormDetail.as_view(), name='boostnow-profile-form-detail'),
    path('advanced-job-searches/', AdvancedJobSearchList.as_view(), name='advanced-job-search-list'),
    path('advanced-job-searches/<int:pk>/', AdvancedJobSearchDetail.as_view(), name='advanced-job-search-detail'),



    path('advanced-job/', AdvancedsJobSearchAPIView.as_view(), name='advanced-job-search-list'),
    # path('advanced-job-searches/<int:pk>/', AdvancedsJobSearchAPIView.as_view(), name='advanced-job-search-detail'),
    
    
    path('jobs/', JobListCreateAPIView.as_view(), name='job-list-create'),
    path('jobs/<int:id>/', JobListCreateAPIView.as_view(), name='job-list-create'),
    # path('jobs/<int:pk>/', JobDetailAPIView.as_view(), name='job-detail'),
    # path('jobapply/', JobApplyView.as_view(), name='jobapply'), # fetch job apply data jobseeker
    path('jobapply/<int:id>/', JobApplyView.as_view(), name='jobapply'),
    path('applyjobempprofiledashboard/', JobEmployProfiledashobard.as_view(), name='jobprofiledashboard'),
    path('applyjobempprofiledashboard/<int:id>/', JobEmployProfiledashobard.as_view(), name='jobprofiledashboard'),
    
    
    path('blogs/', BlogListCreateAPIView.as_view(), name='blog-list-create'),
    path('blogs/<int:pk>/', BlogDetailAPIView.as_view(), name='blog-detail'),
    
    path('contacts/', ContactDetailView.as_view(), name='contacts'),
    path('contacts/<int:id>/', ContactDetailView.as_view(), name='contacts'),
    path('reviewjobs/', ReviewOnJObsViews.as_view(), name='reviewjobs'),
    
    path('sendemailresetpassword/', SendPasswordResetEmailView.as_view(), name='sendemailresetpassword'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    

    ###########  forget password solved by mukesh ################
    path('forgot-password/', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('confirm-password/', views.PasswordResetConfirmView.as_view(), name='confirm-password'), # use for local server 
    # path('PasswordChange/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'), # use for live server 


    path('sendemailresetpasswordemployeer/', SendPasswordResetEmailEmployeerView.as_view(), name='sendemailresetpasswordemployeer'),
    path('reset-passwordemployeer/<uid>/<token>/', UserPasswordResetEmployeerView.as_view(), name='reset-passwordemploeer'),
    path('edit-employermyprofile/<int:employer_id>/', EmployerProfileUpdateView.as_view(), name='edit-employermyprofile'),
    
    
    path('reviews/', ReviewListCreateAPIView.as_view(), name='review-list-create'),
    path('reviews/<int:pk>/', ReviewRetrieveUpdateDestroyAPIView.as_view(), name='review-detail'),
    
    path('book-demo/', BookDemoListCreateAPIView.as_view(), name='book-demo-list-create'),
    path('book-demo/<int:pk>/', BookDemoRetrieveUpdateDestroyAPIView.as_view(), name='book-demo-detail'),
    
    path('employersregistration/', EmployerRegistrationAPIView.as_view(), name='employer-registration'),
    path('employersregistration/<int:id>/', EmployerRegistrationAPIView.as_view(), name='employer-registration'),
    path('employregisteredprofile/', EmployerRegisteredProfileAPIView.as_view(), name='employer-registered-profile'),
    path('employregisteredprofile/<int:id>/', EmployerRegisteredProfileAPIView.as_view(), name='employer-registered-profile'),
    # path('loginemailusername/', LoginEmialAPIView.as_view(), name='login'),
    path('loginemailusername/', LoginEmialAPIView.as_view(), name='loginemailusername'),
    # path('loginemailusername/', LoginAPIViewEmail.as_view(), name='loginemailusername'),
    path('updatepasswordemps/', ChangePasswordView.as_view(), name='change-password'),
    path('restpwdemployer/', RstPwdEmployerAPIView.as_view(), name='restpwdemployer'),
    path('employerprofileregistration/', EmployerRegisteredProfileAPIView.as_view(), name='employer-profileregistration'),
    path('employerprofileregistration/<int:id>/', EmployerRegisteredProfileAPIView.as_view(), name='employer-profileregistration'),

    
    # path('restpwdemployerconfirm/<uidb64>/<token>/', PasswordResetConfirmAPIView.as_view(), name='password_reset_confirm'),
    # path('accounts/otp-password-reset/<uidb64>/', OTPPasswordResetAPIView.as_view(), name='otp_password_reset'),
    path('restpwdemployerconfirm/', OTPPasswordResetAPIView.as_view(), name='restpwdemployerconfirm'),
    # path('restpwdemployerconfirm/<uidb64>/', OTPPasswordResetAPIView.as_view(), name='restpwdemployerconfirm'),
    path('empreditsendotp/', EmployerSendOTPAPIView.as_view(), name='empreditsendotp'),
    path('empreditverifyotp/', EmployerVerifyOTPAPIView.as_view(), name='empitverifyotp'),

    path('checkOTP/', checkOTP ),
    path('sendOTP/',otpGeneration),
    
    
    path('email-send-otp/', SendOTP.as_view(), name='send_otp'),  ## for email otp send 
    path('email-verify-otp/', VerifyOTP.as_view(), name='verify_otp'),  ## for email otp send 


    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('jobseekerchat/', ChatView.as_view(), name='jobseekerchat'),
    path('jobrolematch/<int:id>/',JobRoleMatchAPIView.as_view(), name='jobrolematch'),
    path('companyreview/', CompanyReviewAPIView.as_view(), name='companyreview'),
    path('companyreview/<int:id>/', CompanyReviewAPIView.as_view(), name='companyreview'),
    
]

