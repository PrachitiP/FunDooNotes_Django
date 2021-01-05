from email.message import EmailMessage
from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import viewsets, status, generics
from rest_framework.response import Response
from rest_framework_jwt.serializers import jwt_payload_handler
from rest_framework_simplejwt.tokens import RefreshToken
from . import serializer
from .models import UserDetails
from .serializer import UserDeatilsSerializer, EmailVerificationSerializer
from django.core.mail import send_mail
from django.conf import settings
from .token import token_activation
from .utils import Util
import views
import logging
import jwt

class registerform(generics.GenericAPIView):
    """
        A Registration class for registration of users with information

    """
    queryset = UserDetails.objects.all()
    serializer_class = UserDeatilsSerializer


    def post(self, request):
        """
            Defined post method which register users with valid email and oher inputs.
            It checks the authenticity of the email by sending a activation link for user to the respective email
             
        """
        try:
            user = request.data
            serializer = self.serializer_class(data=user)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            user_data = serializer.data
            user = User.objects.get(email=user_data['email'])
            user.is_active=False
            payload = jwt_payload_handler(user)
            token = jwt.encode(payload, settings.SECRET_KEY).decode('UTF-8')
            current_site = get_current_site(request).domain
            relativeLink = '/email-verify/'
            absurl = 'http://' + current_site + relativeLink + "?token=" + str(token)
            email_body = 'Hi ' + user.username +  ' Use the link below to verify your email \n' + absurl
            data = {'email_body': email_body, 'to_email': user.email,  'email_subject': 'Verify your email'}
            Util.send_email(data)
            logging.debug('validated data: {}'.format(serializer.data))
            return Response(user_data, status=status.HTTP_201_CREATED)

        except Exception:
           return Response(serializer.errors)
    
    class EmailVerification(generics.GenericAPIView):
    """
       Created class to verify the user email which used for verification
    """
    
    serializer_class = EmailVerificationSerializer
    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        """
                Created method for verifying email and successfully registering the user
                
        """
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_active:

                user.is_active = True
                user.save()
            logging.debug('user activation successful')
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            logging.exception('Exception due to expired signature')
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            logging.exception('Exception due to error in decoding')
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        
class Login(generics.GenericAPIView):
    """
            A Login class which inherited from inbuilt django GenericAPIView class
            It helps to login the user with the right credentials
    """
    serializer_class = LoginSerializer

    def post(self, request):
        """
                      Declared post method to insert login details of user
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'], password=user_data['password'])
        payload = jwt_payload_handler(user)
        token = jwt.encode(payload, settings.SECRET_KEY)
        user_data['token'] = token
        request.session['is_logged'] = True
        return Response(user_data, status=status.HTTP_200_OK)


class ResetPassword(generics.GenericAPIView):
    """
        Created class for sending request to email for password reset
    """
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        """
              Created method to send link to email for password reset
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        current_site = get_current_site(request).domain
        reverseLink = '/new-password/'
        payload = jwt_payload_handler(user)
        token = jwt.encode(payload, settings.SECRET_KEY).decode('UTF-8')

        reset_link = ('http://' + current_site + reverseLink + '?token=' + str(token))
        email_body = "hii \n" + user.username + "Use this link to reset password: \n" + reset_link
        data = {'email_body': email_body, 'to_email': user.email, 'email_subject': "Reset password Link"}
        Util.send_email(data)
        return Response(user_data, status=status.HTTP_200_OK)


class NewPassword(generics.GenericAPIView):
    """
       Created class to set new password the respective user
    """

    serializer_class = NewPasswordSerializer
    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description',type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def put(self, request):
        """
            Created a method to set a new password for existing user
        """
        token = request.GET.get('token')
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data

        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            user.password = user_data['password']
            user.save()
            return Response({'email': 'New password is created'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Link is Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid Token'}, status=status.HTTP_400_BAD_REQUEST)




