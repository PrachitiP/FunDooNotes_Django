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





