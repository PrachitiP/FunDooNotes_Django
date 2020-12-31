from django.conf.urls import url
from django.urls import path,include
from rest_framework import routers
from rest_framework_swagger.views import get_swagger_view
from .import views
from .views import registerform, EmailVerification
from rest_framework import permissions


urlpatterns=[
 
     path('reg/',registerform.as_view()),
     path('email-verify/',EmailVerification.as_view()),
]
