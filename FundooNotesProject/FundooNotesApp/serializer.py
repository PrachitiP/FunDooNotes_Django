from rest_framework import serializers
from .models import UserDetails
from django.contrib.auth.models import User

class RegisterationFormSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDetails
        fields = ['username','email','password','confirm_password']

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)
    class Meta:
        model = User
        fields = ['token']
