from django.contrib.auth.models import User
from rest_framework import serializers
from .models import UserDetails

class UserDeatilsSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'password']
