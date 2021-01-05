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
       
class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255, min_length=3, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account is not activated yet')

        return {
            'username': user.username, 'email': user.email,
        }
class ResetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)

    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email', '')
        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                raise serializers.ValidationError("This email id is not active")
        except User.DoesNotExist:
            raise serializers.ValidationError("This email is not registerd")

        return attrs


class NewPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6)
    NewPassword=serializers.CharField(max_length=68, min_length=6)


    class Meta:
        model = User
        fields = ['password', 'NewPassword']

    def validate(self, attrs):
        password = attrs.get('password', '')
        NewPassword =attrs.get('NewPassword', '')

        if password != NewPassword:
            raise serializers.ValidationError("Password not matched!!")

        return attrs
