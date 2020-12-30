from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from .serializer import RegisterationFormSerializer

class registerForm(GenericAPIView):
    serializer_class = RegisterationFormSerializer

    def post(self, request):
        try:
            userName = request.data['username']
            email = request.data['email']
            password = request.data['password']
            confirm_password = request.data['confirm_password']

            if userName == "" or email == "" or password == "":
                return Response("You can not put empty fields", status=status.HTTP_406_NOT_ACCEPTABLE)
            if password == confirm_password:
                try:
                    validate_email(email)
                    user = User.objects.create_user(
                        username=userName, email=email, password=password)
                    user.is_active = False
                    user.save()
