from django.db import models
from django.contrib.auth.models import User


class UserDetails(models.Model):
    username = models.CharField(max_length=20)
    email = models.CharField(max_length=20)
    password = models.CharField(max_length=20)
    confirm_password = models.CharField(max_length=20)