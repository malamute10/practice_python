from django.contrib.auth.models import User
from rest_framework import generics

from users.secializers import RegisterSerializer


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
