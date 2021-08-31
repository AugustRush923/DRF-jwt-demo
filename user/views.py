from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .authentication import JwtHeaderAuthentication, JwtQueryParamAuthentication
from utils.jwt_auth import create_token


# Create your views here.


class LoginAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if username != 'august' and password != "123456":
            return Response({'status': "False"})
        token = create_token({"username": username, "password": password})
        return Response({"status": "True", "token": token})


class OrderAPIView(APIView):
    authentication_classes = [JwtQueryParamAuthentication]

    def get(self, request):
        return Response("成功")


class CenterAPIView(APIView):
    authentication_classes = [JwtHeaderAuthentication]

    def get(self, request):
        return Response("成功")


login = LoginAPIView.as_view()
order = OrderAPIView.as_view()
center = CenterAPIView.as_view()
