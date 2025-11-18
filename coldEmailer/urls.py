from django.contrib import admin
from django.urls import path , include
from . import views
from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('cold-emailer/',  include(
        [
            path('signup/', views.SignUpVIew.as_view(), name="signup"),
            path('send-email/', views.sendEmail.as_view(), name="send-email"),
            path("google/login/",views.GoogleLogin.as_view(), name="google-login"),
            path("google/callback/", views.google_callback, name="google-callback"),

        ]
    )),
]