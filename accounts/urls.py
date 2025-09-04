# accounts/urls.py
from django.urls import path
from . import views

app_name = "accounts"
urlpatterns = [
    path("register/", views.register_view, name="register"),
    path("activate/", views.activate_view, name="activate"),
    path("resend-activation/", views.resend_activation_view, name="resend_activation"),
    path("login/", views.login_view, name="login"),
]