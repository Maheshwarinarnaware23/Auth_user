# accounts/urls.py
from django.urls import path
from . import views
from .views import UploadDocumentView

app_name = "accounts"
urlpatterns = [
    path("register/", views.register_view, name="register"),
    path("activate/", views.activate_view, name="activate"),
    path("resend-activation/", views.resend_activation_view, name="resend_activation"),
    path("login/", views.login_view, name="login"),
    path("forgot-password/", views.ForgotPasswordView.as_view(), name="forgot_password"),
    path("reset-password/", views.ResetPasswordView.as_view(), name="reset_password"),
    path("home/", views.home_view, name="home"),
    path("logout/", views.logout_view, name="logout"),
    path('upload/', UploadDocumentView.as_view(), name='upload_document'),

]
