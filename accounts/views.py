from django.contrib.auth.decorators import login_required
from django.shortcuts import render

# Create your views here.
# accounts/views.py
# accounts/views.py
import logging
import re
import hashlib
from datetime import timedelta
from django.shortcuts import render, redirect
from django.utils import timezone
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.views import View
from django.views.decorators.http import require_http_methods
from django.urls import reverse
from .forms import RegistrationForm
from .models import User, ActivationToken, Category
from .utils import create_activation, hash_token, send_activation_email, send_password_reset_email, \
    create_password_reset
import secrets
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger("accounts.registration")

# Helper: create captcha (simple arithmetic)
def _generate_captcha(request):
    import random
    a = random.randint(1, 9); b = random.randint(1, 9)
    request.session['captcha_answer'] = a + b
    request.session['captcha_ts'] = timezone.now().timestamp()
    return f"{a} + {b} = ?"

@require_http_methods(["GET","POST"])
def register_view(request):
    if request.method == "GET":
        form = RegistrationForm()
        captcha_q = _generate_captcha(request)
        return render(request, "accounts/registration.html", {"form": form, "captcha_q": captcha_q})
    form = RegistrationForm(request.POST)
    # server-side captcha check
    posted_captcha = request.POST.get("captcha", "").strip()
    expected = str(request.session.get("captcha_answer", ""))
    if posted_captcha != expected:
        form.add_error("captcha", "Captcha is incorrect.")
    if form.is_valid():
        data = form.cleaned_data
        # create user (inactive)
        user = User.objects.create(
            email=data["email"],
            category=data["category"],
            first_name="",
            last_name="",
            is_active=False
        )
        user.set_password(data["password"])
        user.save()
        # create activation token and send email
        token, act_obj = create_activation(user)
        send_activation_email(request, user, token)
        logger.info("Registration success for %s category=%s", user.email, user.category)
        return render(request, "accounts/activation_result.html", {"message": "Registration successful. Check your Gmail for activation link (expires in 24 hours)."})
    else:
        captcha_q = _generate_captcha(request)
        logger.info("Registration failed: %s", form.errors.as_json())
        return render(request, "accounts/registration.html", {"form": form, "captcha_q": captcha_q})
@require_http_methods(["GET"])
def activate_view(request):
    token = request.GET.get("token")
    email = request.GET.get("email")
    cat_id = request.GET.get("category")
    if not token or not email or not cat_id:
        return render(request, "accounts/activation_result.html", {"message":"Invalid activation link."})
    token_hash = hash_token(token)
    try:
        at = ActivationToken.objects.get(token_hash=token_hash, used=False)
    except ActivationToken.DoesNotExist:
        return render(request, "accounts/activation_result.html", {"message":"Invalid or already used activation link."})
    if at.expires_at < timezone.now():
        return render(request, "accounts/activation_result.html", {"message":"Activation link expired. Please request a new one."})
    # activate user
    user = at.user
    user.is_active = True
    user.save()
    at.mark_used()
    return render(request, "accounts/activation_result.html", {"message":"Account activated. You can now log in."})

@require_http_methods(["GET","POST"])
def resend_activation_view(request):
    if request.method == "GET":
        return render(request, "accounts/activation_result.html", {"message":"Send POST request with email and category id to resend activation."})
    email = request.POST.get("email", "").lower()
    cat_id = request.POST.get("category")
    try:
        cat = Category.objects.get(id=cat_id)
        user = User.objects.get(email__iexact=email, category=cat)
    except (Category.DoesNotExist, User.DoesNotExist):
        return render(request, "accounts/activation_result.html", {"message":"No inactive account found for this email and category."})
    if user.is_active:
        return render(request, "accounts/activation_result.html", {"message":"Account is already active. Please login."})
    token, act_obj = create_activation(user)
    send_activation_email(request, user, token)
    return render(request, "accounts/activation_result.html", {"message":"New activation link sent to your email."})

# Template login that sets JWT cookies (HttpOnly)
@require_http_methods(["GET", "POST"])
def login_view(request):
    if request.method == "GET":
        return render(request, "accounts/login.html")

    email = request.POST.get("email", "").lower()
    password = request.POST.get("password", "")

    # authenticate user
    user = authenticate(request, username=email, password=password)
    if user is None:
        return render(request, "accounts/login.html", {"error": "Invalid credentials"})
    if not user.is_active:
        return render(request, "accounts/login.html", {"error": "Account inactive. Activate via email."})

    # ✅ mark user logged in (session-based auth)
    login(request, user)

    # still generate JWT if you want APIs later
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)

    response = redirect("accounts:home")
    response.set_cookie(
        "access", access_token,
        httponly=True, max_age=15*60,
        secure=not settings.DEBUG, samesite="Lax"
    )
    response.set_cookie(
        "refresh", str(refresh),
        httponly=True, max_age=7*24*3600,
        secure=not settings.DEBUG, samesite="Lax"
    )
    return response

class ForgotPasswordView(View):
    def get(self, request):
        captcha_q = _generate_captcha(request)
        return render(request, "accounts/forgot_password.html", {"captcha_q": captcha_q})

    def post(self, request):
        email = request.POST.get("email", "").strip().lower()
        posted_captcha = request.POST.get("captcha", "").strip()
        expected = str(request.session.get("captcha_answer", ""))
        # Protect against enumeration: always show neutral success message
        neutral_success_msg = "If an account exists for the provided email, a password reset link has been sent."

        # Validate captcha
        if posted_captcha != expected:
            messages.error(request, "Captcha is incorrect.")
            return redirect("accounts:forgot_password")

        # Try to fetch user (do not reveal existence)
        try:
            user = User.objects.get(email__iexact=email, is_active=True)
        except User.DoesNotExist:
            # Still show neutral message — prevents user enumeration
            messages.success(request, neutral_success_msg)
            return redirect("accounts:forgot_password")

        # Create token and send email
        token, _ = create_password_reset(user)
        send_password_reset_email(request, user, token)
        messages.success(request, neutral_success_msg)
        return redirect("accounts:forgot_password")

class ResetPasswordView(View):
    def get(self, request):
        token = request.GET.get("token", "")
        email = request.GET.get("email", "").strip().lower()
        if not token or not email:
            messages.error(request, "Invalid password reset link.")
            return redirect("accounts:forgot_password")

        from .models import PasswordResetToken
        try:
            user = User.objects.get(email__iexact=email)
            token_obj = PasswordResetToken.objects.get(user=user, token_hash=hash_token(token), used=False)
        except (User.DoesNotExist, PasswordResetToken.DoesNotExist):
            messages.error(request, "Invalid or expired password reset link.")
            return redirect("accounts:forgot_password")

        if not token_obj.is_valid():
            messages.error(request, "This password reset link has expired or already been used.")
            return redirect("accounts:forgot_password")

        # Show reset form
        return render(request, "accounts/reset_password.html", {"email": email, "token": token})

    def post(self, request):
        password = request.POST.get("password", "")
        confirm_password = request.POST.get("confirm_password", "")
        email = request.POST.get("email", "").strip().lower()
        token = request.POST.get("token", "")

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect(request.path + f"?token={token}&email={email}")

        from .models import PasswordResetToken
        try:
            user = User.objects.get(email__iexact=email)
            token_obj = PasswordResetToken.objects.get(user=user, token_hash=hash_token(token), used=False)
        except (User.DoesNotExist, PasswordResetToken.DoesNotExist):
            messages.error(request, "Invalid request.")
            return redirect("accounts:forgot_password")

        if not token_obj.is_valid():
            messages.error(request, "This password reset link has expired or already been used.")
            return redirect("accounts:forgot_password")

        # Validate password server-side (same regex as registration)
        PASS_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#\$%\^&\*]).{8,}$')
        if not PASS_RE.match(password):
            messages.error(request, "Password must be min 8 characters with uppercase, lowercase, digit and special char.")
            return redirect(request.path + f"?token={token}&email={email}")

        # Update password and invalidate token
        user.set_password(password)
        user.save()
        token_obj.mark_used()

        messages.success(request, "Password has been reset. You can now login.")
        return redirect("accounts:login")

@login_required
def home_view(request):
    return render(request, "accounts/home.html", {"user": request.user})

def logout_view(request):
    logout(request)  # clears the session
    return redirect("accounts:login")  # redirect to login after logout