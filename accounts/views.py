from django.shortcuts import render

# Create your views here.
# accounts/views.py
# accounts/views.py
import logging
import hashlib
from datetime import timedelta
from django.shortcuts import render, redirect
from django.utils import timezone
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate
from django.views.decorators.http import require_http_methods
from django.urls import reverse
from .forms import RegistrationForm
from .models import User, ActivationToken, Category
from .utils import create_activation, hash_token, send_activation_email
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
@require_http_methods(["GET","POST"])
def login_view(request):
    if request.method == "GET":
        return render(request, "accounts/login.html")
    email = request.POST.get("email", "").lower()
    password = request.POST.get("password", "")
    # Note: authenticate expects username field (our USERNAME_FIELD=email)
    user = authenticate(request, username=email, password=password)
    if user is None:
        return render(request, "accounts/login.html", {"error":"Invalid credentials"})
    if not user.is_active:
        return render(request, "accounts/login.html", {"error":"Account inactive. Activate via email."})
    # Create JWTs using simplejwt
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    response = redirect("/")  # desired landing
    # set cookies - HttpOnly, Secure recommended for prod
    response.set_cookie("access", access_token, httponly=True, max_age=15*60, secure=not settings.DEBUG, samesite="Lax")
    response.set_cookie("refresh", str(refresh), httponly=True, max_age=7*24*3600, secure=not settings.DEBUG, samesite="Lax")
    return response