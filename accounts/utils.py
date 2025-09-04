# accounts/utils.py
import secrets
import hashlib
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

def generate_token():
    return secrets.token_urlsafe(32)

def hash_token(token: str) -> str:
    # SHA256 with secret key as salt
    to_hash = f"{token}{settings.SECRET_KEY}"
    return hashlib.sha256(to_hash.encode()).hexdigest()

def create_activation(user, expiry_hours=24):
    from .models import ActivationToken
    token = generate_token()
    token_hash = hash_token(token)
    expires_at = timezone.now() + timedelta(hours=expiry_hours)
    # mark older tokens used
    ActivationToken.objects.filter(user=user, used=False).update(used=True)
    act = ActivationToken.objects.create(user=user, token_hash=token_hash, expires_at=expires_at)
    return token, act

def send_activation_email(request, user, token):
    activation_path = reverse("accounts:activate")
    link = request.build_absolute_uri(f"{activation_path}?token={token}&email={user.email}&category={user.category.id}")
    subject = "Activate your account"
    context = {"user": user, "activation_link": link, "expires": 24}
    body_html = render_to_string("accounts/activation_email.html", context)
    msg = EmailMultiAlternatives(subject, body_html, settings.EMAIL_HOST_USER, [user.email])
    msg.attach_alternative(body_html, "text/html")
    msg.send(fail_silently=False)