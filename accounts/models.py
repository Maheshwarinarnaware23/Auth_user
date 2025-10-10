from django.db import models

# Create your models here.
# accounts/models.py
import secrets
import hashlib
from django.conf import settings
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager
)
from django.utils import timezone

class Category(models.Model):
    name = models.CharField(max_length=80, unique=True)
    slug = models.SlugField(max_length=100, unique=True)

    def __str__(self):
        return self.name

class UserManager(BaseUserManager):
    def create_user(self, email, category, password=None, **extra_fields):
        if not email:
            raise ValueError("Email required")
        if not category:
            raise ValueError("Category required")
        email = self.normalize_email(email)
        user = self.model(email=email, category=category, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        # supply a default category or create one called 'admin' in migrations
        admin_cat, _ = Category.objects.get_or_create(name="admin", slug="admin")
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, admin_cat, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    category = models.ForeignKey(Category, on_delete=models.PROTECT)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    is_active = models.BooleanField(default=False)  # remains False until activation
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []  # category is required programmatically

    def __str__(self):
        return f"{self.email} ({self.category})"


class ActivationToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="activation_tokens")
    token_hash = models.CharField(max_length=128, unique=True)  # store hashed token
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    def mark_used(self):
        self.used = True
        self.save(update_fields=["used"])

    def __str__(self):
        return f"Token for {self.user.email} (used={self.used})"

class PasswordResetToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="password_reset_tokens")
    token_hash = models.CharField(max_length=64, unique=True)   # sha256 hexdigest length = 64
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    def is_valid(self):
        return (not self.used) and (self.expires_at > timezone.now())

    def mark_used(self):
        self.used = True
        self.save(update_fields=["used"])

    def __str__(self):
        return f"PasswordResetToken for {self.user.email} (used={self.used})"

class Document(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to='documents/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.file.name
