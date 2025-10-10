# accounts/forms.py
import re
from django import forms
from .models import User, Category, Document
from django.core.exceptions import ValidationError

GMAIL_REGEX = re.compile(r'^[A-Za-z0-9._%+-]+@gmail\.com$')
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#\$%\^&\*]).{8,}$')


class RegistrationForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)
    category = forms.ModelChoiceField(queryset=Category.objects.all())
    terms = forms.BooleanField()
    captcha = forms.CharField()

    def clean_email(self):
        email = self.cleaned_data['email'].lower()
        if not GMAIL_REGEX.match(email):
            raise ValidationError("Email must be a valid Gmail address (example@gmail.com).")
        return email

    def clean_password(self):
        pw = self.cleaned_data['password']
        if not PASSWORD_REGEX.match(pw):
            raise ValidationError(
                "Password must be min 8 chars and include uppercase, lowercase, digit and special char.")
        return pw

    def clean(self):
        data = super().clean()
        if data.get("password") != data.get("confirm_password"):
            self.add_error("confirm_password", "Passwords do not match.")
        # uniqueness per category
        email = data.get("email")
        cat = data.get("category")
        if email and cat:
            if User.objects.filter(email__iexact=email, category=cat).exists():
                raise ValidationError("This email is already registered for the selected category.")
        return data

class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['file']

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            valid_extensions = ['.pdf', '.csv']
            if not any([file.name.endswith(ext) for ext in valid_extensions]):
                raise forms.ValidationError("Only PDF or CSV files are allowed.")
        return file
