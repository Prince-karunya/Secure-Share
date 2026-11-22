import os

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm

from .file_types import PREVIEW_CONTENT_TYPES


DANGEROUS_EXTENSIONS = {'.exe', '.bat', '.sh', '.js'}
MAX_UPLOAD_SIZE = 100 * 1024 * 1024
VERCEL_UPLOAD_SIZE = 50_000_000 - 16


class RegistrationForm(UserCreationForm):
    """Create an account with clear email, username, and password validation."""

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'placeholder': 'you@example.com'}),
    )

    class Meta(UserCreationForm.Meta):
        model = get_user_model()
        fields = ('username', 'email')

    def clean_email(self):
        """Reject email addresses that already belong to an account."""
        email = self.cleaned_data['email'].strip().lower()
        if get_user_model().objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email


class UploadForm(forms.Form):
    """Validate file uploads and share settings."""

    file = forms.FileField()
    file_name = forms.CharField(required=False, max_length=255)
    file_size = forms.IntegerField(required=False, min_value=1, max_value=MAX_UPLOAD_SIZE)
    expiry_enabled = forms.BooleanField(
        label="Set an expiry time",
        required=False,
        initial=True,
    )
    expiry = forms.ChoiceField(required=False, choices=[
        ('1', '1 minute'),
        ('2', '2 minutes'),
        ('5', '5 minutes'),
        ('10', '10 minutes'),
        ('60', '1 hour'),
        ('360', '6 hours'),
        ('1440', '24 hours'),
        ('10080', '7 days'),
    ])
    max_downloads = forms.ChoiceField(required=False, initial='0', choices=[
        ('0', 'Unlimited'),
        ('1', '1'),
        ('3', '3'),
        ('5', '5'),
        ('10', '10'),
    ])
    password_enabled = forms.BooleanField(
        label="Require a password",
        required=False,
        initial=True,
    )
    password = forms.CharField(required=False, widget=forms.PasswordInput)
    download_allowed = forms.BooleanField(
        label="Allow recipients to download the file",
        required=False,
        initial=False,
    )
    mask_sensitive = forms.BooleanField(
        label="Mask sensitive information in previews and downloads",
        required=False,
        initial=False,
    )

    def clean(self):
        """Require expiry and password values only when their options are enabled."""
        cleaned_data = super().clean()
        if cleaned_data.get('expiry_enabled') and not cleaned_data.get('expiry'):
            self.add_error('expiry', "Choose an expiry time.")
        if cleaned_data.get('download_allowed') and not cleaned_data.get('max_downloads'):
            self.add_error('max_downloads', "Choose a download limit.")
        password = cleaned_data.get('password', '')
        if cleaned_data.get('password_enabled') and len(password) < 6:
            self.add_error('password', "Enter a password of at least 6 characters.")
        uploaded = cleaned_data.get('file')
        file_name = uploaded.name if uploaded else cleaned_data.get('file_name', '')
        if file_name:
            extension = os.path.splitext(file_name.replace('\\', '/'))[1].lower()
            if extension in DANGEROUS_EXTENSIONS:
                self.add_error('file', "This file type is not allowed.")
        if (
            file_name
            and not cleaned_data.get('download_allowed')
            and os.path.splitext(file_name.replace('\\', '/'))[1].lower() not in PREVIEW_CONTENT_TYPES
        ):
            self.add_error(
                'download_allowed',
                "Allow downloads because this file type cannot be previewed in a browser.",
            )
        return cleaned_data

    def clean_file(self):
        """Reject oversized or dangerous file uploads."""
        uploaded = self.cleaned_data.get('file')
        if uploaded is None:
            return None
        if uploaded.size > MAX_UPLOAD_SIZE:
            raise forms.ValidationError("The file must be no larger than 100 MB.")
        extension = os.path.splitext(uploaded.name)[1].lower()
        if extension in DANGEROUS_EXTENSIONS:
            raise forms.ValidationError("This file type is not allowed.")
        return uploaded


class DownloadForm(forms.Form):
    """Collect the password for a shared file."""

    password = forms.CharField(
        label="Download password",
        min_length=1,
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter password'}),
    )
