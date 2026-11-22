from django.db import models
from django.utils import timezone


from django.conf import settings


class SharedFile(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='shared_files',
    )
    token = models.CharField(max_length=32, unique=True)
    original_name = models.CharField(max_length=255)
    stored_name = models.CharField(max_length=255)
    password_hash = models.CharField(max_length=128)
    salt = models.BinaryField()
    nonce = models.BinaryField()
    file_size = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    password_protected = models.BooleanField(default=True)
    download_allowed = models.BooleanField(default=False)
    mask_sensitive = models.BooleanField(default=False)
    max_downloads = models.PositiveIntegerField()
    download_count = models.PositiveIntegerField(default=0)
    failed_attempts = models.PositiveIntegerField(default=0)
    is_deleted = models.BooleanField(default=False)
    storage_delete_after = models.DateTimeField(null=True, blank=True)
    source_document = models.ForeignKey(
        'LibraryDocument',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='shared_links',
    )

    def is_expired(self):
        """Return whether this share's expiry time has passed."""
        return self.expires_at is not None and timezone.now() >= self.expires_at

    def downloads_left(self):
        """Return remaining downloads, or None when downloads are unlimited."""
        if self.max_downloads == 0:
            return None
        return max(0, self.max_downloads - self.download_count)

    def is_available(self):
        """Return whether the share can still be downloaded."""
        downloads_left = self.downloads_left()
        return (
            not self.is_deleted
            and not self.is_expired()
            and (downloads_left is None or downloads_left > 0)
        )

    def __str__(self):
        """Return a readable name for the admin and shell."""
        return self.original_name


class LibraryDocument(models.Model):
    """Keep an account-owned encrypted document independently of share links."""

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='library_documents',
    )
    original_name = models.CharField(max_length=255)
    stored_name = models.CharField(max_length=255)
    nonce = models.BinaryField()
    file_size = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_ready = models.BooleanField(default=False)
    pending_until = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        """Return a readable document name for the admin and shell."""
        return self.original_name


class AccessLog(models.Model):
    shared_file = models.ForeignKey(SharedFile, on_delete=models.CASCADE, related_name='access_logs')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    time = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)
    note = models.TextField(blank=True)

    def __str__(self):
        """Return a readable summary of an access attempt."""
        return f"{self.shared_file.token}: {self.note}"

# Create your models here.
