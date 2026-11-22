from django.contrib import admin

from .models import AccessLog, SharedFile


@admin.register(SharedFile)
class SharedFileAdmin(admin.ModelAdmin):
    list_display = ('token', 'original_name', 'expires_at', 'max_downloads',
                    'download_count', 'download_allowed', 'mask_sensitive', 'is_deleted')
    list_filter = ('is_deleted', 'expires_at')
    readonly_fields = ('token', 'original_name', 'stored_name', 'password_hash',
                       'salt', 'nonce', 'file_size', 'created_at', 'expires_at',
                       'max_downloads', 'download_count', 'failed_attempts',
                       'download_allowed', 'is_deleted', 'storage_delete_after')


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ('shared_file', 'ip_address', 'time', 'success', 'note')

# Register your models here.
