from django.contrib import admin

from .models import AccessLog, LibraryDocument, SharedFile


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


@admin.register(LibraryDocument)
class LibraryDocumentAdmin(admin.ModelAdmin):
    list_display = ('original_name', 'owner', 'file_size', 'created_at', 'is_ready')
    list_filter = ('is_ready', 'created_at')
    readonly_fields = ('owner', 'original_name', 'stored_name', 'nonce',
                       'file_size', 'created_at', 'is_ready', 'pending_until')

# Register your models here.
