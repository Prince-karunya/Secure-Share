import base64
import hashlib
import hmac
import io
import logging
import os
import secrets
from pathlib import Path

import qrcode
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.contrib.auth.hashers import check_password, make_password
from django.db.models import F
from django.db.models import Q
from django.http import FileResponse, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.views.decorators.http import require_GET
import re

from .crypto_utils import decrypt_bytes, encrypt_bytes
from .file_types import PREVIEW_CONTENT_TYPES
from .forms import (
    DANGEROUS_EXTENSIONS,
    MAX_UPLOAD_SIZE,
    DownloadForm,
    RegistrationForm,
    UploadForm,
    VERCEL_UPLOAD_SIZE,
)
from .models import AccessLog, LibraryDocument, SharedFile
from . import object_storage

logger = logging.getLogger(__name__)


def encrypted_file_path(shared_file):
    """Build a safe path to the encrypted file for a database record."""
    from django.conf import settings
    return Path(settings.ENCRYPTED_FILES_DIR) / shared_file.stored_name


def library_key_for_user(user):
    """Derive the account's browser-delivered document-library encryption key."""
    message = f"secureshare-library-v1:{user.pk}".encode('utf-8')
    return hmac.new(settings.SECRET_KEY.encode('utf-8'), message, hashlib.sha256).digest()


def library_document_path(document):
    """Build the private on-disk path for an encrypted library document."""
    return Path(settings.ENCRYPTED_FILES_DIR) / document.stored_name


def library_upload_pending(document, user):
    """Return whether this user's library upload is still pending and valid."""
    return (
        document.owner_id == user.id
        and not document.is_ready
        and document.pending_until is not None
        and document.pending_until > timezone.now()
    )


def cleanup_pending_library_uploads():
    """Remove expired, unfinished library uploads from storage and the database."""
    expired = LibraryDocument.objects.filter(
        is_ready=False,
        pending_until__lte=timezone.now(),
    ).exclude(pending_until__isnull=True).order_by('pending_until')[:20]
    for document in expired:
        try:
            if settings.USE_OBJECT_STORAGE:
                object_storage.delete_object(document.stored_name)
            else:
                library_document_path(document).unlink(missing_ok=True)
        except Exception:
            logger.exception("Could not clean up an expired library upload.")
            continue
        document.delete()


def delete_shared_file(shared_file, defer_object_delete=False):
    """Delete a share's encrypted file from disk and mark it unavailable."""
    if settings.USE_OBJECT_STORAGE:
        if defer_object_delete:
            shared_file.storage_delete_after = timezone.now() + timezone.timedelta(minutes=15)
        else:
            object_storage.delete_object(shared_file.stored_name)
            shared_file.storage_delete_after = None
    else:
        encrypted_file_path(shared_file).unlink(missing_ok=True)
        shared_file.storage_delete_after = None
    shared_file.is_deleted = True
    shared_file.save(update_fields=['is_deleted', 'storage_delete_after'])


def cleanup_expired_shares():
    """Clean up expired or fully downloaded shares."""
    if settings.USE_OBJECT_STORAGE:
        pending_deletes = SharedFile.objects.filter(
            is_deleted=True,
            storage_delete_after__lte=timezone.now(),
        ).exclude(storage_delete_after__isnull=True).order_by('storage_delete_after')[:20]
        for shared_file in pending_deletes:
            object_storage.delete_object(shared_file.stored_name)
            SharedFile.objects.filter(pk=shared_file.pk).update(storage_delete_after=None)

        due_shares = SharedFile.objects.filter(is_deleted=False).filter(
            Q(expires_at__lte=timezone.now()) |
            Q(download_count__gte=F('max_downloads'))
        ).order_by('expires_at', 'created_at')[:20]
        for shared_file in due_shares:
            delete_shared_file(shared_file, defer_object_delete=True)
        return

    for shared_file in SharedFile.objects.filter(is_deleted=False):
        if shared_file.is_expired() or shared_file.downloads_left() == 0:
            delete_shared_file(shared_file)


def remove_unavailable_object(shared_file):
    """Immediately remove an expired or exhausted object when its share is opened."""
    if (
        settings.USE_OBJECT_STORAGE
        and not shared_file.is_deleted
        and (shared_file.is_expired() or shared_file.downloads_left() == 0)
    ):
        delete_shared_file(shared_file)


def cleanup_local_storage():
    """Run eager global cleanup when using local disk storage."""
    if not settings.USE_OBJECT_STORAGE:
        cleanup_expired_shares()


def client_ip(request):
    """Return the client's IP address."""
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def log_access(shared_file, request, success, note):
    """Record a download-page access attempt."""
    AccessLog.objects.create(
        shared_file=shared_file,
        ip_address=client_ip(request),
        success=success,
        note=note,
    )


def unavailable(request):
    """Render the generic unavailable page for dead links."""
    return render(request, 'shares/unavailable.html', status=410)


def preview_content_type(filename):
    """Return a safe inline content type for supported preview formats."""
    return PREVIEW_CONTENT_TYPES.get(Path(filename).suffix.lower())


def render_pdf_preview(plaintext, mask_sensitive=False):
    """Render PDF bytes into PNG page images so no browser PDF viewer can expose a download button."""
    import pypdfium2 as pdfium

    pages = []
    document = pdfium.PdfDocument(plaintext)
    try:
        for page_index in range(min(len(document), 50)):
            page = document[page_index]
            bitmap = page.render(scale=1.5)
            image = bitmap.to_pil()
            if mask_sensitive:
                image = mask_image_sensitive_data(image)
            buffer = io.BytesIO()
            image.save(buffer, format='PNG', optimize=True)
            pages.append(base64.b64encode(buffer.getvalue()).decode('ascii'))
            bitmap.close()
            page.close()
    finally:
        document.close()
    return pages


SENSITIVE_PATTERNS = (
    re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
    re.compile(r'\b\d{12}\b'),
    re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b', re.I),
    re.compile(r'\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d][Z\d][A-Z\d]\b', re.I),
    re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,12}\b', re.I),
    re.compile(r'\b(?:\+91[\s-]?)?[6-9]\d{9}\b'),
    re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.I),
    re.compile(r'(?<!\d)(?:\d[\s-]?){8,17}\d(?!\d)'),
)

SENSITIVE_LABELS = re.compile(
    r'(aadhaar|aadhar|pan\s*(number|no)?|gstin|gst\s*(number|no)?|ifsc|account\s*(number|no)?|'
    r'bank\s*account|invoice\s*(number|no)?|order\s*(number|no)?|phone|mobile|email|'
    r'address|place\s*of\s*supply|ship(?:ping)?\s*address|delivery\s*address)',
    re.I,
)


def contains_sensitive_text(text):
    """Return whether text contains a common document-sensitive pattern."""
    return any(pattern.search(text) for pattern in SENSITIVE_PATTERNS)


def mask_text(text):
    """Replace common account, card, Aadhaar, PAN, phone, and email values."""
    for pattern in SENSITIVE_PATTERNS:
        text = pattern.sub(lambda match: '•' * len(match.group(0)), text)
    return text


def mask_image_sensitive_data(image):
    """Cover OCR-detected sensitive text blocks in an image."""
    try:
        import pytesseract
        from PIL import ImageDraw
        from pathlib import Path

        tesseract_path = Path(r'C:\Program Files\Tesseract-OCR\tesseract.exe')
        if tesseract_path.exists():
            pytesseract.pytesseract.tesseract_cmd = str(tesseract_path)
        elif not Path(pytesseract.pytesseract.tesseract_cmd).exists():
            raise RuntimeError("Tesseract OCR is not installed or is not on PATH.")

        data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
        draw = ImageDraw.Draw(image)
        line_text = {}
        line_boxes = {}
        for index, word in enumerate(data['text']):
            key = (data['block_num'][index], data['par_num'][index], data['line_num'][index])
            line_text.setdefault(key, [])
            line_text[key].append(word)
            line_boxes.setdefault(key, []).append({
                'left': data['left'][index],
                'top': data['top'][index],
                'width': data['width'][index],
                'height': data['height'][index],
            })
        for key, words in line_text.items():
            line = ' '.join(words)
            if contains_sensitive_text(line) or SENSITIVE_LABELS.search(line):
                boxes = line_boxes[key]
                left = min(box['left'] for box in boxes)
                top = min(box['top'] for box in boxes)
                right = max(box['left'] + box['width'] for box in boxes)
                bottom = max(box['top'] + box['height'] for box in boxes)
                draw.rectangle((left, top, right, bottom), fill='#1f2937')
    except Exception as exc:
        raise RuntimeError("Sensitive-data masking could not be completed.") from exc
    return image


@login_required
def dashboard(request):
    """Show the signed-in user's upload history and share status."""
    shares = SharedFile.objects.filter(owner=request.user).order_by('-created_at')
    return render(request, 'shares/dashboard.html', {
        'shares': shares,
        'client_encrypted_download': settings.USE_OBJECT_STORAGE,
    })


@login_required
def library(request):
    """Show the signed-in user's private, reusable document library."""
    cleanup_pending_library_uploads()
    documents = LibraryDocument.objects.filter(
        owner=request.user,
        is_ready=True,
    ).order_by('-created_at')
    return render(request, 'shares/library.html', {
        'documents': documents,
        'max_upload_size_mb': (
            50 if settings.USE_OBJECT_STORAGE else MAX_UPLOAD_SIZE // (1024 * 1024)
        ),
    })


@login_required
@require_POST
def library_upload_init(request):
    """Create a short-lived upload record for a browser-encrypted library file."""
    cleanup_pending_library_uploads()
    file_name = request.POST.get('file_name', '').strip()
    try:
        file_size = int(request.POST.get('file_size', '0'))
    except ValueError:
        return JsonResponse({'error': 'Choose a valid file.'}, status=400)
    maximum_size = VERCEL_UPLOAD_SIZE if settings.USE_OBJECT_STORAGE else MAX_UPLOAD_SIZE
    normalized_name = file_name.replace('\\', '/')
    extension = Path(normalized_name).suffix.lower()
    if (
        not file_name
        or len(file_name) > 255
        or Path(normalized_name).name != file_name
        or extension in DANGEROUS_EXTENSIONS
    ):
        return JsonResponse({'error': 'This file name or type is not allowed.'}, status=400)
    if file_size < 1 or file_size > maximum_size:
        return JsonResponse({
            'error': f'Choose a file no larger than {maximum_size // (1024 * 1024)} MB.'
        }, status=400)

    token = secrets.token_urlsafe(24)
    nonce = secrets.token_bytes(12)
    stored_name = (
        f"library/pending/{token}.enc"
        if settings.USE_OBJECT_STORAGE else f"library-{token}.enc"
    )
    document = LibraryDocument.objects.create(
        owner=request.user,
        original_name=file_name,
        stored_name=stored_name,
        nonce=nonce,
        file_size=file_size,
        pending_until=timezone.now() + timezone.timedelta(minutes=15),
    )
    response = {
        'token': str(document.pk),
        'library_key': base64.b64encode(library_key_for_user(request.user)).decode('ascii'),
        'nonce': base64.b64encode(nonce).decode('ascii'),
    }
    if settings.USE_OBJECT_STORAGE:
        try:
            response['upload_url'] = object_storage.create_upload_url(stored_name)
        except Exception:
            logger.exception("Could not create an object-storage library upload URL.")
            document.delete()
            return JsonResponse({'error': 'Secure upload could not be started.'}, status=503)
    else:
        response['upload_url'] = reverse('library_upload_bytes', kwargs={'document_id': document.pk})
    json_response = JsonResponse(response)
    json_response['Cache-Control'] = 'private, no-store'
    return json_response


@login_required
@require_POST
def library_upload_bytes(request, document_id):
    """Store an encrypted library upload in local private storage."""
    if settings.USE_OBJECT_STORAGE:
        return JsonResponse({'error': 'Use the private object-storage upload URL.'}, status=400)
    try:
        document = LibraryDocument.objects.get(pk=document_id, owner=request.user)
    except LibraryDocument.DoesNotExist:
        return JsonResponse({'error': 'The library upload could not be found.'}, status=404)
    if not library_upload_pending(document, request.user):
        return JsonResponse({'error': 'The upload session expired. Please try again.'}, status=410)
    encrypted_upload = request.FILES.get('encrypted_file')
    if not encrypted_upload or encrypted_upload.size != document.file_size + 16:
        return JsonResponse({'error': 'Uploaded file size did not match the selected file.'}, status=400)
    try:
        path = library_document_path(document)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('wb') as destination:
            for chunk in encrypted_upload.chunks():
                destination.write(chunk)
    except OSError:
        logger.exception("Could not save an encrypted library document.")
        return JsonResponse({'error': 'The encrypted document could not be saved.'}, status=500)
    document.is_ready = True
    document.pending_until = None
    document.save(update_fields=['is_ready', 'pending_until'])
    return JsonResponse({'success': True})


@login_required
@require_POST
def library_upload_finalize(request):
    """Verify and activate an encrypted object-storage library upload."""
    if not settings.USE_OBJECT_STORAGE:
        return JsonResponse({'error': 'Private object storage is not configured.'}, status=503)
    try:
        document = LibraryDocument.objects.get(
            pk=request.POST.get('token', ''),
            owner=request.user,
        )
    except (LibraryDocument.DoesNotExist, ValueError):
        return JsonResponse({'error': 'The library upload could not be found.'}, status=404)
    if not library_upload_pending(document, request.user):
        return JsonResponse({'error': 'The upload session expired. Please try again.'}, status=410)
    try:
        stored_size = object_storage.object_size(document.stored_name)
    except Exception:
        logger.exception("Could not verify an uploaded encrypted library document.")
        return JsonResponse({'error': 'Uploaded file could not be verified.'}, status=502)
    if stored_size != document.file_size + 16:
        return JsonResponse({'error': 'Uploaded file size did not match the selected file.'}, status=400)

    permanent_key = f"library/{secrets.token_urlsafe(24)}.enc"
    try:
        object_storage.promote_object(document.stored_name, permanent_key)
    except Exception:
        logger.exception("Could not promote an object-storage library upload.")
        return JsonResponse({'error': 'Uploaded file could not be finalized.'}, status=502)
    document.stored_name = permanent_key
    document.is_ready = True
    document.pending_until = None
    document.save(update_fields=['stored_name', 'is_ready', 'pending_until'])
    return JsonResponse({'success': True})


@login_required
@require_GET
def library_ciphertext(request, document_id):
    """Return only the signed-in owner's encrypted library file bytes."""
    try:
        document = LibraryDocument.objects.get(
            pk=document_id,
            owner=request.user,
            is_ready=True,
        )
    except LibraryDocument.DoesNotExist:
        return JsonResponse({'error': 'The document is not available.'}, status=404)
    try:
        encrypted_file = open(library_document_path(document), 'rb')
    except OSError:
        logger.exception("Could not read an encrypted library document.")
        return JsonResponse({'error': 'The document is not available.'}, status=404)
    response = FileResponse(encrypted_file, content_type='application/octet-stream')
    response['Cache-Control'] = 'private, no-store'
    return response


@login_required
@require_POST
def library_delete(request, document_id):
    """Delete an encrypted document from the signed-in user's library."""
    try:
        document = LibraryDocument.objects.get(pk=document_id, owner=request.user)
    except LibraryDocument.DoesNotExist:
        return unavailable(request)
    if settings.USE_OBJECT_STORAGE:
        try:
            object_storage.delete_object(document.stored_name)
        except Exception:
            logger.exception("Could not delete an encrypted library document.")
            messages.error(request, "The document could not be deleted. Please try again.")
            return redirect('library')
    else:
        library_document_path(document).unlink(missing_ok=True)
    document.delete()
    messages.success(request, "The document was deleted from your library.")
    return redirect('library')


@login_required
def library_share(request, document_id):
    """Show the sharing options before creating a link for a library document."""
    try:
        document = LibraryDocument.objects.get(
            pk=document_id,
            owner=request.user,
            is_ready=True,
        )
    except LibraryDocument.DoesNotExist:
        return unavailable(request)
    form = UploadForm()
    form.fields['file'].required = False
    return render(request, 'shares/library_share.html', {
        'document': document,
        'form': form,
        'client_encrypted_share': True,
        'share_init_url': reverse('library_share_init', kwargs={'document_id': document.pk}),
    })


@login_required
@require_POST
def library_share_init(request, document_id):
    """Validate share settings and prepare encrypted bytes from a library document."""
    try:
        document = LibraryDocument.objects.get(
            pk=document_id,
            owner=request.user,
            is_ready=True,
        )
    except LibraryDocument.DoesNotExist:
        return JsonResponse({'error': 'The document is not available.'}, status=404)

    form_data = request.POST.copy()
    form_data['file_name'] = document.original_name
    form_data['file_size'] = str(document.file_size)
    form = UploadForm(form_data)
    form.fields['file'].required = False
    if not form.is_valid():
        return JsonResponse({'errors': form.errors.get_json_data()}, status=400)

    password_protected = form.cleaned_data['password_enabled']
    password = form.cleaned_data['password'] if password_protected else None
    token = secrets.token_urlsafe(12)
    object_key = (
        f"pending/{secrets.token_urlsafe(24)}.enc"
        if settings.USE_OBJECT_STORAGE
        else f"pending-{secrets.token_urlsafe(24)}.enc"
    )
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    expiry_minutes = form.cleaned_data['expiry']
    shared_file = SharedFile.objects.create(
        token=token,
        original_name=document.original_name,
        stored_name=object_key,
        password_hash=make_password(password) if password_protected else '',
        salt=salt,
        nonce=nonce,
        file_size=document.file_size,
        expires_at=(
            timezone.now() + timezone.timedelta(minutes=int(expiry_minutes))
            if expiry_minutes else None
        ),
        password_protected=password_protected,
        download_allowed=form.cleaned_data['download_allowed'],
        mask_sensitive=form.cleaned_data['mask_sensitive'],
        max_downloads=int(form.cleaned_data['max_downloads'] or 1),
        owner=request.user,
        is_deleted=True,
        storage_delete_after=timezone.now() + timezone.timedelta(minutes=15),
    )
    if settings.USE_OBJECT_STORAGE:
        try:
            source_url = object_storage.create_download_url(document.stored_name)
            upload_url = object_storage.create_upload_url(object_key)
        except Exception:
            logger.exception("Could not prepare object-storage access for a library share.")
            shared_file.delete()
            return JsonResponse({'error': 'Secure sharing could not be started.'}, status=503)
    else:
        upload_url = reverse('share_upload_bytes', kwargs={'token': token})
        source_url = reverse('library_ciphertext', kwargs={'document_id': document.pk})

    response = JsonResponse({
        'token': token,
        'salt': base64.b64encode(salt).decode('ascii'),
        'nonce': base64.b64encode(nonce).decode('ascii'),
        'upload_url': upload_url,
        'source_url': source_url,
        'library_key': base64.b64encode(library_key_for_user(request.user)).decode('ascii'),
        'library_nonce': base64.b64encode(bytes(document.nonce)).decode('ascii'),
        'file_size': document.file_size,
        'finalize_url': (
            reverse('upload_finalize') if settings.USE_OBJECT_STORAGE
            else reverse('share_upload_bytes', kwargs={'token': token})
        ),
        'created_url': reverse('created', kwargs={'token': token}),
        'password_protected': password_protected,
    })
    response['Cache-Control'] = 'private, no-store'
    return response


@login_required
@require_POST
def share_upload_bytes(request, token):
    """Save locally encrypted share bytes and activate the completed share."""
    if settings.USE_OBJECT_STORAGE:
        return JsonResponse({'error': 'Use the private object-storage upload URL.'}, status=400)
    try:
        shared_file = SharedFile.objects.get(
            token=token,
            owner=request.user,
            is_deleted=True,
        )
    except SharedFile.DoesNotExist:
        return JsonResponse({'error': 'The share upload could not be found.'}, status=404)
    if not shared_file.storage_delete_after or shared_file.storage_delete_after <= timezone.now():
        return JsonResponse({'error': 'The upload session expired. Please try again.'}, status=410)
    encrypted_upload = request.FILES.get('encrypted_file')
    if not encrypted_upload or encrypted_upload.size != shared_file.file_size + 16:
        return JsonResponse({'error': 'Uploaded file size did not match the selected file.'}, status=400)
    shared_file.stored_name = f"{secrets.token_urlsafe(24)}.enc"
    try:
        path = encrypted_file_path(shared_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('wb') as destination:
            for chunk in encrypted_upload.chunks():
                destination.write(chunk)
    except OSError:
        logger.exception("Could not save an encrypted shared document.")
        return JsonResponse({'error': 'The encrypted file could not be saved.'}, status=500)
    shared_file.is_deleted = False
    shared_file.storage_delete_after = None
    shared_file.save(update_fields=['stored_name', 'is_deleted', 'storage_delete_after'])
    delete_tokens = request.session.get('delete_tokens', [])
    delete_tokens.append(shared_file.token)
    request.session['delete_tokens'] = delete_tokens
    return JsonResponse({
        'created_url': reverse('created', kwargs={'token': shared_file.token}),
        'password_protected': shared_file.password_protected,
    })


def register(request):
    """Create an account and sign the user in immediately."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.email = form.cleaned_data['email'].lower()
            user.save()
            login(
                request,
                user,
                backend='allauth.account.auth_backends.AuthenticationBackend',
            )
            messages.success(request, "Account created successfully.")
            return redirect('dashboard')
    else:
        form = RegistrationForm()
    return render(request, 'account/signup.html', {'form': form})


@login_required
def upload(request):
    """Handle file upload, encryption, database creation, and redirect."""
    if settings.USE_OBJECT_STORAGE:
        if request.method == 'POST':
            return HttpResponse("Use the encrypted direct-upload form.", status=400)
        return render(request, 'shares/upload.html', {
            'form': UploadForm(),
            'client_encrypted_upload': True,
            'max_upload_size_mb': 50,
        })

    if request.method == 'POST':
        form = UploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded = form.cleaned_data['file']
            password_protected = form.cleaned_data['password_enabled']
            password = form.cleaned_data['password'] if password_protected else None
            token = secrets.token_urlsafe(12)
            encryption_password = password if password_protected else f"{settings.SECRET_KEY}:{token}"
            data = uploaded.read()
            ciphertext, salt, nonce = encrypt_bytes(data, encryption_password)

            settings.ENCRYPTED_FILES_DIR.mkdir(parents=True, exist_ok=True)
            stored_name = f"{secrets.token_urlsafe(24)}.enc"
            path = settings.ENCRYPTED_FILES_DIR / stored_name
            path.write_bytes(ciphertext)

            expiry_minutes = form.cleaned_data['expiry']
            shared_file = SharedFile.objects.create(
                token=token,
                original_name=uploaded.name,
                stored_name=stored_name,
                password_hash=make_password(password) if password_protected else '',
                salt=salt,
                nonce=nonce,
                file_size=len(data),
                expires_at=(
                    timezone.now() + timezone.timedelta(minutes=int(expiry_minutes))
                    if expiry_minutes else None
                ),
                password_protected=password_protected,
                download_allowed=form.cleaned_data['download_allowed'],
                mask_sensitive=form.cleaned_data['mask_sensitive'],
                max_downloads=int(form.cleaned_data['max_downloads'] or 1),
                owner=request.user,
            )
            delete_tokens = request.session.get('delete_tokens', [])
            delete_tokens.append(shared_file.token)
            request.session['delete_tokens'] = delete_tokens
            messages.success(request, "Your secure share link is ready.")
            return redirect('created', token=shared_file.token)
    else:
        form = UploadForm()
    return render(request, 'shares/upload.html', {'form': form})


def created(request, token):
    """Show the share link, expiry, limit, QR code, and authorized delete action."""
    cleanup_local_storage()
    try:
        shared_file = SharedFile.objects.get(token=token)
    except SharedFile.DoesNotExist:
        return unavailable(request)
    remove_unavailable_object(shared_file)
    if not shared_file.is_available():
        return unavailable(request)

    share_path = reverse('download', kwargs={'token': shared_file.token})
    share_base_url = getattr(settings, 'SHARE_BASE_URL', '')
    share_url = (
        f"{share_base_url.rstrip('/')}{share_path}"
        if share_base_url else request.build_absolute_uri(share_path)
    )
    qr = qrcode.make(share_url)
    buffer = io.BytesIO()
    qr.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode('ascii')
    can_delete = (
        shared_file.token in request.session.get('delete_tokens', [])
        or (
            request.user.is_authenticated
            and shared_file.owner_id == request.user.id
        )
    )
    return render(request, 'shares/created.html', {
        'shared_file': shared_file,
        'share_url': share_url,
        'qr_base64': qr_base64,
        'can_delete': can_delete,
        'qr_uses_localhost': (
            not share_base_url
            and request.get_host().split(':')[0] in {'localhost', '127.0.0.1'}
        ),
        'client_encrypted_share': settings.USE_OBJECT_STORAGE,
    })


def download(request, token):
    """Show file actions and return an authorized preview or download."""
    cleanup_local_storage()
    try:
        shared_file = SharedFile.objects.get(token=token)
    except SharedFile.DoesNotExist:
        return unavailable(request)
    remove_unavailable_object(shared_file)

    if not shared_file.is_available():
        log_access(shared_file, request, False, 'expired or no longer available')
        return unavailable(request)
    if settings.USE_OBJECT_STORAGE and request.method == 'POST':
        return HttpResponse("Use the secure browser access form.", status=400)
    if shared_file.failed_attempts >= 5:
        delete_shared_file(shared_file)
        log_access(shared_file, request, False, 'locked after 5 wrong attempts')
        return unavailable(request)

    action = request.POST.get('action') if request.method == 'POST' else None
    content_type = preview_content_type(shared_file.original_name)
    can_preview = content_type is not None
    if request.method == 'POST' and action == 'download' and not shared_file.download_allowed:
        log_access(shared_file, request, False, 'download denied by uploader')
        messages.error(request, "The uploader has disabled downloads for this share.")
        form = DownloadForm(request.POST)
        form.fields['password'].required = shared_file.password_protected
        return render(request, 'shares/download.html', {
            'shared_file': shared_file,
            'form': form,
            'can_preview': can_preview,
        }, status=403)
    if request.method == 'POST' and action not in {'view', 'download'}:
        form = DownloadForm(request.POST)
        form.fields['password'].required = shared_file.password_protected
        form.add_error(None, "Choose whether to view or download the file.")
        return render(request, 'shares/download.html', {
            'shared_file': shared_file,
            'form': form,
            'can_preview': can_preview,
        }, status=400)

    form = DownloadForm(request.POST if request.method == 'POST' else None)
    form.fields['password'].required = shared_file.password_protected
    if request.method == 'POST' and form.is_valid():
        password = form.cleaned_data['password']
        if shared_file.password_protected and not check_password(password, shared_file.password_hash):
            shared_file.failed_attempts += 1
            shared_file.save(update_fields=['failed_attempts'])
            log_access(shared_file, request, False, 'wrong password')
            if shared_file.failed_attempts >= 5:
                delete_shared_file(shared_file)
                log_access(shared_file, request, False, 'locked after 5 wrong attempts')
                return unavailable(request)
            messages.error(request, "Incorrect password.")
        else:
            if action == 'view' and preview_content_type(shared_file.original_name) is None:
                log_access(shared_file, request, False, 'preview format not supported')
                messages.error(request, "This file type cannot be previewed in the browser.")
                return render(request, 'shares/download.html', {
                    'shared_file': shared_file,
                    'form': form,
                    'can_preview': False,
                }, status=415)
            try:
                ciphertext = encrypted_file_path(shared_file).read_bytes()
                decryption_password = (
                    password if shared_file.password_protected
                    else f"{settings.SECRET_KEY}:{shared_file.token}"
                )
                plaintext = decrypt_bytes(
                    ciphertext, decryption_password, shared_file.salt, shared_file.nonce
                )
            except (OSError, ValueError):
                log_access(shared_file, request, False, 'decryption failed')
                messages.error(request, "This file could not be decrypted.")
            else:
                is_download = action == 'download'
                if is_download:
                    shared_file.download_count += 1
                    shared_file.save(update_fields=['download_count'])
                    log_access(shared_file, request, True, 'downloaded')
                    if shared_file.download_count >= shared_file.max_downloads:
                        delete_shared_file(shared_file)
                else:
                    log_access(shared_file, request, True, 'viewed')
                if not is_download:
                    from html import escape
                    from django.utils.html import format_html, mark_safe

                    content_type = preview_content_type(shared_file.original_name)
                    encoded = base64.b64encode(plaintext).decode('ascii')
                    if content_type.startswith('text/'):
                        text = plaintext.decode("utf-8", errors="replace")
                        if shared_file.mask_sensitive:
                            text = mask_text(text)
                        preview = (
                            '<pre class="secure-preview">'
                            f'{escape(text)}'
                            '</pre>'
                        )
                    elif content_type == 'application/pdf':
                        try:
                            pdf_pages = render_pdf_preview(
                                plaintext,
                                mask_sensitive=shared_file.mask_sensitive,
                            )
                        except Exception:
                            log_access(shared_file, request, False, 'PDF preview render failed')
                            messages.error(request, "This PDF could not be rendered safely for preview.")
                            return render(request, 'shares/download.html', {
                                'shared_file': shared_file,
                                'form': form,
                                'can_preview': False,
                            }, status=422)
                        preview = ''.join(
                            '<img class="secure-preview secure-image pdf-page" '
                            f'src="data:image/png;base64,{page}" '
                            f'alt="PDF page {index + 1}">'
                            for index, page in enumerate(pdf_pages)
                        )
                    else:
                        if shared_file.mask_sensitive:
                            from PIL import Image
                            try:
                                image = Image.open(io.BytesIO(plaintext)).convert('RGB')
                                image = mask_image_sensitive_data(image)
                                masked_buffer = io.BytesIO()
                                image.save(masked_buffer, format='PNG', optimize=True)
                                encoded = base64.b64encode(masked_buffer.getvalue()).decode('ascii')
                                content_type = 'image/png'
                            except Exception:
                                log_access(shared_file, request, False, 'Image masking failed safely')
                                messages.error(request, "This image could not be masked safely and was not shown.")
                                return render(request, 'shares/download.html', {
                                    'shared_file': shared_file,
                                    'form': form,
                                    'can_preview': False,
                                }, status=422)
                        preview = (
                            '<img class="secure-preview secure-image" '
                            f'src="data:{content_type};base64,{encoded}" '
                            f'alt="{escape(shared_file.original_name)}">'
                        )
                    response = HttpResponse(format_html(
                        '''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Cache-Control" content="no-store">
<title>Protected preview - SecureShare</title>
<style>
*{{-webkit-user-select:none!important;user-select:none!important}}
body{{margin:0;background:#111;color:#eee;font-family:system-ui,sans-serif}}
.secure-bar{{position:sticky;top:0;z-index:10;padding:.75rem 1rem;background:#0d6efd;color:white}}
.secure-stage{{min-height:100vh;padding:1rem}}
.secure-preview{{display:block;max-width:100%;max-height:85vh;margin:auto}}
.secure-image{{object-fit:contain}}
.pdf-page{{margin-bottom:1rem;background:white;box-shadow:0 0 12px #888}}
pre.secure-preview{{white-space:pre-wrap;overflow-wrap:anywhere;text-align:left;padding:1rem;background:#fff;color:#111}}
.capture-block{{display:none;position:fixed;inset:0;z-index:9999;background:#111;color:#fff;align-items:center;justify-content:center;text-align:center}}
</style></head>
<body>
<div class="secure-bar">Protected preview - downloads are disabled unless the uploader allowed them</div>
<div class="capture-block" id="captureBlock">Preview paused while this page is not active.</div>
<main class="secure-stage">{preview}</main>
<script>
document.addEventListener('contextmenu', function(e){{e.preventDefault()}});
document.addEventListener('dragstart', function(e){{e.preventDefault()}});
document.addEventListener('keydown', function(e){{
  if(e.key==='PrintScreen'||e.ctrlKey||e.metaKey){{
    if(e.key==='s'||e.key==='S'||e.key==='p'||e.key==='P'||e.key==='u'||e.key==='U'||e.key==='PrintScreen')e.preventDefault();
  }}
}});
function pausePreview(){{
  document.getElementById('captureBlock').style.display='flex';
  document.querySelector('.secure-stage').style.visibility='hidden';
}}
function resumePreview(){{
  document.getElementById('captureBlock').style.display='none';
  document.querySelector('.secure-stage').style.visibility='visible';
}}
document.addEventListener('visibilitychange', function(){{
  document.hidden?pausePreview():resumePreview();
}});
window.addEventListener('blur', pausePreview);
window.addEventListener('focus', resumePreview);
</script></body></html>''',
                        preview=mark_safe(preview),
                    ))
                    response['Cache-Control'] = 'no-store, no-cache, private, max-age=0'
                    response['Content-Security-Policy'] = "default-src 'none'; img-src data:; frame-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'"
                    response['X-Frame-Options'] = 'DENY'
                    response['X-Content-Type-Options'] = 'nosniff'
                    return response
                response = FileResponse(
                    io.BytesIO(plaintext),
                    as_attachment=is_download,
                    filename=shared_file.original_name,
                    content_type=(
                        None if is_download
                        else preview_content_type(shared_file.original_name)
                    ),
                )
                if not is_download:
                    response['X-Content-Type-Options'] = 'nosniff'
                return response

    return render(request, 'shares/download.html', {
        'shared_file': shared_file,
        'form': form,
        'can_preview': can_preview,
        'client_encrypted_download': settings.USE_OBJECT_STORAGE,
    })


@login_required
@require_POST
def upload_init(request):
    """Validate share settings and return a short-lived direct-upload URL."""
    if not settings.USE_OBJECT_STORAGE:
        return JsonResponse({'error': 'Private object storage is not configured.'}, status=503)

    form = UploadForm(request.POST)
    form.fields['file'].required = False
    if not form.is_valid():
        return JsonResponse({'errors': form.errors.get_json_data()}, status=400)
    if not form.cleaned_data.get('file_name') or not form.cleaned_data.get('file_size'):
        return JsonResponse({'error': 'Choose a file before uploading.'}, status=400)

    file_name = form.cleaned_data['file_name']
    if form.cleaned_data['file_size'] > VERCEL_UPLOAD_SIZE:
        return JsonResponse({'error': 'The free deployment upload limit is 50 MB.'}, status=400)
    if Path(file_name.replace('\\', '/')).name != file_name:
        return JsonResponse({'error': 'Invalid file name.'}, status=400)

    password_protected = form.cleaned_data['password_enabled']
    password = form.cleaned_data['password'] if password_protected else None
    token = secrets.token_urlsafe(12)
    object_key = f"pending/{secrets.token_urlsafe(24)}.enc"
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    expiry_minutes = form.cleaned_data['expiry']
    shared_file = SharedFile.objects.create(
        token=token,
        original_name=file_name,
        stored_name=object_key,
        password_hash=make_password(password) if password_protected else '',
        salt=salt,
        nonce=nonce,
        file_size=form.cleaned_data['file_size'],
        expires_at=(
            timezone.now() + timezone.timedelta(minutes=int(expiry_minutes))
            if expiry_minutes else None
        ),
        password_protected=password_protected,
        download_allowed=form.cleaned_data['download_allowed'],
        mask_sensitive=form.cleaned_data['mask_sensitive'],
        max_downloads=int(form.cleaned_data['max_downloads'] or 1),
        owner=request.user,
        is_deleted=True,
        storage_delete_after=timezone.now() + timezone.timedelta(minutes=15),
    )
    try:
        upload_url = object_storage.create_upload_url(object_key)
    except Exception:
        logger.exception("Could not create an object-storage upload URL.")
        shared_file.delete()
        return JsonResponse({'error': 'Secure upload could not be started.'}, status=503)

    return JsonResponse({
        'token': shared_file.token,
        'salt': base64.b64encode(salt).decode('ascii'),
        'nonce': base64.b64encode(nonce).decode('ascii'),
        'upload_url': upload_url,
        'finalize_url': reverse('upload_finalize'),
        'created_url': reverse('created', kwargs={'token': shared_file.token}),
    })


@login_required
@require_POST
def upload_finalize(request):
    """Verify the encrypted object and activate the completed share."""
    if not settings.USE_OBJECT_STORAGE:
        return JsonResponse({'error': 'Private object storage is not configured.'}, status=503)
    token = request.POST.get('token', '')
    try:
        shared_file = SharedFile.objects.get(
            token=token,
            owner=request.user,
            is_deleted=True,
        )
    except SharedFile.DoesNotExist:
        return JsonResponse({'error': 'Upload could not be finalized.'}, status=404)
    if not shared_file.storage_delete_after or shared_file.storage_delete_after <= timezone.now():
        return JsonResponse({'error': 'The upload session expired. Please try again.'}, status=410)
    try:
        stored_size = object_storage.object_size(shared_file.stored_name)
    except Exception:
        logger.exception("Could not verify an uploaded encrypted object.")
        return JsonResponse({'error': 'Uploaded file could not be verified.'}, status=502)
    if stored_size != shared_file.file_size + 16:
        return JsonResponse({'error': 'Uploaded file size did not match the selected file.'}, status=400)

    permanent_key = f"shares/{secrets.token_urlsafe(24)}.enc"
    try:
        object_storage.promote_object(shared_file.stored_name, permanent_key)
    except Exception:
        logger.exception("Could not promote a verified object-storage upload.")
        return JsonResponse({'error': 'Uploaded file could not be finalized.'}, status=502)
    shared_file.stored_name = permanent_key
    shared_file.is_deleted = False
    shared_file.storage_delete_after = None
    shared_file.save(update_fields=['stored_name', 'is_deleted', 'storage_delete_after'])
    delete_tokens = request.session.get('delete_tokens', [])
    delete_tokens.append(shared_file.token)
    request.session['delete_tokens'] = delete_tokens
    return JsonResponse({
        'created_url': reverse('created', kwargs={'token': shared_file.token}),
        'password_protected': shared_file.password_protected,
    })


@require_POST
def object_access(request, token):
    """Authorize access and return a short-lived URL for encrypted file bytes."""
    if not settings.USE_OBJECT_STORAGE:
        return JsonResponse({'error': 'Private object storage is not configured.'}, status=503)
    try:
        shared_file = SharedFile.objects.get(token=token)
    except SharedFile.DoesNotExist:
        return JsonResponse({'error': 'This link is expired or unavailable.'}, status=410)
    remove_unavailable_object(shared_file)
    if not shared_file.is_available() or shared_file.failed_attempts >= 5:
        if not shared_file.is_deleted and shared_file.failed_attempts >= 5:
            delete_shared_file(shared_file)
        log_access(shared_file, request, False, 'expired or no longer available')
        return JsonResponse({'error': 'This link is expired or unavailable.'}, status=410)

    action = request.POST.get('action')
    if action not in {'view', 'download'}:
        return JsonResponse({'error': 'Choose whether to view or download the file.'}, status=400)
    if action == 'download' and not shared_file.download_allowed:
        log_access(shared_file, request, False, 'download denied by uploader')
        return JsonResponse({'error': 'The uploader has disabled downloads.'}, status=403)
    if action == 'view':
        content_type = preview_content_type(shared_file.original_name)
        if content_type is None:
            return JsonResponse({'error': 'This file type cannot be previewed.'}, status=415)
    password = request.POST.get('password', '')
    if shared_file.password_protected and not check_password(password, shared_file.password_hash):
        SharedFile.objects.filter(pk=shared_file.pk).update(failed_attempts=F('failed_attempts') + 1)
        shared_file.refresh_from_db()
        log_access(shared_file, request, False, 'wrong password')
        if shared_file.failed_attempts >= 5:
            delete_shared_file(shared_file)
            log_access(shared_file, request, False, 'locked after 5 wrong attempts')
            return JsonResponse({'error': 'This link is expired or unavailable.'}, status=410)
        return JsonResponse({'error': 'Incorrect password.'}, status=403)

    try:
        download_url = object_storage.create_download_url(shared_file.stored_name)
    except Exception:
        logger.exception("Could not create an object-storage download URL.")
        return JsonResponse({'error': 'The encrypted file could not be retrieved.'}, status=502)

    if action == 'download':
        updated = SharedFile.objects.filter(
            pk=shared_file.pk,
            is_deleted=False,
            download_count__lt=F('max_downloads'),
            failed_attempts__lt=5,
        ).update(download_count=F('download_count') + 1)
        if not updated:
            log_access(shared_file, request, False, 'download limit reached')
            return JsonResponse({'error': 'This link is expired or unavailable.'}, status=410)
        shared_file.refresh_from_db()
        log_access(shared_file, request, True, 'download authorized')
    else:
        log_access(shared_file, request, True, 'preview authorized')

    exhausted = action == 'download' and shared_file.downloads_left() == 0
    if exhausted:
        delete_shared_file(shared_file, defer_object_delete=True)
    return JsonResponse({
        'download_url': download_url,
        'salt': base64.b64encode(bytes(shared_file.salt)).decode('ascii'),
        'nonce': base64.b64encode(bytes(shared_file.nonce)).decode('ascii'),
        'file_name': shared_file.original_name,
        'file_size': shared_file.file_size,
        'content_type': preview_content_type(shared_file.original_name) or 'application/octet-stream',
        'password_protected': shared_file.password_protected,
        'action': action,
        'mask_sensitive': shared_file.mask_sensitive,
    })


@require_GET
def vercel_cleanup(request):
    """Run scheduled storage cleanup only for an authorized Vercel cron request."""
    expected = os.environ.get('CRON_SECRET', '')
    supplied = request.headers.get('Authorization', '')
    if not expected or not secrets.compare_digest(supplied, f'Bearer {expected}'):
        return HttpResponse(status=403)
    cleanup_expired_shares()
    return JsonResponse({'status': 'ok'})


@require_POST
def delete_now(request, token):
    """Allow only a browser holding the uploader delete token to destroy a share."""
    try:
        shared_file = SharedFile.objects.get(token=token)
    except SharedFile.DoesNotExist:
        return unavailable(request)
    has_session_token = token in request.session.get('delete_tokens', [])
    owns_share = (
        request.user.is_authenticated
        and shared_file.owner_id == request.user.id
    )
    if not has_session_token and not owns_share:
        return unavailable(request)
    delete_shared_file(shared_file)
    log_access(shared_file, request, False, 'deleted by uploader')
    messages.success(request, "The file was deleted immediately.")
    return redirect('upload')

# Create your views here.
