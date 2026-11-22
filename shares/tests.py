import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from .models import SharedFile
from .forms import MAX_UPLOAD_SIZE, UploadForm
from .views import mask_text, mask_image_sensitive_data


@override_settings(SHARE_BASE_URL='https://share.example.test')
class ShareOptionsTests(TestCase):
    """Verify optional expiry/password behavior and generated public links."""

    def setUp(self):
        """Use an isolated encrypted-file directory for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        override = override_settings(ENCRYPTED_FILES_DIR=Path(self.temp_dir.name))
        override.enable()
        self.addCleanup(override.disable)
        self.user = get_user_model().objects.create_user(
            username='testuser',
            email='test@example.com',
            password='securepass',
        )
        self.client.force_login(self.user)

    def upload(self, **options):
        """Create a test share and return its database record."""
        data = {
            'file': SimpleUploadedFile('notes.txt', b'private contents'),
            'max_downloads': '1',
            'download_allowed': 'on',
            **options,
        }
        response = self.client.post('/', data)
        self.assertEqual(response.status_code, 302)
        return SharedFile.objects.get(token=response.url.rstrip('/').split('/')[-1])

    def test_expiry_and_password_can_both_be_disabled(self):
        """Create a passwordless share without an expiry and download it."""
        shared_file = self.upload()
        self.assertIsNone(shared_file.expires_at)
        self.assertFalse(shared_file.password_protected)
        self.assertTrue(shared_file.is_available())

        response = self.client.post(f'/f/{shared_file.token}/', {'action': 'download'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b''.join(response.streaming_content), b'private contents')
        shared_file.refresh_from_db()
        self.assertTrue(shared_file.is_deleted)
        self.assertFalse(Path(self.temp_dir.name, shared_file.stored_name).exists())

    def test_password_option_is_required_when_enabled(self):
        """Reject enabled password protection without a sufficiently long password."""
        response = self.client.post('/', {
            'file': SimpleUploadedFile('notes.txt', b'private contents'),
            'max_downloads': '1',
            'password_enabled': 'on',
            'password': 'short',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'at least 6 characters')
        self.assertEqual(SharedFile.objects.count(), 0)

    def test_local_upload_still_requires_a_file(self):
        """Keep the original server-upload flow from accepting empty file forms."""
        response = self.client.post('/', {'max_downloads': '1'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'This field is required.')
        self.assertEqual(SharedFile.objects.count(), 0)

    def test_qr_uses_configured_reachable_base_url(self):
        """Generate QR content for the configured share URL, not localhost."""
        shared_file = self.upload()
        target_url = f'https://share.example.test/f/{shared_file.token}/'
        with patch('shares.views.qrcode.make') as make_qr:
            response = self.client.get(f'/created/{shared_file.token}/')
        self.assertEqual(response.status_code, 200)
        make_qr.assert_called_once_with(target_url)
        self.assertContains(response, target_url)

    def test_local_share_url_uses_the_current_request_host(self):
        """Avoid stale Wi-Fi IPs when generating links in local mode."""
        shared_file = self.upload()
        with override_settings(SHARE_BASE_URL=''):
            with patch('shares.views.qrcode.make') as make_qr:
                response = self.client.get(f'/created/{shared_file.token}/', HTTP_HOST='localhost')
        target_url = f'http://localhost/f/{shared_file.token}/'
        self.assertEqual(response.status_code, 200)
        make_qr.assert_called_once_with(target_url)
        self.assertContains(response, target_url)
        self.assertContains(response, 'phone cannot open a computer')

    def test_expiry_choices_include_short_minutes(self):
        """Accept each added short expiry selection."""
        for minutes in ('1', '2', '5'):
            with self.subTest(minutes=minutes):
                shared_file = self.upload(
                    expiry_enabled='on',
                    expiry=minutes,
                    password_enabled='on',
                    password='secure6',
                )
                self.assertIsNotNone(shared_file.expires_at)
                self.assertTrue(shared_file.password_protected)

    def test_view_and_download_respect_uploader_permission(self):
        """Preview a file without consuming a download, then enforce download permission."""
        shared_file = self.upload()
        response = self.client.post(f'/f/{shared_file.token}/', {
            'action': 'view',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Protected preview')
        self.assertContains(response, 'private contents')
        shared_file.refresh_from_db()
        self.assertEqual(shared_file.download_count, 0)
        self.assertFalse(shared_file.is_deleted)

        response = self.client.post(f'/f/{shared_file.token}/', {
            'action': 'download',
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertEqual(b''.join(response.streaming_content), b'private contents')
        shared_file.refresh_from_db()
        self.assertEqual(shared_file.download_count, 1)
        self.assertTrue(shared_file.is_deleted)

    def test_uploader_can_disable_downloads_but_allow_preview(self):
        """Reject download attempts when disabled while continuing to allow previews."""
        shared_file = self.upload(download_allowed='')
        self.assertFalse(shared_file.download_allowed)

        response = self.client.post(f'/f/{shared_file.token}/', {'action': 'view'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Protected preview')

        response = self.client.post(f'/f/{shared_file.token}/', {'action': 'download'})
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'uploader has disabled downloads', status_code=403)
        shared_file.refresh_from_db()
        self.assertEqual(shared_file.download_count, 0)
        self.assertFalse(shared_file.is_deleted)

    def test_download_limit_is_required_when_downloads_enabled(self):
        """Ask the uploader to select a limit after enabling recipient downloads."""
        response = self.client.post('/', {
            'file': SimpleUploadedFile('notes.txt', b'private contents'),
            'download_allowed': 'on',
            'password_enabled': 'on',
            'password': 'secure6',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Choose a download limit')
        self.assertEqual(SharedFile.objects.count(), 0)

    def test_upload_size_limit_is_100_mb(self):
        """Accept exactly 100 MB and reject files larger than the configured limit."""
        for size, expected_valid in (
            (MAX_UPLOAD_SIZE, True),
            (MAX_UPLOAD_SIZE + 1, False),
        ):
            with self.subTest(size=size):
                uploaded = SimpleUploadedFile('large.txt', b'x')
                uploaded.size = size
                form = UploadForm(
                    data={'download_allowed': 'on', 'max_downloads': '1'},
                    files={'file': uploaded},
                )
                self.assertEqual(form.is_valid(), expected_valid, form.errors)
                if not expected_valid:
                    self.assertIn('100 MB', str(form.errors['file']))

    def test_direct_encrypted_upload_activates_and_consumes_share(self):
        """Finalize a private object upload and enforce its download limit."""
        with override_settings(USE_OBJECT_STORAGE=True):
            with patch(
                'shares.views.object_storage.create_upload_url',
                return_value='https://storage.example.test/upload',
            ):
                response = self.client.post('/api/uploads/init/', {
                    'file_name': 'notes.txt',
                    'file_size': '5',
                    'password_enabled': 'on',
                    'password': 'secure6',
                    'download_allowed': 'on',
                    'max_downloads': '1',
                })
            self.assertEqual(response.status_code, 200, response.content)
            token = response.json()['token']
            shared_file = SharedFile.objects.get(token=token)
            self.assertTrue(shared_file.is_deleted)
            self.assertEqual(len(bytes(shared_file.salt)), 16)

            with patch('shares.views.object_storage.object_size', return_value=21), patch(
                'shares.views.object_storage.promote_object'
            ) as promote:
                response = self.client.post('/api/uploads/finalize/', {'token': token})
            self.assertEqual(response.status_code, 200, response.content)
            promote.assert_called_once()
            shared_file.refresh_from_db()
            self.assertFalse(shared_file.is_deleted)

            with patch(
                'shares.views.object_storage.create_download_url',
                return_value='https://storage.example.test/download',
            ):
                response = self.client.post(
                    f'/api/shares/{token}/access/',
                    {'action': 'download', 'password': 'secure6'},
                )
            self.assertEqual(response.status_code, 200, response.content)
            self.assertEqual(
                response.json()['download_url'],
                'https://storage.example.test/download',
            )
            shared_file.refresh_from_db()
            self.assertEqual(shared_file.download_count, 1)
            self.assertTrue(shared_file.is_deleted)
            self.assertIsNotNone(shared_file.storage_delete_after)

    def test_new_share_disables_downloads_by_default(self):
        """Create a share with the unchecked permission option and verify it is enforced."""
        shared_file = self.upload(download_allowed='')
        self.assertFalse(shared_file.download_allowed)
        page = self.client.get(f'/f/{shared_file.token}/')
        self.assertEqual(page.status_code, 200)
        self.assertNotContains(page, 'Download file')

        response = self.client.post(f'/f/{shared_file.token}/', {'action': 'download'})
        self.assertEqual(response.status_code, 403)
        shared_file.refresh_from_db()
        self.assertEqual(shared_file.download_count, 0)
        self.assertFalse(shared_file.is_deleted)

    def test_download_request_requires_explicit_action(self):
        """Do not treat an actionless POST as permission to download."""
        shared_file = self.upload()
        response = self.client.post(f'/f/{shared_file.token}/', {})
        self.assertEqual(response.status_code, 400)
        shared_file.refresh_from_db()
        self.assertEqual(shared_file.download_count, 0)
        self.assertFalse(shared_file.is_deleted)

    def test_pdf_preview_renders_as_images_not_a_pdf_viewer(self):
        """Render PDF previews as PNG data instead of exposing browser download controls."""
        shared_file = self.upload(
            file=SimpleUploadedFile('invoice.pdf', b'%PDF-1.4\n%%EOF'),
            download_allowed='',
        )

        with patch('shares.views.render_pdf_preview', return_value=['cGFnZTE=']):
            response = self.client.post(f'/f/{shared_file.token}/', {'action': 'view'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data:image/png;base64')
        self.assertNotContains(response, 'application/pdf;base64')
        self.assertNotContains(response, '<iframe')

    def test_sensitive_text_is_masked_on_preview(self):
        """Replace common sensitive values in text previews."""
        masked = mask_text(
            'Email test@example.com phone 9876543210 Aadhaar 123412341234 PAN ABCDE1234F'
        )
        self.assertNotIn('test@example.com', masked)
        self.assertNotIn('9876543210', masked)
        self.assertNotIn('123412341234', masked)
        self.assertNotIn('ABCDE1234F', masked)

    def test_ocr_masking_fails_closed_without_tesseract(self):
        """Do not return an image unchanged if OCR masking cannot run."""
        from PIL import Image
        from unittest.mock import patch

        image = Image.new('RGB', (300, 100), 'white')
        with patch('pytesseract.image_to_data', side_effect=RuntimeError('OCR unavailable')):
            with self.assertRaises(RuntimeError):
                mask_image_sensitive_data(image)

    def test_upload_is_owned_by_user_and_history_shows_it(self):
        """Store the document under the signed-in user and show it on the dashboard."""
        shared_file = self.upload(mask_sensitive='on')
        self.assertEqual(shared_file.owner, self.user)
        self.assertTrue(shared_file.mask_sensitive)

        response = self.client.get('/dashboard/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'notes.txt')
        self.assertContains(response, 'Enabled')

    def test_registration_creates_user_without_smtp(self):
        """Allow account registration without an external SMTP server."""
        self.client.logout()
        response = self.client.post('/accounts/signup/', {
            'email': 'new@example.com',
            'username': 'newaccount',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!',
        })
        self.assertIn(response.status_code, (302, 200))
        self.assertTrue(
            get_user_model().objects.filter(username='newaccount').exists()
        )

    def test_login_accepts_email_or_username(self):
        """Allow users to sign in with either identifier used during registration."""
        for identifier in ('test@example.com', 'testuser'):
            with self.subTest(identifier=identifier):
                self.client.logout()
                response = self.client.post('/accounts/login/', {
                    'login': identifier,
                    'password': 'securepass',
                    'remember': 'on',
                })
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.url, '/dashboard/')
                self.client.logout()

    def test_download_disabled_requires_previewable_file(self):
        """Prevent creating a link that has no recipient action available."""
        response = self.client.post('/', {
            'file': SimpleUploadedFile('archive.bin', b'binary contents'),
            'max_downloads': '1',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Allow downloads because this file type cannot be previewed')
        self.assertEqual(SharedFile.objects.count(), 0)

# Create your tests here.
