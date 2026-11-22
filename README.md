# Self-Destruct Secure Share

A small Django application that AES-256-GCM encrypts uploaded files and removes them when the share expires or reaches its download limit.

Uploads are limited to 100 MB per file.

Expiry and password protection can each be turned off on the upload form. Download
limits are independent of expiry; choose **Unlimited** to keep a share available
until its expiry time or until the uploader deletes it. Views do not consume
download grants. Shares without a password are still encrypted at rest;
their encryption key is derived from Django's `SECRET_KEY` and the share token.
Set a private `DJANGO_SECRET_KEY` for real use and keep it stable; passwordless
shares cannot be decrypted if it changes. The built-in key is for local
development only.

Uploaders can also disable recipient downloads. Recipients can still preview
supported image, PDF, and text formats in-browser; other formats require
downloads to be enabled. Browser previews cannot prevent screenshots or saving
content through browser features. The download limit counts downloads, not
previews.

## Accounts and history

Users can register or log in with either their email address or username and
password. New shares and their download history are tied to the signed-in
account and appear in `/dashboard/`.

The signed-in **My documents** area stores reusable files encrypted in the
browser. Only the owning account can access the library. Choose **Share** on a
stored document to select its expiry, recipient password, download permission
and limit, and preview masking before creating a link. Sharing creates a
separate encrypted copy; deleting or expiring that link does not remove the
library document. Share history offers **Reshare** for links created from a
stored document. Library files remain until you delete them. Keep
`DJANGO_SECRET_KEY` unchanged and backed up so stored library files remain
decryptable.

For local image and PDF previews, install Tesseract OCR separately and make
sure `tesseract` is on `PATH`. On Vercel, the recipient's browser uses
Tesseract.js to find and cover sensitive OCR text in image/PDF previews;
text-file previews use pattern matching. Vercel loads the pinned OCR library
and English language model from jsDelivr on demand, so masking those files
requires an internet connection. File contents are processed in the browser,
not sent to an OCR service. Masked downloads are also transformed in the
browser. OCR and pattern detection can miss sensitive content; carefully
review the preview and do not treat masking as a legal-compliance guarantee.

Protected preview mode also disables common browser actions and hides content
while the tab is inactive. It cannot prevent OS-level screenshots, screen
recording, external cameras, or capture by software that bypasses browser rules.

## Setup

Requires Python 3.10 or newer.

### Start locally on this computer

The easiest local setup is to run the app only on localhost. This does not rely
on Wi-Fi and works when the computer is offline. From PowerShell:

```powershell
cd "D:\MINI Project"
.\start-local.ps1
```

The script applies migrations, starts Django at `http://127.0.0.1:8000/`,
opens the browser, and uses the existing local SQLite database and
`encrypted_files/` folder. Stop it with:

```powershell
.\stop-local.ps1
```

Links and QR codes created in local mode open on this same computer. A phone's
camera cannot use a PC's `localhost` URL. Opening a link on another device
requires a shared network (such as the same Wi-Fi/hotspot) and LAN mode; it
cannot work with Wi-Fi completely unavailable.

To run the server manually instead:

```powershell
cd "D:\MINI Project"
py -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open `http://127.0.0.1:8000/`. The Django admin is at `/admin/`.

Generate a persistent key with
`python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"`
and set it in the `DJANGO_SECRET_KEY` environment variable before starting Django.

### QR codes on another device (optional LAN mode)

The QR code contains the same URL shown in the share-link field. Localhost mode
is stable but only works on the computer running Django. To let a phone access
the app, both devices must be connected to the same Wi-Fi or hotspot. Set
`SHARE_BASE_URL` to the computer's current LAN URL and allow that IP in
`DJANGO_ALLOWED_HOSTS`, then run Django bound to all interfaces:

```powershell
$env:SHARE_BASE_URL = "http://192.168.1.25:8000"
$env:DJANGO_ALLOWED_HOSTS = "127.0.0.1,localhost,192.168.1.25"
python manage.py runserver 0.0.0.0:8000
```

Replace `192.168.1.25` with the computer's LAN IPv4 address. For use over the
internet, set `SHARE_BASE_URL` to the HTTPS domain configured for the deployment.

## Automatic cleanup

Run cleanup whenever needed:

```powershell
python manage.py cleanup_expired
```

The app also checks links lazily when they are opened.

### Windows Task Scheduler

Create a Basic Task that runs every 5 minutes. Set the program to the virtual environment's Python, for example:

`D:\MINI Project\.venv\Scripts\python.exe`

Set arguments to:

`D:\MINI Project\manage.py cleanup_expired`

Set "Start in" to:

`D:\MINI Project`

### Cron

```cron
*/5 * * * * cd /path/to/project && /path/to/venv/bin/python manage.py cleanup_expired
```

Encrypted files are stored in `encrypted_files/` outside static and media URLs.

## Deploying on Vercel

Vercel functions do not provide durable local disk or a persistent SQLite
database. For a student project on free tiers, use Supabase for both PostgreSQL
records and a private Storage bucket. Uploads are encrypted in the browser and
sent directly to the bucket; the Supabase Free plan currently limits individual
uploads to 50 MB. Downloads are fetched and decrypted in the recipient's browser.

### 1. Create external storage

Create a Supabase Free project and a **private** Storage bucket named
`secure-share-files`. Keep the bucket private. In Storage settings, enable the
S3 protocol and create S3 access keys for server-side use. Supabase S3
credentials are server-side secrets; never expose them in browser code.
Supabase's S3 endpoint, region, access key, and secret are displayed in the
project's Storage S3 configuration page.

The browser uploads directly to signed URLs from Supabase's S3 endpoint. Check
that the endpoint accepts browser requests from your Vercel production origin;
if testing Preview deployments, check their origins too.

### 2. Configure Vercel

Import this folder as a Vercel project. Add the environment variables from
`.env.example` in Vercel Project Settings for Production and Preview. Set
`DJANGO_SECRET_KEY` to a new random value. Copy the Postgres connection string
from Supabase's Connect dialog into `DATABASE_URL`; use its session pooler
connection for serverless deployments. Configure the private bucket name and
the S3 endpoint, region, access key, and secret from Supabase's Storage S3
settings.
`VERCEL_URL` is supplied by Vercel. Set `DJANGO_ALLOWED_HOSTS`,
`CSRF_TRUSTED_ORIGINS`, and `SHARE_BASE_URL` to your actual project domain.
Set a random `CRON_SECRET` for scheduled cleanup. Never commit real credentials.
Supabase Free currently includes 500 MB of database, 1 GB of file storage, and
5 GB of egress; free projects may pause after one week of inactivity. Check
Supabase's current pricing and limits before presenting, as plan terms can change.

Vercel detects the Django `manage.py` and WSGI entry point, then collects and
serves static assets through its CDN. The configured Vercel cron requests
cleanup once a day so it is deployable on Vercel Hobby. Expired and used-up
links are rejected and deleted as soon as someone opens them; the scheduled
cleanup removes stale object data when no one returns to the share. Keep the
app's cleanup cron configured.
Vercel Hobby supports only daily cron execution. On Pro, change the schedule
in `vercel.json` to `*/5 * * * *` for more frequent physical cleanup.
The deployment can now be created before environment variables are entered;
until all required values are configured, app requests show a setup-required
503 response instead of failing Vercel's Django settings discovery.

### 3. Apply database migrations and deploy

Install/use the Vercel CLI, sign in, and link this folder to the configured
Vercel project. A Git repository is optional when deploying with the CLI:

```powershell
npx vercel login
npx vercel link
npx vercel env run --environment=production -- python manage.py migrate
npx vercel --prod
```

For subsequent schema changes, run migrations against the same production
`DATABASE_URL` before relying on the new code.

### Vercel deployment behavior and limitations

- Password-protected uploads derive AES-256-GCM keys in the browser using
  PBKDF2-HMAC-SHA256 (200,000 iterations); the app stores only Django's password
  hash. For a share without a password, the browser creates a random key and
  puts it in the URL fragment. The fragment is not sent to Django; keep the
  generated link private.
- Vercel must be accessed over HTTPS for browser cryptography. Vercel's
  deployment URL and private bucket CORS must both be configured correctly.
- Vercel performs OCR masking for image and PDF previews in the recipient's
  browser using Tesseract.js; document contents stay in the browser and are not
  uploaded to an OCR service. The browser downloads the OCR library and English
  language data from jsDelivr when needed, so an internet connection is
  required. OCR and pattern detection can miss sensitive content; review the
  preview carefully. Text previews use local pattern matching. Local mode uses
  Tesseract OCR installed on the server.
- Vercel download limits count successful access grants. The private bucket
  URL is short-lived (two minutes) but can be reused during that window, so
  this serverless direct-transfer design does not provide strict one-use
  downloads. Use a persistent server host if strict one-time enforcement is
  required.
- A 50 MB encrypted file is briefly buffered in browser memory during
  encryption/decryption. Test the presentation on a modern computer and phone
  with sufficient free memory.
- The database and bucket are external services and may incur costs or have
  their own quotas. Vercel alone cannot persist this application's files.
