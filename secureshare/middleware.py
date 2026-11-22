import os

from django.conf import settings
from django.http import HttpResponse


class DeploymentConfigurationMiddleware:
    """Block Vercel requests until persistent database and storage settings exist."""

    def __init__(self, get_response):
        """Store Django's next middleware or view."""
        self.get_response = get_response

    def __call__(self, request):
        """Reject incomplete Vercel configuration without breaking build discovery."""
        if settings.VERCEL:
            required = (
                'DJANGO_SECRET_KEY',
                'DATABASE_URL',
                'S3_BUCKET_NAME',
                'S3_REGION',
                'S3_ENDPOINT_URL',
                'S3_ACCESS_KEY_ID',
                'S3_SECRET_ACCESS_KEY',
            )
            missing = [key for key in required if not os.environ.get(key)]
            if missing:
                return HttpResponse(
                    'Deployment configuration is incomplete. Set these environment '
                    f'variables in Vercel project settings: {", ".join(missing)}.',
                    status=503,
                    content_type='text/plain',
                )
        return self.get_response(request)
