from django.core.management.base import BaseCommand

from shares.models import SharedFile
from shares.views import delete_shared_file


class Command(BaseCommand):
    help = "Delete expired or used-up encrypted shares"

    def handle(self, *args, **options):
        """Clean expired and fully downloaded shares from disk and database."""
        count = 0
        for shared_file in SharedFile.objects.filter(is_deleted=False):
            if shared_file.is_expired() or shared_file.downloads_left() == 0:
                delete_shared_file(shared_file)
                count += 1
        self.stdout.write(self.style.SUCCESS(f"Cleaned {count} share(s)."))
