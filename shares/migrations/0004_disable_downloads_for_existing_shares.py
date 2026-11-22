from django.db import migrations, models


def disable_downloads_for_existing_shares(apps, schema_editor):
    """Require explicit uploader permission for shares created before this option existed."""
    SharedFile = apps.get_model('shares', 'SharedFile')
    SharedFile.objects.all().update(download_allowed=False)


class Migration(migrations.Migration):

    dependencies = [
        ('shares', '0003_sharedfile_download_allowed'),
    ]

    operations = [
        migrations.RunPython(
            disable_downloads_for_existing_shares,
            migrations.RunPython.noop,
        ),
        migrations.AlterField(
            model_name='sharedfile',
            name='download_allowed',
            field=models.BooleanField(default=False),
        ),
    ]
