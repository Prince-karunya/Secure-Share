import os

import boto3
from botocore.config import Config


def _client():
    """Create an S3 client from the deployment's private storage settings."""
    return boto3.client(
        's3',
        endpoint_url=os.environ.get('S3_ENDPOINT_URL') or None,
        region_name=os.environ.get('S3_REGION', 'us-east-1'),
        aws_access_key_id=os.environ.get('S3_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('S3_SECRET_ACCESS_KEY'),
        config=Config(
            signature_version='s3v4',
            s3={'addressing_style': 'path'},
        ),
    )


def create_upload_url(object_key):
    """Create a short-lived URL for a browser to upload encrypted bytes directly."""
    return _client().generate_presigned_url(
        'put_object',
        Params={
            'Bucket': os.environ['S3_BUCKET_NAME'],
            'Key': object_key,
            'ContentType': 'application/octet-stream',
        },
        ExpiresIn=900,
    )


def create_download_url(object_key):
    """Create a short-lived URL for a browser to fetch encrypted bytes directly."""
    return _client().generate_presigned_url(
        'get_object',
        Params={
            'Bucket': os.environ['S3_BUCKET_NAME'],
            'Key': object_key,
        },
        ExpiresIn=120,
    )


def object_size(object_key):
    """Return the size of an uploaded encrypted object."""
    result = _client().head_object(Bucket=os.environ['S3_BUCKET_NAME'], Key=object_key)
    return result['ContentLength']


def promote_object(source_key, destination_key):
    """Move a verified temporary encrypted upload into permanent storage."""
    client = _client()
    bucket = os.environ['S3_BUCKET_NAME']
    client.copy_object(
        Bucket=bucket,
        Key=destination_key,
        CopySource={'Bucket': bucket, 'Key': source_key},
        MetadataDirective='COPY',
    )
    client.delete_object(Bucket=bucket, Key=source_key)


def delete_object(object_key):
    """Delete an encrypted object from the private bucket."""
    _client().delete_object(Bucket=os.environ['S3_BUCKET_NAME'], Key=object_key)
