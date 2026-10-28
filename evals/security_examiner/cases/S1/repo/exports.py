import boto3

import config


def upload(path, key):
    client = boto3.client(
        "s3",
        aws_access_key_id=config.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
        region_name=config.AWS_REGION,
    )
    client.upload_file(path, config.EXPORT_BUCKET, key)
