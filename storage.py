"""
File storage abstraction — S3/MinIO in production, local filesystem fallback.
"""

import os
import io
import uuid
import logging

import config

logger = logging.getLogger(__name__)

_s3_client = None


def _get_s3_client():
    """Lazy-init boto3 S3 client."""
    global _s3_client
    if _s3_client is None:
        import boto3
        _s3_client = boto3.client(
            "s3",
            endpoint_url=config.S3_ENDPOINT_URL,
            aws_access_key_id=config.S3_ACCESS_KEY,
            aws_secret_access_key=config.S3_SECRET_KEY,
            region_name=config.S3_REGION,
        )
        # Ensure bucket exists
        try:
            _s3_client.head_bucket(Bucket=config.S3_BUCKET)
        except Exception:
            try:
                _s3_client.create_bucket(Bucket=config.S3_BUCKET)
                logger.info("Created S3 bucket: %s", config.S3_BUCKET)
            except Exception:
                logger.warning("Could not create S3 bucket %s — it may already exist", config.S3_BUCKET)
    return _s3_client


def store_eml(raw_bytes, filename):
    """Store an .eml file. Returns the storage key/path."""
    key = f"eml/{uuid.uuid4().hex}/{filename}"

    if config.S3_ENABLED:
        try:
            client = _get_s3_client()
            client.put_object(
                Bucket=config.S3_BUCKET,
                Key=key,
                Body=raw_bytes,
                ContentType="message/rfc822",
            )
            logger.info("Stored %s in S3: %s", filename, key)
            return key
        except Exception:
            logger.exception("S3 upload failed for %s — falling back to local", filename)

    # Local fallback
    local_dir = os.path.join(config.UPLOAD_DIR, key.rsplit("/", 1)[0])
    os.makedirs(local_dir, exist_ok=True)
    local_path = os.path.join(config.UPLOAD_DIR, key)
    with open(local_path, "wb") as f:
        f.write(raw_bytes)
    logger.info("Stored %s locally: %s", filename, local_path)
    return key


def retrieve_eml(key):
    """Retrieve an .eml file by its storage key. Returns bytes or None."""
    if config.S3_ENABLED:
        try:
            client = _get_s3_client()
            resp = client.get_object(Bucket=config.S3_BUCKET, Key=key)
            return resp["Body"].read()
        except Exception:
            logger.exception("S3 download failed for %s — trying local", key)

    # Local fallback
    local_path = os.path.join(config.UPLOAD_DIR, key)
    if os.path.isfile(local_path):
        with open(local_path, "rb") as f:
            return f.read()
    return None


def delete_eml(key):
    """Delete an .eml file from storage."""
    if config.S3_ENABLED:
        try:
            client = _get_s3_client()
            client.delete_object(Bucket=config.S3_BUCKET, Key=key)
            logger.info("Deleted from S3: %s", key)
            return True
        except Exception:
            logger.exception("S3 delete failed for %s", key)

    # Local fallback
    local_path = os.path.join(config.UPLOAD_DIR, key)
    if os.path.isfile(local_path):
        os.remove(local_path)
        logger.info("Deleted locally: %s", local_path)
        return True
    return False
