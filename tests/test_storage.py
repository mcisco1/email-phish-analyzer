"""Tests for storage.py — S3/MinIO and local file storage."""

import os
import pytest
from unittest.mock import patch, MagicMock

from storage import store_eml, retrieve_eml, delete_eml


class TestStoreEml:
    @patch("storage.config")
    def test_local_storage(self, mock_config, tmp_path):
        mock_config.S3_ENABLED = False
        mock_config.UPLOAD_DIR = str(tmp_path)

        key = store_eml(b"test eml content", "test.eml")
        assert key is not None
        assert "test.eml" in key
        # Verify file was written
        local_path = os.path.join(str(tmp_path), key)
        assert os.path.isfile(local_path)
        with open(local_path, "rb") as f:
            assert f.read() == b"test eml content"

    @patch("storage._get_s3_client")
    @patch("storage.config")
    def test_s3_storage(self, mock_config, mock_get_client):
        mock_config.S3_ENABLED = True
        mock_config.S3_BUCKET = "test-bucket"

        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        key = store_eml(b"test data", "upload.eml")
        assert key is not None
        mock_client.put_object.assert_called_once()

    @patch("storage._get_s3_client")
    @patch("storage.config")
    def test_s3_failure_falls_back_to_local(self, mock_config, mock_get_client, tmp_path):
        mock_config.S3_ENABLED = True
        mock_config.S3_BUCKET = "test-bucket"
        mock_config.UPLOAD_DIR = str(tmp_path)

        mock_client = MagicMock()
        mock_client.put_object.side_effect = Exception("S3 down")
        mock_get_client.return_value = mock_client

        key = store_eml(b"test data", "upload.eml")
        assert key is not None
        # Should have fallen back to local
        local_path = os.path.join(str(tmp_path), key)
        assert os.path.isfile(local_path)

    @patch("storage.config")
    def test_empty_bytes(self, mock_config, tmp_path):
        mock_config.S3_ENABLED = False
        mock_config.UPLOAD_DIR = str(tmp_path)

        key = store_eml(b"", "empty.eml")
        assert key is not None

    @patch("storage.config")
    def test_key_format(self, mock_config, tmp_path):
        mock_config.S3_ENABLED = False
        mock_config.UPLOAD_DIR = str(tmp_path)

        key = store_eml(b"data", "test.eml")
        assert key.startswith("eml/")
        assert "test.eml" in key


class TestRetrieveEml:
    @patch("storage.config")
    def test_retrieve_local(self, mock_config, tmp_path):
        mock_config.S3_ENABLED = False
        mock_config.UPLOAD_DIR = str(tmp_path)

        # Store first
        key = store_eml(b"retrieve me", "test.eml")
        # Then retrieve
        data = retrieve_eml(key)
        assert data == b"retrieve me"

    @patch("storage.config")
    def test_retrieve_not_found(self, mock_config, tmp_path):
        mock_config.S3_ENABLED = False
        mock_config.UPLOAD_DIR = str(tmp_path)

        data = retrieve_eml("eml/nonexistent/missing.eml")
        assert data is None

    @patch("storage._get_s3_client")
    @patch("storage.config")
    def test_retrieve_s3(self, mock_config, mock_get_client):
        mock_config.S3_ENABLED = True
        mock_config.S3_BUCKET = "test-bucket"

        mock_body = MagicMock()
        mock_body.read.return_value = b"s3 content"
        mock_client = MagicMock()
        mock_client.get_object.return_value = {"Body": mock_body}
        mock_get_client.return_value = mock_client

        data = retrieve_eml("eml/uuid/test.eml")
        assert data == b"s3 content"


class TestDeleteEml:
    @patch("storage.config")
    def test_delete_local(self, mock_config, tmp_path):
        mock_config.S3_ENABLED = False
        mock_config.UPLOAD_DIR = str(tmp_path)

        key = store_eml(b"delete me", "test.eml")
        result = delete_eml(key)
        assert result is True
        # File should be gone
        local_path = os.path.join(str(tmp_path), key)
        assert not os.path.isfile(local_path)

    @patch("storage.config")
    def test_delete_not_found(self, mock_config, tmp_path):
        mock_config.S3_ENABLED = False
        mock_config.UPLOAD_DIR = str(tmp_path)

        result = delete_eml("eml/nonexistent/missing.eml")
        assert result is False

    @patch("storage._get_s3_client")
    @patch("storage.config")
    def test_delete_s3(self, mock_config, mock_get_client):
        mock_config.S3_ENABLED = True
        mock_config.S3_BUCKET = "test-bucket"

        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        result = delete_eml("eml/uuid/test.eml")
        assert result is True
        mock_client.delete_object.assert_called_once()

    @patch("storage._get_s3_client")
    @patch("storage.config")
    def test_s3_delete_error(self, mock_config, mock_get_client):
        mock_config.S3_ENABLED = True
        mock_config.S3_BUCKET = "test-bucket"
        mock_config.UPLOAD_DIR = "/nonexistent"

        mock_client = MagicMock()
        mock_client.delete_object.side_effect = Exception("S3 error")
        mock_get_client.return_value = mock_client

        # Should not raise
        result = delete_eml("eml/uuid/test.eml")
        # Falls through to local check which also fails
        assert result is False
