"""Tests for ml_classifier.py — ML-based phishing classification."""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock

from ml_classifier import (
    _extract_features, classify, FEATURE_NAMES,
    _build_training_data, _load_model,
)


class MockHeaders:
    spf_result = "fail"
    dkim_result = "fail"
    dmarc_result = "fail"
    reply_to_mismatch = True
    display_name_spoofed = True
    anomalies = ["SPF fail", "DKIM fail"]
    forged_headers = ["X-Mailer"]
    received_chain = [{"from": "a", "by": "b"}]
    originating_ip = "1.2.3.4"
    from_address = "attacker@evil.com"
    subject = "Urgent"


class MockBody:
    text_content = "Click here to verify"
    html_content = "<p>Click</p>"
    urgency_keywords_found = ["verify", "urgent"]
    javascript_detected = False
    form_action_external = False
    hidden_text = False
    embedded_urls = ["http://evil.com"]
    embedded_images = 0
    nlp_analysis = None
    html_similarity = None


class MockURLFinding:
    url = "http://evil.com/login"
    known_phishing = True
    is_ip_based = False
    is_shortened = False
    has_homoglyph = False
    suspicious_tld = True
    redirect_chain = ["http://evil.com/r1"]
    risk_score = 30
    has_credential_form = True
    js_redirects = []
    iframes_detected = []
    intermediate_domains = []


class MockAttachment:
    is_executable = False
    has_macro = False
    extension_mismatch = False
    entropy = 4.5
    malware_match = None
    vt_detections = 0
    yara_matches = []


class TestExtractFeatures:
    def test_feature_vector_length(self):
        features = _extract_features(MockHeaders(), [], [], MockBody())
        assert len(features) == len(FEATURE_NAMES)
        assert features.shape == (len(FEATURE_NAMES),)

    def test_phishing_headers_produce_nonzero(self):
        features = _extract_features(MockHeaders(), [], [], MockBody())
        # SPF fail -> spf_pass should be 0
        assert features[0] == 0.0  # spf_pass
        assert features[1] == 0.0  # dkim_pass
        assert features[3] == 1.0  # reply_to_mismatch
        assert features[4] == 1.0  # display_name_spoofed

    def test_clean_headers(self):
        h = MockHeaders()
        h.spf_result = "pass"
        h.dkim_result = "pass"
        h.dmarc_result = "pass"
        h.reply_to_mismatch = False
        h.display_name_spoofed = False
        features = _extract_features(h, [], [], MockBody())
        assert features[0] == 1.0  # spf_pass
        assert features[1] == 1.0  # dkim_pass
        assert features[3] == 0.0  # no mismatch

    def test_url_features(self):
        features = _extract_features(MockHeaders(), [MockURLFinding()], [], MockBody())
        assert features[10] > 0  # num_urls
        assert features[11] > 0  # phishing URLs
        assert features[18] == 1.0  # has_credential_form

    def test_attachment_features(self):
        features = _extract_features(MockHeaders(), [], [MockAttachment()], MockBody())
        assert features[22] > 0  # num_attachments

    def test_empty_inputs(self):
        # No headers attributes
        features = _extract_features(object(), [], [], object())
        assert features.shape == (len(FEATURE_NAMES),)
        # Most should be zero
        assert np.sum(features) == 0.0

    def test_all_zeros_vector(self):
        features = _extract_features(object(), None, None, object())
        assert np.all(features == 0.0)


class TestBuildTrainingData:
    def test_returns_correct_shape(self):
        X, y = _build_training_data()
        assert X.shape == (1000, len(FEATURE_NAMES))
        assert y.shape == (1000,)

    def test_balanced_labels(self):
        X, y = _build_training_data()
        assert np.sum(y == 0) == 500
        assert np.sum(y == 1) == 500

    def test_values_in_range(self):
        X, y = _build_training_data()
        assert np.all(X >= 0)
        assert np.all(X <= 1)


class TestClassify:
    @patch("ml_classifier._load_model")
    def test_classify_phishing(self, mock_load):
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.15, 0.85]])
        mock_load.return_value = mock_model

        result = classify(MockHeaders(), [MockURLFinding()], [MockAttachment()], MockBody())
        assert result["ml_available"] is True
        assert result["ml_confidence"] > 70
        assert result["ml_verdict"] == "phishing"

    @patch("ml_classifier._load_model")
    def test_classify_legitimate(self, mock_load):
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.85, 0.15]])
        mock_load.return_value = mock_model

        result = classify(MockHeaders(), [], [], MockBody())
        assert result["ml_verdict"] == "legitimate"
        assert result["ml_confidence"] < 40

    @patch("ml_classifier._load_model")
    def test_classify_suspicious(self, mock_load):
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.45, 0.55]])
        mock_load.return_value = mock_model

        result = classify(MockHeaders(), [], [], MockBody())
        assert result["ml_verdict"] == "suspicious"

    @patch("ml_classifier._load_model")
    def test_model_unavailable(self, mock_load):
        mock_load.return_value = None

        result = classify(MockHeaders(), [], [], MockBody())
        assert result["ml_available"] is False
        assert result["ml_verdict"] == "unavailable"
        assert result["ml_confidence"] is None

    @patch("ml_classifier._load_model")
    def test_model_exception_handled(self, mock_load):
        mock_model = MagicMock()
        mock_model.predict_proba.side_effect = ValueError("bad input")
        mock_load.return_value = mock_model

        result = classify(MockHeaders(), [], [], MockBody())
        assert result["ml_available"] is False
        assert result["ml_verdict"] == "error"

    def test_result_structure(self):
        with patch("ml_classifier._load_model", return_value=None):
            result = classify(MockHeaders(), [], [], MockBody())
        assert "ml_confidence" in result
        assert "ml_verdict" in result
        assert "ml_features" in result
        assert "ml_available" in result
