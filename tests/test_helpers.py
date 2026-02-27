"""Tests for helpers.py utility functions."""

import time
import hashlib
import pytest

from helpers import (
    truncate, safe_filename, hash_content, fmt_timestamp, time_ago,
    is_valid_email, extract_domain, chunked, parse_email_address,
    clamp, pluralize, env_bool, mask_email,
)


class TestTruncate:
    def test_short_string_unchanged(self):
        assert truncate("hello", 80) == "hello"

    def test_long_string_truncated(self):
        result = truncate("a" * 100, 50)
        assert len(result) == 50
        assert result.endswith("…")

    def test_none_input(self):
        assert truncate(None) is None

    def test_empty_string(self):
        assert truncate("") == ""

    def test_exact_length(self):
        s = "a" * 80
        assert truncate(s, 80) == s


class TestSafeFilename:
    def test_strips_special_chars(self):
        result = safe_filename("hello world!@#$%.eml")
        assert "!" not in result
        assert "@" not in result
        assert "#" not in result

    def test_preserves_dots_and_dashes(self):
        result = safe_filename("my-file.eml")
        assert ".eml" in result
        assert "-" in result

    def test_truncates_to_200(self):
        result = safe_filename("a" * 300)
        assert len(result) <= 200

    def test_collapses_underscores(self):
        result = safe_filename("too   many   spaces")
        assert "__" not in result


class TestHashContent:
    def test_sha256_string(self):
        result = hash_content("hello")
        expected = hashlib.sha256(b"hello").hexdigest()
        assert result == expected

    def test_sha256_bytes(self):
        data = b"binary data"
        result = hash_content(data)
        expected = hashlib.sha256(data).hexdigest()
        assert result == expected

    def test_md5_algo(self):
        result = hash_content("test", algo="md5")
        expected = hashlib.md5(b"test").hexdigest()
        assert result == expected


class TestFmtTimestamp:
    def test_current_time(self):
        result = fmt_timestamp()
        assert "UTC" in result

    def test_epoch_zero(self):
        result = fmt_timestamp(0)
        assert "1970" in result

    def test_specific_timestamp(self):
        result = fmt_timestamp(1705312200)
        assert "2024" in result


class TestTimeAgo:
    def test_just_now(self):
        assert time_ago(time.time()) == "just now"

    def test_minutes(self):
        assert "m ago" in time_ago(time.time() - 120)

    def test_hours(self):
        assert "h ago" in time_ago(time.time() - 7200)

    def test_days(self):
        assert "d ago" in time_ago(time.time() - 172800)

    def test_months(self):
        assert "mo ago" in time_ago(time.time() - 86400 * 45)


class TestIsValidEmail:
    def test_valid_emails(self):
        assert is_valid_email("user@example.com")
        assert is_valid_email("user.name+tag@domain.co.uk")
        assert is_valid_email("a@b.cc")

    def test_invalid_emails(self):
        assert not is_valid_email("")
        assert not is_valid_email(None)
        assert not is_valid_email("not-an-email")
        assert not is_valid_email("@missing-local.com")
        assert not is_valid_email("missing-domain@")
        assert not is_valid_email("spaces in@email.com")

    def test_non_string_input(self):
        assert not is_valid_email(12345)
        assert not is_valid_email([])


class TestExtractDomain:
    def test_from_email(self):
        assert extract_domain("user@EXAMPLE.COM") == "example.com"

    def test_from_url(self):
        assert extract_domain("https://www.example.com/path") == "www.example.com"

    def test_plain_domain(self):
        assert extract_domain("example.com") == "example.com"


class TestParseEmailAddress:
    def test_display_name_format(self):
        name, email = parse_email_address('"John Doe" <john@example.com>')
        assert name == "John Doe"
        assert email == "john@example.com"

    def test_email_only(self):
        name, email = parse_email_address("user@example.com")
        assert email == "user@example.com"

    def test_empty_input(self):
        name, email = parse_email_address("")
        assert name == ""
        assert email == ""

    def test_none_input(self):
        name, email = parse_email_address(None)
        assert name == ""
        assert email == ""


class TestMaskEmail:
    def test_normal_email(self):
        result = mask_email("john@example.com")
        assert result.startswith("j")
        assert "@example.com" in result
        assert "*" in result

    def test_single_char_local(self):
        result = mask_email("j@example.com")
        assert result == "*@example.com"

    def test_none_input(self):
        assert mask_email(None) is None

    def test_no_at_sign(self):
        assert mask_email("not-an-email") == "not-an-email"


class TestEnvBool:
    def test_true_values(self):
        assert env_bool("true") is True
        assert env_bool("1") is True
        assert env_bool("yes") is True
        assert env_bool("on") is True
        assert env_bool("TRUE") is True

    def test_false_values(self):
        assert env_bool("false") is False
        assert env_bool("0") is False
        assert env_bool("no") is False
        assert env_bool("random") is False

    def test_none_default(self):
        assert env_bool(None) is False
        assert env_bool(None, default=True) is True


class TestChunked:
    def test_even_chunks(self):
        result = list(chunked([1, 2, 3, 4], 2))
        assert result == [[1, 2], [3, 4]]

    def test_uneven_chunks(self):
        result = list(chunked([1, 2, 3, 4, 5], 2))
        assert len(result) == 3
        assert result[-1] == [5]

    def test_empty_list(self):
        result = list(chunked([], 3))
        assert result == []


class TestClamp:
    def test_within_range(self):
        assert clamp(5, 0, 10) == 5

    def test_below_min(self):
        assert clamp(-5, 0, 10) == 0

    def test_above_max(self):
        assert clamp(15, 0, 10) == 10


class TestPluralize:
    def test_singular(self):
        assert pluralize("email", 1) == "email"

    def test_plural(self):
        assert pluralize("email", 5) == "emails"

    def test_zero(self):
        assert pluralize("email", 0) == "emails"
