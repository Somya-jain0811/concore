"""Security tests for tools/cwrap.py and tools/pwrap.py (Issue D).

Verifies that sensitive mediator API keys are masked in debug logs and URLs,
preventing plaintext credential exposure (CWE-532).
"""

import sys
import os
import logging
import pytest

# Ensure concore root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.cwrap import mask_apikey as cwrap_mask
from tools.pwrap import mask_apikey as pwrap_mask


@pytest.mark.parametrize("mask_func", [cwrap_mask, pwrap_mask])
class TestMaskApiKey:
    """Test the mask_apikey function across cwrap and pwrap."""

    def test_empty_and_none(self, mask_func):
        assert mask_func("") == "<empty>"
        assert mask_func(None) == "<empty>"
        assert mask_func("   ") == "<empty>"
        assert mask_func("\n\t") == "<empty>"

    def test_short_keys_fully_masked(self, mask_func):
        assert mask_func("a") == "****"
        assert mask_func("ab") == "****"
        assert mask_func("abc") == "****"
        assert mask_func("abcd") == "****"

    def test_standard_keys_redacted(self, mask_func):
        secret = "secret1234"
        masked = mask_func(secret)
        # Should expose only the last 4 characters
        assert masked == "******1234"
        assert "secret" not in masked
        assert masked.endswith("1234")

    def test_long_apikey_redacted(self, mask_func):
        secret = "concore_mediator_secret_key_8899"
        masked = mask_func(secret)
        assert secret not in masked
        assert masked.endswith("8899")
        assert masked.count("*") == len(secret) - 4

    def test_url_query_style_apikey(self, mask_func):
        secret = "?apikey=my_secret_token_1122"
        masked = mask_func(secret)
        assert "my_secret_token" not in masked
        assert masked.startswith("?apikey=")
        assert masked.endswith("1122")

    def test_bare_query_style_apikey(self, mask_func):
        secret = "apikey=my_secret_token_3344"
        masked = mask_func(secret)
        assert "my_secret_token" not in masked
        assert masked.startswith("apikey=")
        assert masked.endswith("3344")

    def test_whitespace_stripped(self, mask_func):
        secret = "  secret5678\n"
        masked = mask_func(secret)
        assert "secret" not in masked
        assert masked.endswith("5678")


class TestLogSanitization:
    """Verify that logging with mask_apikey prevents plaintext secret leakage."""

    def test_cwrap_debug_log_does_not_leak_key(self, caplog):
        secret_key = "super_sensitive_api_key_4321"
        caplog.set_level(logging.DEBUG)

        logger = logging.getLogger("cwrap_test")
        logger.debug(f"API Key: {cwrap_mask(secret_key)}")

        # Plaintext secret must NOT be in the log output
        assert secret_key not in caplog.text
        # Masked version must be present
        assert cwrap_mask(secret_key) in caplog.text
        assert "4321" in caplog.text

    def test_cwrap_url_log_does_not_leak_key(self, caplog):
        secret_key = "?apikey=super_sensitive_api_key_9988"
        yuyu = "yuyu"
        name2 = "ym"
        caplog.set_level(logging.DEBUG)

        logger = logging.getLogger("cwrap_url_test")
        url = f"https://www.controlcore.org/pm/{yuyu}{cwrap_mask(secret_key)}&fetch={name2}"
        logger.debug(url)

        # Plaintext secret must NOT be in the log output
        assert "super_sensitive_api_key" not in caplog.text
        # URL structure with masked key should be in log
        assert "https://www.controlcore.org/pm/yuyu?apikey=" in caplog.text
        assert "9988&fetch=ym" in caplog.text

    def test_pwrap_debug_log_does_not_leak_key(self, caplog):
        secret_key = "another_secret_token_7766"
        caplog.set_level(logging.DEBUG)

        logger = logging.getLogger("pwrap_test")
        logger.debug(f"API Key: {pwrap_mask(secret_key)}")

        assert secret_key not in caplog.text
        assert pwrap_mask(secret_key) in caplog.text
        assert "7766" in caplog.text
