"""Tests for aws_assume.core"""

from __future__ import annotations

import configparser
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from aws_assume.core import (
    Credentials,
    _get_aws_config_path,
    list_profiles,
    write_credentials_file,
)


@pytest.fixture
def sample_creds() -> Credentials:
    return Credentials(
        access_key_id="AKIAIOSFODNN7EXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token="AQoXnyc4lcK4w//example/token==",
        expiration="2024-12-31T23:59:59+00:00",
        profile_name="my-profile",
    )


class TestCredentials:
    def test_to_eval(self, sample_creds: Credentials) -> None:
        result = sample_creds.to_eval()
        # shlex.quote() omits quotes for safe strings; adds single-quotes for unsafe ones
        assert "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" in result
        assert "export AWS_SECRET_ACCESS_KEY=" in result
        assert "export AWS_SESSION_TOKEN=" in result
        assert "export AWS_ASSUME_PROFILE=my-profile" in result

    def test_to_eval_prevents_shell_injection(self) -> None:
        """Verify shell metacharacters in credential values are safely quoted by shlex."""
        creds = Credentials(
            access_key_id="AKID",
            secret_access_key="SECRET",
            session_token="tok$(whoami)",
            expiration="unknown",
            profile_name="myprofile",
        )
        result = creds.to_eval()
        # The raw $() metacharacter must be wrapped in single-quotes, not left bare
        assert "=$(tok$(whoami))" not in result
        assert "'tok$(whoami)'" in result

    def test_to_eval_no_session_token(self) -> None:
        creds = Credentials(
            access_key_id="AKID",
            secret_access_key="SAK",
            session_token="",
            expiration="unknown",
            profile_name="static",
        )
        result = creds.to_eval()
        assert "AWS_SESSION_TOKEN" not in result
        assert "AWS_ACCESS_KEY_ID" in result

    def test_to_env_file(self, sample_creds: Credentials) -> None:
        result = sample_creds.to_env_file()
        assert "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" in result
        assert "AWS_SECRET_ACCESS_KEY=" in result
        assert "AWS_SESSION_TOKEN=" in result
        # No quotes in env file format
        assert '"' not in result

    def test_to_env_file_no_session_token(self) -> None:
        creds = Credentials(
            access_key_id="AKID",
            secret_access_key="SAK",
            session_token="",
            expiration="unknown",
            profile_name="static",
        )
        result = creds.to_env_file()
        assert "AWS_SESSION_TOKEN" not in result

    def test_to_json(self, sample_creds: Credentials) -> None:
        import json
        result = json.loads(sample_creds.to_json())
        assert result["AccessKeyId"] == "AKIAIOSFODNN7EXAMPLE"
        assert "SecretAccessKey" in result
        assert "SessionToken" in result
        assert "Expiration" in result

    def test_to_json_no_session_token(self) -> None:
        import json
        creds = Credentials(
            access_key_id="AKID",
            secret_access_key="SAK",
            session_token="",
            expiration="unknown",
            profile_name="static",
        )
        result = json.loads(creds.to_json())
        assert "SessionToken" not in result

    def test_to_env_vars(self, sample_creds: Credentials) -> None:
        result = sample_creds.to_env_vars()
        assert result["AWS_ACCESS_KEY_ID"] == "AKIAIOSFODNN7EXAMPLE"
        assert "AWS_SECRET_ACCESS_KEY" in result
        assert "AWS_SESSION_TOKEN" in result

    def test_to_env_vars_no_session_token(self) -> None:
        creds = Credentials(
            access_key_id="AKID",
            secret_access_key="SAK",
            session_token="",
            expiration="unknown",
            profile_name="static",
        )
        result = creds.to_env_vars()
        assert "AWS_SESSION_TOKEN" not in result


class TestListProfiles:
    def test_list_profiles(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config"
        config_file.write_text(textwrap.dedent("""\
            [default]
            region = us-east-1

            [profile dev]
            sso_start_url = https://my-sso.awsapps.com/start
            sso_region = us-east-1

            [profile prod]
            role_arn = arn:aws:iam::123456789012:role/Admin
            source_profile = dev
        """))

        with patch("aws_assume.core._get_aws_config_path", return_value=config_file):
            profiles = list_profiles()

        assert "default" in profiles
        assert "dev" in profiles
        assert "prod" in profiles

    def test_list_profiles_missing_file(self, tmp_path: Path) -> None:
        with patch("aws_assume.core._get_aws_config_path", return_value=tmp_path / "nonexistent"):
            profiles = list_profiles()
        assert profiles == []


class TestWriteCredentialsFile:
    def test_write_new_file(self, tmp_path: Path, sample_creds: Credentials) -> None:
        creds_file = tmp_path / "credentials"
        with patch("aws_assume.core._get_aws_credentials_path", return_value=creds_file):
            path = write_credentials_file(sample_creds, profile_name="dev")

        assert path == creds_file
        config = configparser.ConfigParser()
        config.read(creds_file)
        assert "dev" in config
        assert config["dev"]["aws_access_key_id"] == "AKIAIOSFODNN7EXAMPLE"

    def test_write_enforces_0600_permissions(
        self, tmp_path: Path, sample_creds: Credentials
    ) -> None:
        creds_file = tmp_path / "credentials"
        with patch("aws_assume.core._get_aws_credentials_path", return_value=creds_file):
            write_credentials_file(sample_creds, profile_name="dev")
        mode = creds_file.stat().st_mode & 0o777
        assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

    def test_write_preserves_existing_profiles(
        self, tmp_path: Path, sample_creds: Credentials
    ) -> None:
        creds_file = tmp_path / "credentials"
        creds_file.write_text(textwrap.dedent("""\
            [existing-profile]
            aws_access_key_id = EXISTINGKEY
            aws_secret_access_key = EXISTINGSECRET
        """))

        with patch("aws_assume.core._get_aws_credentials_path", return_value=creds_file):
            write_credentials_file(sample_creds, profile_name="new-profile")

        config = configparser.ConfigParser()
        config.read(creds_file)
        assert "existing-profile" in config
        assert "new-profile" in config
        assert config["existing-profile"]["aws_access_key_id"] == "EXISTINGKEY"
