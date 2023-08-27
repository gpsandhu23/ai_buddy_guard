import pytest
from ai_buddy_guard.core.core import check_credentials_in_repo, check_git_depdency_cves, invalidate_aws_key, inform_SOC, get_public_buckets, check_aws_mfa

def test_check_credentials_in_repo():
    # Assuming a test repository with known results
    test_repo = "https://github.com/test/repo.git"
    expected_result = "No leaked credentials found."
    assert check_credentials_in_repo(test_repo) == expected_result

def test_check_git_depdency_cves():
    # Assuming a test repository with known results
    test_repo = "https://github.com/test/repo.git"
    expected_result = "No out-of-date dependencies with security issues found."
    assert check_git_depdency_cves(test_repo) == expected_result

def test_invalidate_aws_key():
    # Assuming a test AWS access key
    test_access_key = "AKIAxxxxxxxxxxxxx"
    expected_result = "AWS Key invalidated successfully."
    assert invalidate_aws_key(test_access_key) == expected_result

def test_inform_SOC():
    # Assuming a test message
    test_message = "Test message."
    expected_result = "Message posted successfully."
    assert inform_SOC(test_message) == expected_result

def test_get_public_buckets():
    # Assuming a test AWS account name
    test_aws_account_name = "test_account"
    expected_result = []
    assert get_public_buckets(test_aws_account_name) == expected_result

def test_check_aws_mfa():
    # Assuming a test AWS account name
    test_account = "test_account"
    expected_result = []
    assert check_aws_mfa(test_account) == expected_result
