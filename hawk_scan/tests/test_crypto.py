import pytest
from hawk_scan.web.crypto import encrypt_credentials, decrypt_credentials


def test_roundtrip():
    secret = "test-secret-key-for-encryption"
    username = "DOMAIN\\admin"
    password = "s3cret!"
    encrypted = encrypt_credentials(username, password, secret)
    assert isinstance(encrypted, str)
    assert password not in encrypted
    result_user, result_pass = decrypt_credentials(encrypted, secret)
    assert result_user == username
    assert result_pass == password


def test_wrong_key_fails():
    secret = "correct-key"
    wrong = "wrong-key"
    encrypted = encrypt_credentials("user", "pass", secret)
    with pytest.raises(Exception):
        decrypt_credentials(encrypted, wrong)


def test_different_inputs_different_outputs():
    secret = "test-key"
    enc1 = encrypt_credentials("user", "pass1", secret)
    enc2 = encrypt_credentials("user", "pass2", secret)
    assert enc1 != enc2
