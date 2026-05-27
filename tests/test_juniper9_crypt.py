"""pytest suite for juniper9_crypt."""

import pytest

from juniper9_crypt import MAGIC, check, decrypt, encrypt, main


KNOWN_VECTORS = [
    ("$9$FNkC3/t1IcevLuOWx", "hello"),
    ("$9$a1Gjk5Qnp0I.P0IEcvMaZUjP5Ctu", "Juniper99"),
]

ROUNDTRIP_PLAINTEXTS = [
    "a",
    "hello",
    "L@bS3cr3t!",
    "4613b874e5",
    "0" * 20,
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    "!@#$%^&*()_+-=[]{}|;':\",./<>?",
]


@pytest.mark.parametrize("ciphertext,expected", KNOWN_VECTORS)
def test_decrypt_known_vectors(ciphertext: str, expected: str) -> None:
    assert decrypt(ciphertext) == expected


@pytest.mark.parametrize("plaintext", ROUNDTRIP_PLAINTEXTS)
def test_roundtrip(plaintext: str) -> None:
    assert decrypt(encrypt(plaintext)) == plaintext


def test_encrypt_starts_with_magic() -> None:
    assert encrypt("hello").startswith(MAGIC)


def test_encrypt_is_nondeterministic() -> None:
    results = {encrypt("test") for _ in range(20)}
    assert len(results) > 1


def test_decrypt_missing_magic() -> None:
    with pytest.raises(ValueError, match=r"\$9\$"):
        decrypt("plaintext")


def test_decrypt_empty_payload() -> None:
    with pytest.raises(ValueError, match="Empty"):
        decrypt("$9$")


def test_decrypt_invalid_start_char() -> None:
    with pytest.raises(ValueError, match="start character"):
        decrypt("$9$~~~~~")


def test_decrypt_invalid_payload_char() -> None:
    with pytest.raises(ValueError, match="not in"):
        decrypt("$9$Q~~~~~~~~~~~~~~~~~")


def test_check_against_plaintext() -> None:
    _, _, match = check(encrypt("s3cr3t"), "s3cr3t")
    assert match


def test_check_against_ciphertext_same_plaintext() -> None:
    a = encrypt("s3cr3t")
    b = encrypt("s3cr3t")
    assert a != b
    _, _, match = check(a, b)
    assert match


def test_check_against_ciphertext_different_plaintext() -> None:
    _, _, match = check(encrypt("foo"), encrypt("bar"))
    assert not match


def test_cli_decrypt(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--decrypt", "$9$FNkC3/t1IcevLuOWx"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "hello"


def test_cli_check_match_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--check", "$9$FNkC3/t1IcevLuOWx", "hello"])
    assert rc == 0


def test_cli_check_mismatch_exits_one(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--check", "$9$FNkC3/t1IcevLuOWx", "nope"])
    assert rc == 1


def test_cli_invalid_input_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--decrypt", "plaintext"])
    assert rc == 2
    assert "error" in capsys.readouterr().err
