"""pwhash 核心契约的验收测试。

对应题面列出的十类安全缺陷，外加五条基础正确性断言。测试只使用标准库与
pytest，熵源全部显式传入，不依赖时钟或系统随机。
"""

import base64
import hashlib

import pytest

from pwhash import hash as pwhash_hash
from pwhash.hash import (
    decode,
    derive,
    encode,
    hash_batch,
    needs_rehash,
    salt_bytes,
    validate_policy,
    verify,
)


class CounterEntropy:
    """确定性熵源：第 n 次调用返回 n 个重复字节，共 size 字节。"""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, size: int) -> bytes:
        self.calls += 1
        return bytes([self.calls]) * size


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def test_salt_bytes_uses_entropy_and_stays_unique() -> None:
    fixed = salt_bytes(lambda size: b"A" * size, 16)
    assert fixed == b"A" * 16

    source = CounterEntropy()
    first = salt_bytes(source, 16)
    second = salt_bytes(source, 16)
    assert len(first) == 16
    assert len(second) == 16
    assert first != second

    assert len(salt_bytes(lambda size: b"B" * size, 24)) == 24
    with pytest.raises(ValueError):
        salt_bytes(lambda size: b"C" * size, 15)


def test_derive_honours_requested_iterations() -> None:
    password = "correct horse battery staple"
    salt = b"0123456789abcdef"
    expected = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100_000, 32
    )
    assert derive(password, salt, 100_000) == expected
    assert derive(password, salt, 100_001) != expected
    with pytest.raises(ValueError):
        derive(password, salt, 50_000)


def test_derive_keeps_password_and_salt_separate() -> None:
    left = derive("ab", b"cdefghijklmnopqrs", 100_000)
    right = derive("abc", b"defghijklmnopqrs", 100_000)
    assert left != right


def test_encode_records_algorithm_name() -> None:
    salt = b"\x00" * 16
    digest = b"\x01" * 32
    encoded = encode(salt, digest, 100_000)
    assert encoded.split("$")[0] == "pbkdf2_sha256"
    assert encoded.count("$") == 3

    record = decode(encoded)
    assert record["algorithm"] == "pbkdf2_sha256"
    assert record["iterations"] == 100_000
    assert record["salt"] == salt
    assert record["digest"] == digest


def test_decode_rejects_iterations_below_floor() -> None:
    salt = b"\x02" * 16
    digest = b"\x03" * 32
    weak = "pbkdf2_sha256$1$" + b64(salt) + "$" + b64(digest)
    with pytest.raises(ValueError):
        decode(weak)


def test_verify_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    password = "s3cret-pw"
    salt = b"\x04" * 16
    encoded = encode(salt, derive(password, salt, 100_000), 100_000)

    calls = []
    real_compare = pwhash_hash.hmac.compare_digest

    def spy(left: bytes, right: bytes) -> bool:
        calls.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(pwhash_hash.hmac, "compare_digest", spy)
    assert verify(password, encoded) is True
    assert calls, "verify 必须使用 hmac.compare_digest 做恒定时间比较"


def test_verify_returns_false_for_invalid_record() -> None:
    salt = b"\x05" * 16
    digest = b"\x06" * 32
    invalid_records = [
        "",
        "not-a-record",
        "pbkdf2_sha256$100000$!!!!$!!!!",
        "pbkdf2_sha256$100000$AAAA$AAAA",
        "md5$100000$" + b64(salt) + "$" + b64(digest),
        "pbkdf2_sha256$1$" + b64(salt) + "$" + b64(digest),
    ]
    for record in invalid_records:
        assert verify("s3cret-pw", record) is False


def test_needs_rehash_detects_low_iterations() -> None:
    salt = b"\x07" * 16
    digest = b"\x08" * 32
    policy = {"algorithm": "pbkdf2_sha256", "iterations": 150_000, "salt_bytes": 16}

    weak = encode(salt, digest, 100_000)
    strong = encode(salt, digest, 150_000)
    foreign = "argon2id$150000$" + b64(salt) + "$" + b64(digest)

    assert needs_rehash(weak, policy) is True
    assert needs_rehash(strong, policy) is False
    assert needs_rehash(foreign, policy) is True


def test_validate_policy_checks_salt_length() -> None:
    valid = {"algorithm": "pbkdf2_sha256", "iterations": 100_000, "salt_bytes": 16}
    assert validate_policy(valid) == []
    assert validate_policy({**valid, "salt_bytes": 8}) == ["salt_too_short"]
    assert validate_policy({**valid, "iterations": 99_999}) == ["iterations_too_low"]
    assert validate_policy({**valid, "algorithm": "md5"}) == ["unknown_algorithm"]


def test_batch_uses_unique_salt_per_record() -> None:
    records = [
        {"username": "alice", "password": "alice-pw"},
        {"username": "bob", "password": "bob-pw"},
        {"username": "carol", "password": "carol-pw"},
    ]
    policy = {
        "algorithm": "pbkdf2_sha256",
        "iterations": 100_000,
        "salt_bytes": 16,
        "entropy": CounterEntropy(),
    }
    result = hash_batch(records, policy)
    assert set(result) == {"alice", "bob", "carol"}

    salts = [decode(result[record["username"]])["salt"] for record in records]
    assert len(set(salts)) == 3
    assert all(len(salt) == 16 for salt in salts)


def test_derive_is_deterministic_for_same_inputs() -> None:
    salt = b"fedcba9876543210"
    first = derive("same-password", salt, 100_000)
    second = derive("same-password", salt, 100_000)
    assert first == second
    assert len(first) == 32


def test_derive_changes_with_salt() -> None:
    first = derive("same-password", b"0123456789abcdef", 100_000)
    second = derive("same-password", b"fedcba9876543210", 100_000)
    assert first != second


def test_verify_accepts_correct_password_and_rejects_one_char_off() -> None:
    salt = salt_bytes(lambda size: b"\x09" * size, 16)
    encoded = encode(salt, derive("s3cret", salt, 100_000), 100_000)
    assert verify("s3cret", encoded) is True
    assert verify("s3creT", encoded) is False


def test_encode_rejects_iterations_below_floor() -> None:
    with pytest.raises(ValueError):
        encode(b"\x0a" * 16, b"\x0b" * 32, 99_999)


def test_batch_matches_individual_processing() -> None:
    records = [
        {"username": "u1", "password": "p1"},
        {"username": "u2", "password": "p2"},
    ]
    policy = {
        "algorithm": "pbkdf2_sha256",
        "iterations": 100_000,
        "salt_bytes": 16,
        "entropy": CounterEntropy(),
    }
    batch = hash_batch(records, policy)

    source = CounterEntropy()
    individual = {}
    for record in records:
        salt = salt_bytes(source, 16)
        digest = derive(record["password"], salt, 100_000)
        individual[record["username"]] = encode(salt, digest, 100_000)

    assert batch == individual
