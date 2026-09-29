import base64
import hashlib

from script_inventory.sri import check_integrity, parse_integrity, sri_hash

BODY = b"alert(1);"


def b64(algo, body=BODY):
    return base64.b64encode(hashlib.new(algo, body).digest()).decode()


def test_sri_hash_matches_manual_computation():
    assert sri_hash(BODY, "sha256") == "sha256-" + b64("sha256")
    assert sri_hash(BODY) == "sha384-" + b64("sha384")


def test_absent_and_blank():
    assert check_integrity(None, BODY)[0] == "absent"
    assert check_integrity("   ", BODY)[0] == "absent"


def test_valid_each_algorithm():
    for algo in ("sha256", "sha384", "sha512"):
        assert check_integrity(f"{algo}-{b64(algo)}", BODY) == ("valid", algo)


def test_invalid_reports_actual_hash():
    status, detail = check_integrity("sha384-" + b64("sha384", b"other"), BODY)
    assert status == "invalid"
    assert sri_hash(BODY, "sha384") in detail


def test_only_strongest_algorithm_counts():
    # A correct sha256 does not rescue a wrong sha512 (W3C SRI "strongest metadata").
    value = f"sha256-{b64('sha256')} sha512-{b64('sha512', b'x')}"
    assert check_integrity(value, BODY)[0] == "invalid"
    # Any matching digest of the strongest algorithm is enough.
    value = f"sha512-{b64('sha512', b'x')} sha512-{b64('sha512')}"
    assert check_integrity(value, BODY)[0] == "valid"


def test_unknown_algorithms_and_options_ignored():
    assert parse_integrity("md5-abc sha384-xyz?opt sha1-q") == [("sha384", "xyz")]
    assert check_integrity("md5-abcdef", BODY)[0] == "malformed"
    assert check_integrity(f"sha256-{b64('sha256')}?foo=bar", BODY)[0] == "valid"


def test_base64url_and_missing_padding_accepted():
    digest = b64("sha256").replace("+", "-").replace("/", "_").rstrip("=")
    assert check_integrity(f"sha256-{digest}", BODY)[0] == "valid"


def test_unverified_without_body():
    assert check_integrity(f"sha256-{b64('sha256')}", None)[0] == "unverified"
