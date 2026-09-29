import pytest

from script_inventory.kb import advisories_for, advisory_table
from script_inventory.versions import compare_versions, in_range, parse_version


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("3.5.0", "3.5.0", 0),
        ("3.5", "3.5.0", 0),
        ("3.4.1", "3.5.0", -1),
        ("3.10.0", "3.9.9", 1),
        ("v1.8.2", "1.8.2", 0),
        ("4.0.0-beta.2", "4.0.0", -1),
        ("4.0.0-beta.2", "4.0.0-alpha", 1),
        ("1.2.3.4", "1.2.3", 1),
    ],
)
def test_compare(a, b, expected):
    assert compare_versions(a, b) == expected


def test_unparsable():
    assert parse_version("latest") is None
    assert not in_range("latest", None, "9.0.0")
    with pytest.raises(ValueError):
        compare_versions("x", "1.0.0")


def test_range_bounds():
    assert in_range("3.4.1", "1.2.0", "3.5.0")
    assert not in_range("3.5.0", "1.2.0", "3.5.0")
    assert not in_range("1.1.4", "1.2.0", "3.5.0")
    assert in_range("0.1.0", None, "1.0.0")


def ids(lib, version):
    return {a.id for a in advisories_for(lib, version)}


def test_jquery_advisories():
    assert {"CVE-2020-11022", "CVE-2020-11023"} <= ids("jquery", "3.4.1")
    assert "CVE-2019-11358" in ids("jquery", "3.3.1")
    assert "CVE-2019-11358" not in ids("jquery", "3.4.1")
    assert ids("jquery", "3.5.0") == set()
    assert ids("jquery", "3.7.1") == set()


def test_bootstrap_advisories():
    assert "CVE-2019-8331" in ids("bootstrap", "3.4.0")
    assert "CVE-2019-8331" not in ids("bootstrap", "3.4.1")
    assert "CVE-2019-8331" in ids("bootstrap", "4.3.0")
    assert "CVE-2019-8331" not in ids("bootstrap", "4.3.1")
    assert ids("bootstrap", "4.6.2") == {"EOL"}
    assert ids("bootstrap", "5.3.3") == set()


def test_lodash_moment_angularjs_vue():
    assert "CVE-2021-23337" in ids("lodash", "4.17.20")
    assert ids("lodash", "4.17.21") == set()
    assert "CVE-2022-31129" in ids("moment", "2.29.3")
    assert ids("moment", "2.29.4") == set()
    assert ids("angularjs", "1.8.3") == {"EOL"}
    assert ids("vue", "2.7.16") == {"EOL"}
    assert ids("vue", "3.4.0") == set()


def test_unknown_version_has_no_advisories():
    assert advisories_for("jquery", None) == []


def test_every_advisory_has_source_links():
    for a in advisory_table():
        assert a.references and all(r.startswith("https://") for r in a.references)
        assert a.affected
