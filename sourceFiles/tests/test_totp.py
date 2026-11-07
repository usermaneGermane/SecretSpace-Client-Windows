"""2FA codes: the RFC 6238 test vectors, and every form a secret is pasted in."""

import base64

import pytest

import totp

# RFC 6238, Appendix B: the seeds are these ASCII strings, codes have 8 digits.
SEEDS = {"SHA1": b"12345678901234567890",
         "SHA256": b"12345678901234567890123456789012",
         "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234"}
VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


def b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=")


@pytest.mark.parametrize("at,sha1,sha256,sha512", VECTORS)
def test_rfc_6238_vectors(at, sha1, sha256, sha512):
    for algorithm, expected in (("SHA1", sha1), ("SHA256", sha256),
                                ("SHA512", sha512)):
        params = totp.parse(f"otpauth://totp/RFC?secret={b32(SEEDS[algorithm])}"
                            f"&digits=8&algorithm={algorithm}")
        assert totp.code(params, at) == expected, algorithm


def test_plain_secret_is_six_digits_every_30_seconds_sha1():
    params = totp.parse(b32(SEEDS["SHA1"]))
    assert params.digits == 6 and params.period == 30
    assert params.algorithm == "SHA1"
    # The RFC's 8-digit SHA-1 code at t=59 ends in these six digits.
    assert totp.code(params, 59) == "287082"


@pytest.mark.parametrize("pasted", [
    "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",        # as sites show it
    "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",               # lower case
    "GEZDG-NBVGY-3TQOJ-QGEZD-GNBVG-Y3TQO-JQ",         # dashes
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",           # padded
    "  GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n",           # pasted with whitespace
])
def test_secrets_are_accepted_as_people_paste_them(pasted):
    assert totp.parse(pasted).key == SEEDS["SHA1"]


def test_otpauth_link_with_label_and_issuer():
    link = ("otpauth://totp/Google%3Aalex%40gmail.com?secret="
            + b32(SEEDS["SHA1"]) + "&issuer=Google&period=60&digits=7")
    params = totp.parse(link)
    assert (params.digits, params.period) == (7, 60)
    assert len(totp.code(params, 0)) == 7


@pytest.mark.parametrize("bad,words", [
    ("", "empty"),
    ("NOT-A-SECRET-1!", "A-Z"),
    ("ABC0DEF1", "A-Z"),                              # 0, 1 are not base32
    ("JBSWY3DP", "too short"),
    ("otpauth://hotp/x?secret=" + b32(SEEDS["SHA1"]), "time-based"),
    ("otpauth://totp/x?issuer=Google", "no secret"),
    ("otpauth://totp/x?secret=" + b32(SEEDS["SHA1"]) + "&algorithm=MD5",
     "not supported"),
    ("otpauth://totp/x?secret=" + b32(SEEDS["SHA1"]) + "&digits=4", "6 to 8"),
    ("otpauth://totp/x?secret=" + b32(SEEDS["SHA1"]) + "&period=abc",
     "not a number"),
])
def test_a_bad_secret_says_why(bad, words):
    with pytest.raises(ValueError, match=words):
        totp.parse(bad)
    assert words.split()[0] in totp.check(bad) or bad == ""


def test_check_is_quiet_for_empty_and_good_secrets():
    assert totp.check("") == ""
    assert totp.check("   ") == ""
    assert totp.check(b32(SEEDS["SHA1"])) == ""


def test_seconds_left_counts_down_within_the_period():
    params = totp.parse(b32(SEEDS["SHA1"]))
    assert totp.seconds_left(params, 0) == 30
    assert totp.seconds_left(params, 29.5) == 1
    assert totp.seconds_left(params, 30) == 30
    assert totp.seconds_left(params, 41) == 19


def test_the_code_changes_only_at_the_period_boundary():
    params = totp.parse(b32(SEEDS["SHA1"]))
    assert totp.code(params, 30) == totp.code(params, 59.9)
    assert totp.code(params, 59.9) != totp.code(params, 60)


def test_spaced_for_reading():
    assert totp.spaced("123456") == "123 456"
    assert totp.spaced("1234567") == "1234 567"
    assert totp.spaced("12345678") == "1234 5678"
