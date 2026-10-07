"""Generation and the strength estimator."""

import string

import pytest

from password_generator import generate_password, estimate_strength

ALL = string.ascii_letters + string.digits


def test_length_is_respected():
    for n in (6, 12, 20, 64):
        assert len(generate_password(n)) == n


def test_too_short_is_refused():
    with pytest.raises(ValueError):
        generate_password(5)


def test_every_selected_class_appears():
    for _ in range(50):
        pw = generate_password(12)
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(not c.isalnum() for c in pw)


def test_disabled_classes_are_absent():
    for _ in range(50):
        pw = generate_password(20, use_upper=False, use_symbols=False)
        assert pw.isalnum() and not any(c.isupper() for c in pw)


def test_passwords_do_not_repeat():
    assert len({generate_password(16) for _ in range(200)}) == 200


# --- the estimator used to rate twenty 'a's as Good -----------------------
@pytest.mark.parametrize("weak", [
    "aaaaaaaaaaaaaaaaaaaa",     # a single repeated character
    "abcdefghijklmnopqrst",     # an alphabet run
    "qwertyuiopqwertyuiop",     # a repeated keyboard walk
    "abcabcabcabcabcabc",       # a repeated block
    "Password1!", "P@ssw0rd", "letmein", "123456", "qwerty",
])
def test_structured_and_common_passwords_rate_weak(weak):
    assert estimate_strength(weak)[0] == "Weak"


@pytest.mark.parametrize("strong", [
    "correct horse battery staple",
    "9#mQ2$vB4!xR7&zL",
    "Tr0ub4dor&3xK!",
])
def test_genuinely_good_passwords_are_not_downgraded(strong):
    assert estimate_strength(strong)[0] in ("Good", "Strong")


def test_generated_passwords_rate_strong():
    assert {estimate_strength(generate_password(20))[0] for _ in range(100)} == {"Strong"}


def test_empty_password_has_no_label():
    assert estimate_strength("")[:2] == ("", 0.0)


def test_fraction_stays_in_range():
    for pw in ("a", "aaaa", "x" * 200, generate_password(64)):
        label, frac, color = estimate_strength(pw)
        assert 0.0 <= frac <= 1.0
        assert color.startswith("#")


def test_generation_does_not_require_a_clipboard(monkeypatch):
    """password_generator used to import pyperclip at module scope."""
    import sys
    monkeypatch.setitem(sys.modules, "pyperclip", None)
    assert len(generate_password(16)) == 16
