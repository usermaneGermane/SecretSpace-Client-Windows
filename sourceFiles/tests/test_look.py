"""
The look: smoothed corners and the painted login backdrop.

These guard the two things that made edges look rough: corners forced to
unsmoothed polygons, and backdrop shapes drawn straight on a Tk canvas.
"""
import pytest

pytest.importorskip("customtkinter")
pytest.importorskip("PIL")

import gui
import theme  # noqa: F401  (importing it applies the drawing settings)
from theme import BG, GREEN, pick


def _rgb(colour):
    colour = pick(colour)             # the pair's colour for the mode in use
    return tuple(int(colour[i:i + 2], 16) for i in (1, 3, 5))


def _near(pixel, colour, slack=8):
    """Scaling down overshoots a pure colour by a shade or two."""
    return all(abs(a - b) <= slack for a, b in zip(pixel, _rgb(colour)))


def test_corners_are_not_forced_to_polygons():
    from customtkinter.windows.widgets.core_rendering import DrawEngine
    assert DrawEngine.preferred_drawing_method != "polygon_shapes"


def test_backdrop_has_the_size_asked_for():
    assert gui.backdrop_picture(900, 600).size == (900, 600)


@pytest.mark.parametrize("size", [(0, 0), (1, 1), (1, 400), (400, 1)])
def test_no_backdrop_before_the_window_has_a_size(size):
    assert gui.backdrop_picture(*size) is None


def test_backdrop_edges_are_smoothed():
    """Between the padlock's green and the background lie blended pixels."""
    w, h = 900, 600
    picture = gui.backdrop_picture(w, h)
    x, y = round(w * 0.86), round(h * 0.2)
    lock = picture.crop((x - 34, y - 40, x + 34, y + 42))
    colours = {c for _, c in lock.getcolors(maxcolors=100000)}
    assert any(_near(c, GREEN) for c in colours)
    assert any(_near(c, BG) for c in colours)
    blends = [c for c in colours if not _near(c, GREEN) and not _near(c, BG)]
    assert len(blends) > 20


def test_padlock_body_has_round_corners():
    """The very corner of the body's box is background, not outline."""
    w, h = 900, 600
    picture = gui.backdrop_picture(w, h)
    x, y = round(w * 0.86), round(h * 0.2)
    assert _near(picture.getpixel((x - 26, y - 6)), BG)
    assert _near(picture.getpixel((x, y - 4)), GREEN)       # top edge, middle


# ---- light and dark ---------------------------------------------------------
PAIRS = ("BG", "HEADER_BG", "CARD", "CARD_HOVER", "SELECTED", "INPUT_BG",
         "BORDER", "TEXT", "MUTED", "GREEN", "GREEN_HOVER", "ACCENT_DEEP",
         "DANGER", "DANGER_HOVER", "ON_ACCENT", "WARN")


@pytest.fixture
def mode():
    """Set an appearance for one test, and put the old one back."""
    import customtkinter as ctk
    before = ctk.get_appearance_mode()
    yield theme.apply_appearance
    ctk.set_appearance_mode(before)


@pytest.mark.parametrize("name", PAIRS)
def test_every_colour_is_a_light_and_dark_pair(name):
    light, dark = getattr(theme, name)
    for colour in (light, dark):
        assert len(colour) == 7 and colour.startswith("#")
        int(colour[1:], 16)


def test_pick_follows_the_mode(mode):
    mode("light")
    assert pick(theme.BG) == theme.BG[0] and not theme.is_dark()
    mode("dark")
    assert pick(theme.BG) == theme.BG[1] and theme.is_dark()
    assert pick("#123456") == "#123456"          # a plain colour stays


def test_an_unknown_appearance_means_system(mode):
    import customtkinter as ctk
    mode("purple")
    assert ctk.get_appearance_mode() in ("Light", "Dark")


@pytest.mark.parametrize("which", ["light", "dark"])
def test_backdrop_is_painted_in_the_mode_in_use(mode, which):
    mode(which)
    picture = gui.backdrop_picture(900, 600)
    assert _near(picture.getpixel((450, 300)), theme.BG)


def _luminance(colour):
    def lin(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (int(colour[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def _contrast(a, b):
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


@pytest.mark.parametrize("i", [0, 1])
@pytest.mark.parametrize("ink,ground", [
    ("TEXT", "BG"), ("TEXT", "CARD"), ("TEXT", "INPUT_BG"), ("MUTED", "BG"),
    ("MUTED", "CARD"), ("MUTED", "INPUT_BG"), ("ON_ACCENT", "GREEN"),
    ("GREEN", "CARD"), ("WARN", "CARD"), ("TEXT", "SELECTED")])
def test_text_is_readable_on_its_ground(ink, ground, i):
    """WCAG AA for body text: 4.5 to 1, in light (0) and dark (1)."""
    assert _contrast(getattr(theme, ink)[i], getattr(theme, ground)[i]) >= 4.5


def test_tile_letters_are_readable():
    for tile, letter, band in theme.TILE_PALETTE:
        assert _contrast(tile, letter) >= 4.5
        assert len(band) == 2


def test_the_bundled_font_is_used():
    """The files are in the checkout, so the fallback must not be in use."""
    import os
    here = os.path.dirname(os.path.abspath(theme.__file__))
    assert all(os.path.isfile(os.path.join(here, f)) for f in theme.FONT_FILES)
    assert theme.FONT == "Manrope"
