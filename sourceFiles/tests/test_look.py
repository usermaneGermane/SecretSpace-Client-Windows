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
from theme import BG, GREEN


def _rgb(colour):
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
