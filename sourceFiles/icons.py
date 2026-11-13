"""
The app's icons, drawn here.

A dozen line icons on a 24-unit grid, one stroke width, round ends. They are
drawn with Pillow instead of shipped as files, so there is one look, no
licence to carry, and each comes in the light and the dark text colour.
:func:`icon` gives a CustomTkinter image that follows the appearance mode.
"""

import customtkinter as ctk
from PIL import Image, ImageDraw

from theme import TEXT

GRID = 24            # the units the shapes below are written in
STROKE = 1.8         # line width, in those units
OVERSAMPLE = 4       # drawn this much larger, then scaled down: smooth edges
HIDPI = 2            # pixels per point kept in the image, for scaled screens


class _Pen:
    """Draws in grid units onto an oversampled image."""

    def __init__(self, pixels, colour):
        self.scale = pixels * OVERSAMPLE / GRID
        self.colour = colour
        self.width = max(1, round(STROKE * self.scale))
        self.image = Image.new("RGBA", (pixels * OVERSAMPLE,) * 2, (0, 0, 0, 0))
        self.draw = ImageDraw.Draw(self.image)

    def _p(self, x, y):
        return (x * self.scale, y * self.scale)

    def _box(self, x0, y0, x1, y1):
        return [x0 * self.scale, y0 * self.scale, x1 * self.scale, y1 * self.scale]

    def dot(self, x, y, r=STROKE / 2):
        self.draw.ellipse(self._box(x - r, y - r, x + r, y + r), fill=self.colour)

    def line(self, *points, closed=False):
        """A stroke through the points, with round ends and joints."""
        points = list(points) + ([points[0]] if closed else [])
        self.draw.line([self._p(x, y) for x, y in points], fill=self.colour,
                       width=self.width, joint="curve")
        for x, y in points:
            self.dot(x, y)

    def circle(self, x, y, r):
        self.draw.ellipse(self._box(x - r, y - r, x + r, y + r),
                          outline=self.colour, width=self.width)

    def arc(self, x0, y0, x1, y1, start, end):
        """Angles as Pillow has them: clockwise from three o'clock."""
        self.draw.arc(self._box(x0, y0, x1, y1), start, end, fill=self.colour,
                      width=self.width)

    def box(self, x0, y0, x1, y1, r=2):
        self.draw.rounded_rectangle(self._box(x0, y0, x1, y1),
                                    radius=r * self.scale,
                                    outline=self.colour, width=self.width)


def _plus(p):
    p.line((12, 5), (12, 19))
    p.line((5, 12), (19, 12))


def _vaults(p):
    p.line((12, 3), (3, 8), (12, 13), (21, 8), closed=True)
    p.line((3, 13), (12, 18), (21, 13))


def _archive(p):
    p.box(3, 4, 21, 9, r=1.5)
    p.line((5, 9), (5, 20), (19, 20), (19, 9))
    p.line((10, 13.5), (14, 13.5))


def _key(p):
    p.circle(8, 16, 4.2)
    p.line((11, 13), (20, 4))
    p.line((16.5, 7.5), (19, 10))
    p.line((19, 5), (21, 7))


def _import(p):
    p.line((12, 3.5), (12, 15))
    p.line((7, 10), (12, 15), (17, 10))
    p.line((4, 20), (20, 20))


def _settings(p):
    p.line((4, 7), (12.5, 7))
    p.line((19.5, 7), (20, 7))
    p.circle(16, 7, 2.6)
    p.line((4, 17), (4.5, 17))
    p.line((11.5, 17), (20, 17))
    p.circle(8, 17, 2.6)


def _sync(p):
    p.arc(4, 4, 20, 20, 195, 345)
    p.line((20, 4.5), (20, 10), (14.5, 10))
    p.arc(4, 4, 20, 20, 15, 165)
    p.line((4, 19.5), (4, 14), (9.5, 14))


def _lock(p):
    p.box(5, 11, 19, 20.5, r=2.2)
    p.arc(8, 3.5, 16, 12.5, 180, 360)
    p.line((8, 8), (8, 11))
    p.line((16, 8), (16, 11))


def _copy(p):
    p.box(9, 9, 20, 20, r=2.2)
    p.line((5, 15), (5, 5), (15, 5))


def _edit(p):
    p.line((4, 20), (5, 16), (16, 5), (19, 8), (8, 19), closed=True)


def _people(p):
    p.circle(9, 8, 3.5)
    p.arc(2.5, 14.5, 15.5, 27.5, 180, 360)
    p.arc(13, 4.5, 20, 11.5, 270, 90)
    p.arc(11.5, 14.8, 21.5, 27, 290, 360)


def _activity(p):
    p.line((3, 12), (7, 12), (10, 4.5), (14, 19.5), (17, 12), (21, 12))


SHAPES = {
    "plus": _plus, "vaults": _vaults, "archive": _archive, "key": _key,
    "import": _import, "settings": _settings, "sync": _sync, "lock": _lock,
    "copy": _copy, "edit": _edit, "people": _people, "activity": _activity,
}


def picture(name, colour, pixels):
    """One icon as a Pillow image of ``pixels`` square, in ``colour``."""
    pen = _Pen(pixels, colour)
    SHAPES[name](pen)
    return pen.image.resize((pixels, pixels), Image.LANCZOS)


_cache = {}


def icon(name, size=18, colour=TEXT):
    """
    The icon as an image for a CustomTkinter widget: ``size`` points square,
    in the pair's light or dark colour, whichever mode is in use.
    """
    key = (name, size, tuple(colour))
    if key not in _cache:
        light, dark = colour
        _cache[key] = ctk.CTkImage(
            light_image=picture(name, light, size * HIDPI),
            dark_image=picture(name, dark, size * HIDPI), size=(size, size))
    return _cache[key]
