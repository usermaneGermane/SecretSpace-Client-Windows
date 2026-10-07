"""
Palette, fonts and asset lookup.

Everything visual that more than one module needs lives here, so the colours
are defined in exactly one place.
"""

import os
import sys

import customtkinter as ctk

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

# CustomTkinter's Windows default draws rounded corners out of font glyphs,
# which costs ~60 ms per account row. Polygons -- its macOS default -- halve
# that, at the price of slightly less smoothed corners. Must be set before
# any widget is created.
from customtkinter.windows.widgets.core_rendering import DrawEngine
DrawEngine.preferred_drawing_method = "polygon_shapes"

HEADER_BG = "#202022"
CARD = "#2A2A2D"
CARD_HOVER = "#34343A"
INPUT_BG = "#2A2A2D"
BORDER = "#3A3A40"
TEXT = "#ECECEC"
MUTED = "#9B9BA3"
GREEN = "#67C090"
GREEN_HOVER = "#4EA877"
DANGER = "#E5534B"
DANGER_HOVER = "#C23B34"
ON_ACCENT = "#0E1A13"          # text drawn on top of the green accent
WARN = "#E0A030"

FONT = "Segoe UI"
MONO = "Consolas"

# Avatar colors cycled per account for a bit of visual variety.
AVATAR_PALETTE = ["#67C090", "#4F9DDE", "#E0A030", "#C97BD4",
                  "#E5705B", "#54B7A8", "#7E83E8", "#D98AB0"]


def F(size, weight="normal"):
    """Shorthand for a themed font."""
    return ctk.CTkFont(family=FONT, size=size, weight=weight)


def avatar_color(s):
    """Stable per-site avatar colour."""
    if not s:
        return GREEN
    return AVATAR_PALETTE[sum(ord(c) for c in s) % len(AVATAR_PALETTE)]


def asset_candidates(name):
    """Possible locations for a bundled asset: PyInstaller bundle, the script
    directory, the current dir, and the legacy dist/ folder."""
    paths = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        paths.append(os.path.join(meipass, name))
    paths.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), name))
    paths.append(name)
    paths.append(os.path.join("dist", name))
    return paths
