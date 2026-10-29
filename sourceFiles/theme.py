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

BG = "#0A0C0B"                 # the window itself
HEADER_BG = "#101311"          # top bar, history panel
CARD = "#131715"               # cards and panels on top of BG
CARD_HOVER = "#1C231F"
SELECTED = "#18271E"           # the selected row in the account list
INPUT_BG = "#1A1F1C"
BORDER = "#27302A"
TEXT = "#E6EDE8"
MUTED = "#8E9A92"
GREEN = "#2BD47D"
GREEN_HOVER = "#22B169"
DANGER = "#E5534B"
DANGER_HOVER = "#C23B34"
ON_ACCENT = "#06110B"          # text drawn on top of the green accent
WARN = "#E3B341"

FONT = "Segoe UI"
MONO = "Consolas"

# Per-site tile colours: (tile, letter, header band). Dark tints with a light
# letter, so entries are told apart without breaking the black-and-green look.
TILE_PALETTE = [
    ("#173A27", "#8FF0B9", "#10291B"),
    ("#3A2C17", "#F2C27A", "#2A2213"),
    ("#2A2340", "#CBB8FF", "#1E1A30"),
    ("#3D1E22", "#FFA9B1", "#2D171A"),
    ("#172B3D", "#9CCBFF", "#12223A"),
    ("#222B35", "#B8C6D6", "#1A222B"),
]


def F(size, weight="normal"):
    """Shorthand for a themed font."""
    return ctk.CTkFont(family=FONT, size=size, weight=weight)


def tile_colors(s):
    """Stable per-site (tile, letter, band) colours."""
    if not s:
        return TILE_PALETTE[0]
    return TILE_PALETTE[sum(ord(c) for c in s) % len(TILE_PALETTE)]


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
