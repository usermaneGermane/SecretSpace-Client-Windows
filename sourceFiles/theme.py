"""
Palette, fonts and asset lookup.

Everything visual that more than one module needs lives here, so the colours
are defined in exactly one place.

Every colour is a ``(light, dark)`` pair. CustomTkinter widgets take the pair
as it is and follow the appearance mode by themselves; a plain Tk widget or a
Pillow drawing needs one colour, which :func:`pick` chooses.
"""

import os
import sys

import customtkinter as ctk

#: What Settings offers. "system" follows Windows / the desktop.
APPEARANCES = ("system", "light", "dark")

ctk.set_appearance_mode("system")
ctk.set_default_color_theme("green")

# Rounded corners are drawn the way CustomTkinter prefers here: out of
# smoothed font glyphs. Until 3.0.0-alpha.4 polygons were forced instead,
# which are quicker (about 7 ms per account row, measured on CustomTkinter
# 6.0) but not smoothed at all -- every corner showed its pixel steps.

#                 light       dark
BG = ("#EDF0F4", "#15161A")              # the window itself
HEADER_BG = ("#E6EAEF", "#1A1C21")       # top bar, history panel
CARD = ("#FFFFFF", "#1F2127")            # cards and panels on top of BG
CARD_HOVER = ("#E9EDF2", "#2A2D36")
SELECTED = ("#DDF1E6", "#1F3128")        # the selected row in the account list
INPUT_BG = ("#F4F6F9", "#191B20")
BORDER = ("#DCE1E8", "#2E313A")
TEXT = ("#16181D", "#F0F1F4")
MUTED = ("#586170", "#A2A8B3")
GREEN = ("#0E7A47", "#56E39F")
GREEN_HOVER = ("#0B6239", "#3FCB87")
ACCENT_DEEP = ("#0E7A47", "#177A49")     # a selected choice under light text
DANGER = ("#C0362F", "#E5534B")
DANGER_HOVER = ("#9E2A24", "#C23B34")
ON_ACCENT = ("#FFFFFF", "#05230F")       # text drawn on top of the green accent
WARN = ("#8A5300", "#F2B955")

# The drawn login backdrop (Pillow / a Tk canvas: use pick()).
DECOR_DISC_A = ("#DCE8E1", "#17211B")
DECOR_DISC_B = ("#E1E6EB", "#1A1D21")
DECOR_DOT = ("#BFD3C7", "#26392E")
DECOR_INK = ("#3F9A6C", "#7BE0A6")

#: The app's typeface, bundled beside the program (SIL Open Font License,
#: Manrope-OFL.txt). FONT falls back when the files are missing.
FONT_FILES = ("Manrope-Regular.ttf", "Manrope-Bold.ttf")
FALLBACK_FONT = "Segoe UI"
MONO = "Consolas"

# Per-site tile colours: (tile, letter, header band). A pastel tile with a
# dark letter in both modes; only the band behind an open entry differs.
TILE_PALETTE = [
    ("#D5F2DD", "#0E4023", ("#E2F6E8", "#1D3527")),
    ("#FFE0C2", "#5C2E05", ("#FFEBD8", "#3D2C1B")),
    ("#E7DBFF", "#35206B", ("#EFE7FF", "#2B2547")),
    ("#FFD9E0", "#641328", ("#FFE6EA", "#3F2228")),
    ("#CFE3FF", "#12305E", ("#DCE9FF", "#22324D")),
    ("#D6EEF2", "#0C3F49", ("#E3F4F7", "#1C3338")),
]


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


def _load_fonts():
    """Make the bundled typeface known to Tk. True when every file loaded."""
    for name in FONT_FILES:
        path = next((p for p in asset_candidates(name) if os.path.isfile(p)),
                    None)
        try:
            if path is None or not ctk.FontManager.load_font(path):
                return False
        except Exception:
            return False
    return True


FONT = "Manrope" if _load_fonts() else FALLBACK_FONT


def F(size, weight="normal"):
    """Shorthand for a themed font."""
    return ctk.CTkFont(family=FONT, size=size, weight=weight)


def is_dark():
    return ctk.get_appearance_mode() == "Dark"


def pick(color):
    """One colour out of a ``(light, dark)`` pair, for what is not a
    CustomTkinter widget. A plain colour is returned as it is."""
    if isinstance(color, (tuple, list)):
        return color[1] if is_dark() else color[0]
    return color


def apply_appearance(mode):
    """Switch to "system", "light" or "dark"; anything else means system."""
    ctk.set_appearance_mode(mode if mode in APPEARANCES else "system")


def tile_colors(s):
    """Stable per-site (tile, letter, band) colours."""
    if not s:
        return TILE_PALETTE[0]
    return TILE_PALETTE[sum(ord(c) for c in s) % len(TILE_PALETTE)]
