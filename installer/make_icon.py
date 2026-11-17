"""
Draw the app's icon from the logo.

    py installer\\make_icon.py

Writes sourceFiles\\SecretSpace-logo.ico: the window, the taskbar, the Start
menu, the installer and Settings > Apps use it. The logo is cropped to its
shield (plus a margin), so at 16-24 px the shield fills the icon instead of
a few pixels of it, and given rounded corners, like an app tile. One frame
per size Windows asks for at 100 to 200 % display scaling, each drawn from
the full-size logo rather than scaled from another frame. Run it again after
the logo changes, and commit the icon; the build only reads it.
"""

import os

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "sourceFiles")
ICON = os.path.join(SRC, "SecretSpace-logo.ico")

#: 16/20/24/32/40/48/64: title bar, taskbar, Start and Explorer at 100-200 %
#: scaling; 128 and 256: large icons.
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
#: Room around the shield, as a share of the shield's own size.
MARGIN = 0.2
#: Corner radius, as a share of the side: the wizard's small picture's.
CORNER = 0.22


def tight_logo():
    """The logo cropped to a square around its shield (the bright pixels)."""
    image = Image.open(os.path.join(SRC, "SecretSpace-logo.png")).convert("RGBA")
    left, top, right, bottom = image.convert("L").point(
        lambda v: 255 if v > 40 else 0).getbbox()
    side = round(max(right - left, bottom - top) * (1 + MARGIN))
    x = (left + right) // 2 - side // 2
    y = (top + bottom) // 2 - side // 2
    return image.crop((x, y, x + side, y + side))


def frame(logo, size):
    image = logo.resize((size, size), Image.LANCZOS)
    big = size * 4                      # the mask drawn large, then reduced: smooth
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, big - 1, big - 1),
                                           radius=round(big * CORNER), fill=255)
    image.putalpha(mask.resize((size, size), Image.LANCZOS))
    return image


def main():
    logo = tight_logo()
    frames = [frame(logo, size) for size in SIZES]
    frames[-1].save(ICON, format="ICO", sizes=[(s, s) for s in SIZES],
                    append_images=frames[:-1])
    print("wrote", ICON, "with", ", ".join(str(s) for s in SIZES))


if __name__ == "__main__":
    main()
