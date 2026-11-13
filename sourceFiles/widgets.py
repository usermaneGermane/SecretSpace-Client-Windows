"""
Reusable widgets and modal plumbing, free of application state.

Each function takes the widget it should build into, so these can be used from
gui.py and dialogs.py alike without either importing the other.

Every dialog is built the same way since 2.9.0, to match the main window:
:func:`dialog_shell` gives it a header band (title, optional site tile), a
body, and a footer bar for its buttons; :func:`section` groups settings into
cards like the details card's.
"""

import tkinter as tk
from types import SimpleNamespace

import customtkinter as ctk

from theme import (tile_colors, strength_color, F, FONT, BG, HEADER_BG, CARD, TEXT, MUTED, GREEN,
                   GREEN_HOVER, DANGER, DANGER_HOVER, INPUT_BG, BORDER,
                   CARD_HOVER, ON_ACCENT)
from password_generator import estimate_strength

#: Side padding inside every dialog.
PAD = 28

#: Segments in a strength meter -- the details card and the dialogs alike.
STRENGTH_SEGMENTS = 5


class Tooltip:
    """Lightweight hover tooltip that works on any tk/ctk widget."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _show(self, _=None):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + self.widget.winfo_width() // 2
        y = self.widget.winfo_rooty() - 30
        self.tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tw.attributes("-topmost", True)
        lbl = tk.Label(tw, text=self.text, bg="#16181D", fg="#F0F1F4",
                       padx=9, pady=4, font=(FONT, 9), bd=0)
        lbl.pack()

    def _hide(self, _=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


# ---------------------------------------------------------------------------
# Buttons
# ---------------------------------------------------------------------------
def ghost_button(parent, text, command, width=120, danger=False):
    return ctk.CTkButton(
        parent, text=text, command=command, width=width, height=40,
        corner_radius=10, fg_color="transparent", border_width=1,
        border_color=BORDER, hover_color=CARD_HOVER,
        text_color=DANGER if danger else TEXT, font=F(13, "bold"),
    )


def accent_button(parent, text, command, width=140):
    return ctk.CTkButton(
        parent, text=text, command=command, width=width, height=40,
        corner_radius=10, fg_color=GREEN, hover_color=GREEN_HOVER,
        text_color=ON_ACCENT, font=F(13, "bold"),
    )


def danger_button(parent, text, command, width=130):
    return ctk.CTkButton(
        parent, text=text, command=command, width=width, height=40,
        corner_radius=10, fg_color=DANGER, hover_color=DANGER_HOVER,
        text_color="white", font=F(13, "bold"),
    )


def even_width(widget, holder):
    """
    Fill ``holder`` (a frame of the widget's height, with nothing else in
    it) with ``widget``, an even number of pixels wide. Smoothed corners are
    drawn for even sizes only; at an odd width a bright button shows a
    one-pixel step down its right edge.

    The widget is placed, not packed: its width must not feed back into
    the layout that decides the holder's.
    """
    def fit(event):
        try:
            # winfo sizes are physical pixels; CTk wants its own points.
            scale = widget._get_widget_scaling()
        except Exception:
            scale = 1
        want = (event.width // 2 * 2) / scale
        if abs(widget.cget("width") - want) > 0.01:
            widget.configure(width=want)
    widget.place(x=0, y=0)
    holder.bind("<Configure>", fit, add="+")


def small_button(parent, text, command, accent=False, danger=False, width=72):
    """The compact button of list rows (archive) -- same as the details card's."""
    return ctk.CTkButton(
        parent, text=text, command=command, width=width, height=34,
        corner_radius=10,
        fg_color=GREEN if accent else "transparent",
        hover_color=GREEN_HOVER if accent else CARD_HOVER,
        border_width=0 if accent else 1, border_color=BORDER,
        text_color=ON_ACCENT if accent else (DANGER if danger else TEXT),
        font=F(12, "bold"))


# ---------------------------------------------------------------------------
# Form parts
# ---------------------------------------------------------------------------
def field_label(parent, text):
    lbl = ctk.CTkLabel(parent, text=text, anchor="w", font=F(12, "bold"),
                       text_color=MUTED)
    lbl.pack(anchor="w", pady=(14, 6))
    return lbl


def entry(parent, show=None, placeholder="", height=44, font=None):
    return ctk.CTkEntry(parent, height=height, corner_radius=12,
                        fg_color=INPUT_BG, border_width=1, border_color=BORDER,
                        show=show, font=font or F(14),
                        placeholder_text=placeholder)


def field(parent, label, show=None, placeholder=""):
    field_label(parent, label)
    e = entry(parent, show=show, placeholder=placeholder)
    e.pack(fill="x")
    return e


def note(parent, text, width, color=MUTED, size=12, pady=(0, 0)):
    """A paragraph that wraps at ``width`` (the space it has, in points)."""
    lbl = ctk.CTkLabel(parent, text=text, font=F(size), text_color=color,
                       wraplength=width, justify="left", anchor="w")
    lbl.pack(anchor="w", fill="x", pady=pady)
    return lbl


def error_label(parent, width):
    lbl = ctk.CTkLabel(parent, text="", font=F(12), text_color=DANGER,
                       wraplength=width, justify="left", anchor="w")
    lbl.pack(anchor="w", fill="x", pady=(10, 0))
    return lbl


def check(parent, text, width, checked=False):
    """
    A checkbox whose text wraps. CTkCheckBox draws its text on one line, so a
    long one ran off the side of the dialog; here the text is a label beside
    the box, and clicking it ticks the box all the same.
    """
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", pady=(14, 0))
    box = ctk.CTkCheckBox(row, text="", width=24, checkbox_width=22,
                          checkbox_height=22, fg_color=GREEN,
                          hover_color=GREEN_HOVER, border_color=MUTED)
    box.pack(side="left", anchor="n")
    lbl = ctk.CTkLabel(row, text=text, font=F(12), text_color=TEXT,
                       wraplength=width - 34, justify="left", anchor="w",
                       cursor="hand2")
    lbl.pack(side="left", fill="x", padx=(8, 0))
    lbl.bind("<Button-1>", lambda e: box.toggle())
    if checked:
        box.select()
    return box


def strength_widget(parent):
    """
    The 5-segment strength meter of the details card, live.
    Returns (frame, label, update(password)).
    """
    box = ctk.CTkFrame(parent, fg_color="transparent")
    box.pack(fill="x", pady=(12, 0))
    segments = []
    for _ in range(STRENGTH_SEGMENTS):
        seg = ctk.CTkFrame(box, width=10, height=6, corner_radius=3,
                           fg_color=BORDER)
        seg.pack(side="left", fill="x", expand=True, padx=(0, 4))
        segments.append(seg)
    label = ctk.CTkLabel(box, text="", width=64, anchor="e",
                         font=F(12, "bold"), text_color=MUTED)
    label.pack(side="left", padx=(6, 0))

    def update(password):
        name, frac, _ = estimate_strength(password)
        color = strength_color(name)
        lit = max(round(frac * STRENGTH_SEGMENTS), 1) if password else 0
        for n, seg in enumerate(segments):
            seg.configure(fg_color=color if n < lit else BORDER)
        label.configure(text=name if password else "", text_color=color)

    update("")
    return box, label, update


# ---------------------------------------------------------------------------
# Dialog layout
# ---------------------------------------------------------------------------
def _rule(parent):
    ctk.CTkFrame(parent, height=1, corner_radius=0,
                 fg_color=BORDER).pack(fill="x")


def avatar(parent, name, size=40):
    """A person's initial on a round pastel tile, the colour fixed by the
    name."""
    bg, ink, _ = tile_colors(name)
    # A frame of a fixed size with the letter placed in it: a label with
    # rounded corners grows sideways and the circle becomes an oval.
    disc = ctk.CTkFrame(parent, width=size, height=size,
                        corner_radius=size // 2, fg_color=bg)
    disc.pack_propagate(False)
    disc.grid_propagate(False)
    ctk.CTkLabel(disc, text=(name[:1].upper() or "?"), fg_color="transparent",
                 text_color=ink, font=F(size * 2 // 5, "bold")).place(
        relx=0.5, rely=0.5, anchor="center")
    return disc


def dialog_shell(top, title, subtitle="", tile=None, danger=False,
                 scroll=False, fit_exact=True, band=None):
    """
    Header band, body and footer bar for a dialog -- the top bar and the
    details card of the main window, in small.

    ``tile``      (letter, tile colour, letter colour): the site tile, as in
                  the list and the details card.
    ``scroll``    the body scrolls (long lists, Settings); the header and the
                  buttons stay put.
    ``fit_exact`` the window takes the height its content needs, so short
                  dialogs lose their empty middle. Scrolling ones keep theirs.
    ``band``      the header's colour, for a dialog about one thing that has
                  a tile (a vault, an entry): the band of its tile colours.

    Returns a namespace: ``body`` (build into it), ``buttons`` (the footer
    row), ``heading`` and ``tile`` (to change them live), ``text_width``
    (what a paragraph in the body can wrap at).
    """
    width = getattr(top, "pm_width", 460)
    top.pm_fit_exact = fit_exact and not scroll

    foot = ctk.CTkFrame(top, fg_color=HEADER_BG, corner_radius=0)
    foot.pack(side="bottom", fill="x")
    _rule(foot)
    buttons = ctk.CTkFrame(foot, fg_color="transparent")
    buttons.pack(fill="x", padx=PAD, pady=14)

    head = ctk.CTkFrame(top, fg_color=band or HEADER_BG, corner_radius=0)
    head.pack(side="top", fill="x")
    inner = ctk.CTkFrame(head, fg_color="transparent")
    inner.pack(fill="x", padx=PAD, pady=(20, 18))
    text_width = width - 2 * PAD
    tile_label = None
    if tile:
        letter, bg, ink = tile
        tile_label = ctk.CTkLabel(inner, text=letter, width=48, height=48,
                                  corner_radius=14, fg_color=bg,
                                  text_color=ink, font=F(20, "bold"))
        tile_label.pack(side="left", padx=(0, 16))
        text_width -= 64
    words = ctk.CTkFrame(inner, fg_color="transparent")
    words.pack(side="left", fill="x", expand=True)
    heading = ctk.CTkLabel(words, text=title, font=F(19, "bold"),
                           text_color=DANGER if danger else TEXT, anchor="w",
                           justify="left", wraplength=text_width)
    heading.pack(anchor="w")
    if subtitle:
        ctk.CTkLabel(words, text=subtitle, font=F(12),
                     text_color=TEXT if band else MUTED,
                     anchor="w", justify="left",
                     wraplength=text_width).pack(anchor="w", pady=(3, 0))
    if not band:
        _rule(head)

    if scroll:
        body = ctk.CTkScrollableFrame(top, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=(PAD - 6, 8), pady=(8, 8))
        body_width = width - 2 * PAD - 24
    else:
        body = ctk.CTkFrame(top, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=PAD, pady=(6, 22))
        body_width = width - 2 * PAD
    return SimpleNamespace(body=body, buttons=buttons, heading=heading,
                           tile=tile_label, text_width=body_width)


def section(parent, title, danger=False, first=False):
    """A titled card, like the details card's sections."""
    ctk.CTkLabel(parent, text=title, font=F(12, "bold"),
                 text_color=DANGER if danger else MUTED,
                 anchor="w").pack(anchor="w", pady=(10 if first else 22, 6))
    # A card needs no outline on the window colour; a dangerous one keeps
    # its red line.
    card = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=16,
                        border_width=1 if danger else 0, border_color=DANGER)
    card.pack(fill="x")
    return card


def setting_row(card, title, hint="", hint_width=240, first=False):
    """
    One row of a section card: what it is on the left (with a hint under
    it), the control on the right. Returns the frame for the control.
    """
    if not first:
        ctk.CTkFrame(card, height=1, corner_radius=0,
                     fg_color=BORDER).pack(fill="x", padx=16)
    row = ctk.CTkFrame(card, fg_color="transparent")
    row.pack(fill="x", padx=16, pady=14)
    row.grid_columnconfigure(0, weight=1)
    text = ctk.CTkFrame(row, fg_color="transparent")
    text.grid(row=0, column=0, sticky="w")
    ctk.CTkLabel(text, text=title, font=F(13, "bold"), text_color=TEXT,
                 anchor="w").pack(anchor="w")
    if hint:
        ctk.CTkLabel(text, text=hint, font=F(12), text_color=MUTED,
                     wraplength=hint_width, justify="left",
                     anchor="w").pack(anchor="w", pady=(2, 0))
    right = ctk.CTkFrame(row, fg_color="transparent")
    right.grid(row=0, column=1, sticky="e", padx=(12, 0))
    return right


def option_menu(parent, values, command, width=140):
    return ctk.CTkOptionMenu(
        parent, width=width, height=34, corner_radius=10, values=values,
        fg_color=INPUT_BG, button_color=BORDER, button_hover_color=CARD_HOVER,
        text_color=TEXT, font=F(12), dropdown_fg_color=CARD,
        dropdown_hover_color=CARD_HOVER, dropdown_text_color=TEXT,
        command=command)


# ---------------------------------------------------------------------------
# Modal plumbing
# ---------------------------------------------------------------------------
def fit_modal(root, top):
    """
    Size a modal to its content. The hardcoded sizes are only a starting
    point -- the height needed varies with Windows display scaling and font
    metrics, which used to cut off the bottom button row on scaled displays.

    A dialog that is too short always grows. One built with
    ``dialog_shell(fit_exact=True)`` also shrinks, so a short form does not
    sit in a tall, mostly empty window.
    """
    top.update_idletasks()
    need = top.winfo_reqheight()
    cur_w, cur_h = top.winfo_width(), top.winfo_height()
    if need == cur_h or (need < cur_h and not getattr(top, "pm_fit_exact",
                                                      False)):
        return
    x = root.winfo_rootx() + (root.winfo_width() - cur_w) // 2
    y = root.winfo_rooty() + (root.winfo_height() - need) // 2
    # Raw tkinter geometry: winfo_* values are physical pixels, and CTk's
    # geometry() would scale them a second time on high-DPI displays.
    tk.Toplevel.geometry(top, f"{cur_w}x{need}+{max(x, 0)}+{max(y, 0)}")


def safe_grab(root, top, icon_path=None):
    try:
        if icon_path:
            top.iconbitmap(icon_path)
    except Exception:
        pass
    try:
        fit_modal(root, top)
    except Exception:
        pass
    try:
        top.grab_set()
        top.focus()
    except Exception:
        pass


def modal(root, title, w, h, icon_path=None):
    top = ctk.CTkToplevel(root, fg_color=BG)
    top.title(title)
    top.resizable(False, False)
    top.pm_width = w
    root.update_idletasks()
    x = root.winfo_rootx() + (root.winfo_width() - w) // 2
    y = root.winfo_rooty() + (root.winfo_height() - h) // 2
    top.geometry(f"{w}x{h}+{max(x, 0)}+{max(y, 0)}")
    top.transient(root)
    # CTkToplevel needs a beat before it can grab / take an icon.
    top.after(120, lambda: safe_grab(root, top, icon_path))
    return top


def confirm(root, title, message, danger=True, icon_path=None):
    top = modal(root, title, 440, 240, icon_path)
    result = {"ok": False}
    shell = dialog_shell(top, title)
    note(shell.body, message, shell.text_width, color=TEXT, size=13,
         pady=(14, 0))

    def ok():
        result["ok"] = True
        top.destroy()

    ghost_button(shell.buttons, "Cancel", top.destroy,
                 width=120).pack(side="left")
    (danger_button(shell.buttons, "Delete", ok) if danger else
     accent_button(shell.buttons, "Confirm", ok, width=130)).pack(side="right")
    top.bind("<Return>", lambda e: ok())
    top.bind("<Escape>", lambda e: top.destroy())
    root.wait_window(top)
    return result["ok"]
