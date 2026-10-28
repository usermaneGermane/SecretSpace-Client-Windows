"""
Reusable widgets and modal plumbing, free of application state.

Each function takes the widget it should build into, so these can be used from
gui.py and dialogs.py alike without either importing the other.
"""

import tkinter as tk

import customtkinter as ctk

from theme import (F, FONT, BG, TEXT, MUTED, GREEN, GREEN_HOVER, DANGER,
                   DANGER_HOVER, INPUT_BG, BORDER, CARD_HOVER, ON_ACCENT)
from password_generator import estimate_strength


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
        lbl = tk.Label(tw, text=self.text, bg="#0E0E10", fg="#EDEDED",
                       padx=9, pady=4, font=(FONT, 9), bd=0)
        lbl.pack()

    def _hide(self, _=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


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


def field(parent, label, show=None, placeholder=""):
    ctk.CTkLabel(parent, text=label, anchor="w", font=F(13, "bold"),
                 text_color=MUTED).pack(anchor="w", pady=(12, 4))
    e = ctk.CTkEntry(parent, height=42, corner_radius=10, fg_color=INPUT_BG,
                     border_color=BORDER, show=show, font=F(14),
                     placeholder_text=placeholder)
    e.pack(fill="x")
    return e


def strength_widget(parent):
    """A strength bar + label; returns (bar, label, update(password))."""
    box = ctk.CTkFrame(parent, fg_color="transparent")
    box.pack(fill="x", pady=(10, 0))
    box.grid_columnconfigure(0, weight=1)
    bar = ctk.CTkProgressBar(box, height=8, corner_radius=4,
                             progress_color=GREEN)
    bar.grid(row=0, column=0, sticky="ew", padx=(0, 10))
    bar.set(0)
    label = ctk.CTkLabel(box, text="", width=54, font=F(12, "bold"),
                         text_color=MUTED)
    label.grid(row=0, column=1)

    def update(password):
        name, frac, color = estimate_strength(password)
        bar.set(frac)
        bar.configure(progress_color=color)
        label.configure(text=name, text_color=color)

    return bar, label, update


def fit_modal(root, top):
    """
    Grow a modal so its content is never clipped. The hardcoded sizes are
    only a starting point — actual required height varies with Windows
    display scaling and font metrics, which used to cut off the bottom
    button row on scaled displays.
    """
    top.update_idletasks()
    need = top.winfo_reqheight()
    cur_w, cur_h = top.winfo_width(), top.winfo_height()
    if need <= cur_h:
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
    root.update_idletasks()
    x = root.winfo_rootx() + (root.winfo_width() - w) // 2
    y = root.winfo_rooty() + (root.winfo_height() - h) // 2
    top.geometry(f"{w}x{h}+{max(x, 0)}+{max(y, 0)}")
    top.transient(root)
    # CTkToplevel needs a beat before it can grab / take an icon.
    top.after(120, lambda: safe_grab(root, top, icon_path))
    return top


def confirm(root, title, message, danger=True, icon_path=None):
    top = modal(root, title, 400, 220, icon_path)
    result = {"ok": False}
    wrap = ctk.CTkFrame(top, fg_color="transparent")
    wrap.pack(fill="both", expand=True, padx=26, pady=24)
    ctk.CTkLabel(wrap, text=title, font=F(17, "bold"),
                 text_color=TEXT).pack(anchor="w")
    ctk.CTkLabel(wrap, text=message, font=F(13), text_color=MUTED,
                 wraplength=340, justify="left").pack(anchor="w", pady=(8, 0))

    def ok():
        result["ok"] = True
        top.destroy()

    row = ctk.CTkFrame(wrap, fg_color="transparent")
    row.pack(fill="x", side="bottom", pady=(16, 0))
    ghost_button(row, "Cancel", top.destroy, width=120).pack(side="left")
    ctk.CTkButton(
        row, text="Delete" if danger else "Confirm", width=130, height=40,
        corner_radius=10, fg_color=DANGER if danger else GREEN,
        hover_color=DANGER_HOVER if danger else GREEN_HOVER,
        text_color="white" if danger else ON_ACCENT, font=F(13, "bold"),
        command=ok).pack(side="right")
    top.bind("<Return>", lambda e: ok())
    top.bind("<Escape>", lambda e: top.destroy())
    root.wait_window(top)
    return result["ok"]
