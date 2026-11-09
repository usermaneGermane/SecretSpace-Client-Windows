"""
SecretSpace Builder: the window around build.py.

It shows every prerequisite as a checklist, offers to install what is
missing (asking before each install), then builds
SecretSpace-Client-Installer.exe with a live log. All the work happens in build.py, on a background thread, so the
window never freezes during a long build.
"""

import os
import queue
import sys
import threading
from tkinter import filedialog, messagebox

# Reuse SecretSpace's own look. When frozen, PyInstaller has bundled theme.py.
if not getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "sourceFiles"))

import customtkinter as ctk                                    # noqa: E402

import build                                                   # noqa: E402
from theme import (F, MONO, HEADER_BG, CARD, BORDER, TEXT,     # noqa: E402
                   MUTED, GREEN, DANGER, asset_candidates)
from widgets import ghost_button, accent_button               # noqa: E402

MARKS = {True: ("✓", GREEN), False: ("✗", DANGER), None: ("–", MUTED)}


class BuilderApp:
    def __init__(self, root, project):
        self.root = root
        self.project = project
        self.events = queue.Queue()
        self.busy = False
        self.checks = []
        self.python = None

        root.title("SecretSpace Builder")
        root.geometry("760x640")
        root.minsize(640, 520)
        for path in asset_candidates("SecretSpace-logo.ico"):
            if os.path.exists(path):
                try:
                    root.iconbitmap(path)
                except Exception:
                    pass
                break

        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(2, weight=1)

        head = ctk.CTkFrame(root, fg_color=HEADER_BG, corner_radius=0)
        head.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(head, text="SecretSpace Builder", font=F(20, "bold"),
                     text_color=GREEN).pack(anchor="w", padx=20, pady=(14, 0))
        self.where = ctk.CTkLabel(head, text="", font=F(12),
                                  text_color=MUTED, anchor="w")
        self.where.pack(anchor="w", padx=20, pady=(0, 14))

        self.list = ctk.CTkFrame(root, fg_color=CARD, corner_radius=12)
        self.list.grid(row=1, column=0, sticky="ew", padx=18, pady=(14, 8))
        self.list.grid_columnconfigure(1, weight=1)

        self.log_box = ctk.CTkTextbox(
            root, font=ctk.CTkFont(family=MONO, size=12), fg_color=HEADER_BG,
            border_color=BORDER, border_width=1, text_color=TEXT,
            wrap="word")
        self.log_box.grid(row=2, column=0, sticky="nsew", padx=18, pady=8)
        self.log_box.configure(state="disabled")

        bar = ctk.CTkFrame(root, fg_color="transparent")
        bar.grid(row=3, column=0, sticky="ew", padx=18, pady=(4, 16))
        self.folder_btn = ghost_button(bar, "Choose folder...",
                                       self.choose_folder, width=130)
        self.folder_btn.pack(side="left")
        self.recheck_btn = ghost_button(bar, "Check again", self.recheck,
                                        width=120)
        self.recheck_btn.pack(side="left", padx=(10, 0))
        self.build_btn = accent_button(bar, "Build", self.start_build,
                                       width=120)
        self.build_btn.pack(side="right")
        self.install_btn = ghost_button(bar, "Install missing",
                                        self.install_missing, width=140)
        self.install_btn.pack(side="right", padx=(0, 10))
        self.open_btn = ghost_button(bar, "Open folder", self.open_folder,
                                     width=120)

        root.after(50, self.poll)
        self.recheck()

    # -- background work --------------------------------------------------
    def work(self, job, done):
        """Run ``job`` off the UI thread; ``done(result)`` runs back on it."""
        self.set_busy(True)

        def target():
            try:
                result = job()
            except Exception as e:                 # never leave it "busy"
                self.events.put(("log", f"Error: {e}"))
                result = None
            self.events.put(("done", (done, result)))

        threading.Thread(target=target, daemon=True).start()

    def poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self.append(payload)
                elif kind == "done":
                    done, result = payload
                    self.set_busy(False)
                    done(result)
        except queue.Empty:
            pass
        self.root.after(50, self.poll)

    def log(self, line):
        """Safe from any thread."""
        self.events.put(("log", line))

    def append(self, line):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def set_busy(self, busy):
        self.busy = busy
        self.root.configure(cursor="watch" if busy else "")
        self.refresh_buttons()

    # -- checks -----------------------------------------------------------
    def recheck(self):
        try:
            version = build.app_version(self.project)
        except Exception:
            version = "?"
        self.where.configure(text=f"{self.project}    ·    version {version}")
        self.open_btn.pack_forget()

        def job():
            return build.check_all(self.project), build.find_python()

        self.work(job, self.show_checks)

    def show_checks(self, result):
        if result is None:
            return
        self.checks, self.python = result
        for w in self.list.winfo_children():
            w.destroy()
        for i, c in enumerate(self.checks):
            # "–" for a check that waits on an earlier one ("needs Python
            # first"), so the list shows what to fix rather than a wall of ✗.
            state = True if c.ok else (None if c.detail.startswith("needs")
                                       else False)
            mark, colour = MARKS[state]
            ctk.CTkLabel(self.list, text=mark, width=26, font=F(15, "bold"),
                         text_color=colour).grid(row=i, column=0,
                                                 padx=(14, 4), pady=3)
            ctk.CTkLabel(self.list, text=c.name, font=F(13, "bold"),
                         text_color=TEXT, anchor="w").grid(
                row=i, column=1, sticky="w", pady=3)
            ctk.CTkLabel(self.list, text=c.detail, font=F(12),
                         text_color=MUTED, anchor="w", wraplength=360,
                         justify="left").grid(row=i, column=2, sticky="w",
                                              padx=(8, 14), pady=3)
        if build.can_build(self.checks):
            self.append("Everything the build needs is here. "
                        "Press Build.")
        else:
            for step in build.manual_steps(self.checks):
                self.append("To do by hand: " + step)
            if self.fixes():
                self.append("Press \"Install missing\" to install what "
                            "is missing.")
        self.refresh_buttons()

    def fixes(self):
        return build.fix_commands(self.checks, self.project, self.python)

    def refresh_buttons(self):
        ready = bool(self.checks) and build.can_build(self.checks)
        idle = not self.busy
        self.build_btn.configure(state="normal" if idle and ready
                                 else "disabled")
        self.install_btn.configure(state="normal" if idle and self.fixes()
                                   else "disabled")
        for b in (self.recheck_btn, self.folder_btn):
            b.configure(state="normal" if idle else "disabled")

    # -- actions ----------------------------------------------------------
    def install_missing(self):
        approved = []
        for label, cmd in self.fixes():
            if messagebox.askyesno(
                    "Install?",
                    f"{label}?\n\nThis runs:\n"
                    f"{build.subprocess.list2cmdline(cmd)}",
                    parent=self.root):
                approved.append((label, cmd))
        if not approved:
            return

        def job():
            for label, cmd in approved:
                self.log("")
                self.log(label + "...")
                res = build.run(cmd, on_line=self.log)
                self.log("done" if res.code == 0
                         else f"failed (exit code {res.code})")

        # Re-check afterwards: a fresh Python can then get its libraries.
        self.work(job, lambda _: self.recheck())

    def start_build(self):
        self.open_btn.pack_forget()
        iscc = build.find_iscc()

        def job():
            return build.build(self.project, self.python, iscc, log=self.log)

        def done(ok):
            if ok:
                self.open_btn.pack(side="right", padx=(0, 10))
            else:
                messagebox.showerror("Build failed", "The build failed. The "
                                     "log says why.", parent=self.root)

        self.work(job, done)

    def choose_folder(self):
        folder = filedialog.askdirectory(
            parent=self.root, title="Choose the SecretSpace project folder",
            initialdir=self.project)
        if folder:
            self.project = os.path.normpath(folder)
            self.recheck()

    def open_folder(self):
        os.startfile(self.project)


def main():
    root = ctk.CTk()
    BuilderApp(root, build.project_dir())
    root.mainloop()


if __name__ == "__main__":
    main()
