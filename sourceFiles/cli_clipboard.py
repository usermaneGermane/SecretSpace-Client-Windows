"""
The clipboard for the command line, on Windows. (The app for Linux has its
own file of this name.)
"""

import time

import pyperclip


class NoClipboard(Exception):
    """There is no clipboard to copy to."""


def hold(text: str, seconds: float) -> None:
    """
    Put ``text`` on the clipboard for ``seconds``, then clear it -- at once
    when interrupted. A text copied by something else meanwhile is left
    alone. Windows clipboard history (Win+V) keeps its own copy.
    """
    try:
        pyperclip.copy(text)
    except Exception as e:
        raise NoClipboard(f"The clipboard cannot be used: {e}") from None
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if pyperclip.paste() == text:
                pyperclip.copy("")
        except Exception:
            pass
