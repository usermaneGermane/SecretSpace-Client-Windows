"""
One program at a time in an account.

The app keeps an open account's vaults in memory and writes whole vaults.
Were another program (the command line, a second window) to change a vault
meanwhile, the app's next save would put the older copy back and the change
would be gone. So whoever may write holds the account: the app from unlock
to lock, the command line while one command runs. Reading needs no hold:
files are replaced whole, never half written.

It is a lock the operating system keeps on an empty file beside the
account's folder, so it ends with the program, also after a crash. Where
the file system has no such locks there is none, as in earlier versions.
"""

import errno
import os
import threading
import time

import accounts
import vault

_BUSY = {errno.EACCES, errno.EAGAIN, errno.EDEADLK,
         getattr(errno, "EDEADLOCK", errno.EAGAIN)}


class Busy(Exception):
    """Another program holds the account."""


class Hold:
    """An account held by this program, until every holder let go."""

    def __init__(self, username: str, file=None):
        self.username = username
        self._file = file
        self._count = 1
        self._guard = threading.Lock()

    def retain(self) -> bool:
        """One more holder. False when everyone let go already."""
        with self._guard:
            if not self._count:
                return False
            self._count += 1
            return True

    def release(self) -> None:
        with self._guard:
            if not self._count:
                return
            self._count -= 1
            if self._count or self._file is None:
                return
            file, self._file = self._file, None
            file.close()                    # which also unlocks it

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.release()


def lock_path(username: str) -> str:
    return os.path.join(accounts.accounts_dir(),
                        "." + vault.validate_username(username) + ".lock")


def _lock(file) -> None:
    if os.name == "nt":
        import msvcrt
        file.seek(0)
        msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def take(username: str, wait: float = 0) -> Hold:
    """Hold the account, waiting up to ``wait`` seconds, or raise Busy."""
    path = lock_path(username)
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        file = open(path, "ab")
    except OSError:
        return Hold(username)           # e.g. a folder that cannot be written
    end = time.monotonic() + wait
    while True:
        try:
            _lock(file)
            return Hold(username, file)
        except OSError as e:
            if e.errno not in _BUSY:
                file.close()
                return Hold(username)
            if time.monotonic() >= end:
                file.close()
                raise Busy(username) from None
        time.sleep(0.05)
