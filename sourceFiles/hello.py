"""
Unlock again with Windows Hello (fingerprint, face or PIN).

Once an account was opened with its master password, locking it keeps that
password in this program's memory, encrypted: with a fresh AES key, which is
encrypted to the Windows user's Hello key. Only Windows can decrypt that,
and it asks for the Hello gesture. Nothing of it is ever written to disk, so
after SecretSpace was closed or the PC restarted the master password is
needed again (owner, 2026-11-25).

The Hello key is the one Windows made when Hello was set up ("Microsoft
Passport Key Storage Provider"). No key is created and none is deleted.
Windows only; elsewhere ``available`` is False.
"""

import ctypes
import os
import sys
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import accounts

SETTING = "windows_hello"
_CONTEXT = b"SecretSpace Windows Hello\x00"

_PROVIDER = "Microsoft Passport Key Storage Provider"
_SILENT, _PKCS1 = 0x40, 0x2
_SYSTEM32 = 0x800                       # LOAD_LIBRARY_SEARCH_SYSTEM32
_CANCELLED = {0x80090036, 0x800704C7}   # NTE_USER_CANCELLED, ERROR_CANCELLED
_BAD_DATA = 0x80090005
# A TPM or the fingerprint service that is busy or just woke up.
_AGAIN = {0x8028008B, 0x80280095, 0x80280159, 0x80098046}
_TRIES, _PAUSE = 3, 0.5


class Cancelled(Exception):
    """The user closed the Hello window."""


class Failed(Exception):
    """Windows Hello is not set up, or did not work."""


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------
def _check(status: int, what: str, ignore: int = 0) -> None:
    status &= 0xFFFFFFFF
    if status < 0x80000000 or status == ignore:
        return
    if status in _CANCELLED:
        raise Cancelled()
    error = Failed(f"Windows Hello did not work ({what}, 0x{status:08X}).")
    error.status = status
    raise error


def _user_sid() -> str:
    from ctypes import wintypes as w
    advapi = ctypes.WinDLL("advapi32", winmode=_SYSTEM32)
    kernel = ctypes.WinDLL("kernel32", winmode=_SYSTEM32)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD,
                                        ctypes.POINTER(w.HANDLE)]
    advapi.GetTokenInformation.argtypes = [
        w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD,
        ctypes.POINTER(w.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    token = w.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x8,
                                   ctypes.byref(token)):
        raise Failed("The Windows user could not be read.")
    try:
        size = w.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        text = ctypes.c_void_p()
        # TOKEN_USER starts with the pointer to the SID.
        if not advapi.GetTokenInformation(token, 1, buffer, size,
                                          ctypes.byref(size)) \
                or not advapi.ConvertSidToStringSidW(
                    ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0],
                    ctypes.byref(text)):
            raise Failed("The Windows user could not be read.")
        try:
            return ctypes.wstring_at(text.value)
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.CloseHandle(token)


def _key_name() -> str:
    """The name of this Windows user's Hello key, or Failed: not set up."""
    try:
        find = ctypes.WinDLL("cryptngc",
                             winmode=_SYSTEM32).NgcGetDefaultDecryptionKeyName
    except (OSError, AttributeError):
        raise Failed("This Windows has no Windows Hello.") from None
    find.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
                     ctypes.POINTER(ctypes.c_wchar_p)]
    name = ctypes.c_wchar_p()
    status = find(_user_sid(), 0, 0, ctypes.byref(name)) & 0xFFFFFFFF
    if status >= 0x80000000 or not name.value:
        raise Failed("Windows Hello is not set up for this Windows user.")
    return name.value


class _Key:
    """The Hello key, open."""

    def __init__(self, silent: bool):
        n = self._n = ctypes.WinDLL("ncrypt", winmode=_SYSTEM32)
        handle, dword = ctypes.c_size_t, ctypes.c_ulong
        n.NCryptOpenStorageProvider.argtypes = [
            ctypes.POINTER(handle), ctypes.c_wchar_p, dword]
        n.NCryptOpenKey.argtypes = [handle, ctypes.POINTER(handle),
                                    ctypes.c_wchar_p, dword, dword]
        n.NCryptSetProperty.argtypes = [handle, ctypes.c_wchar_p,
                                        ctypes.c_char_p, dword, dword]
        n.NCryptFreeObject.argtypes = [handle]
        for crypt in (n.NCryptEncrypt, n.NCryptDecrypt):
            crypt.argtypes = [handle, ctypes.c_char_p, dword, ctypes.c_void_p,
                              ctypes.c_void_p, dword, ctypes.POINTER(dword),
                              dword]
        name = _key_name()
        self._provider, self._key = handle(), handle()
        _check(n.NCryptOpenStorageProvider(ctypes.byref(self._provider),
                                           _PROVIDER, 0), "provider")
        try:
            _check(n.NCryptOpenKey(self._provider, ctypes.byref(self._key),
                                   name, 0, _SILENT if silent else 0), "key")
        except BaseException:
            n.NCryptFreeObject(self._provider)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._n.NCryptFreeObject(self._key)
        self._n.NCryptFreeObject(self._provider)

    def _set(self, name, raw, ignore=0):
        _check(self._n.NCryptSetProperty(self._key, name, raw, len(raw), 0),
               name, ignore)

    def ask(self, window: int, text: str) -> None:
        """What the Hello window says and belongs to; never skip it."""
        if window:
            self._set("HWND Handle", window.to_bytes(
                ctypes.sizeof(ctypes.c_void_p), "little"), _BAD_DATA)
        self._set("Use Context", text.encode("utf-16-le") + bytes(2))
        self._set("PinCacheIsGestureRequired", (1).to_bytes(4, "little"))

    def _crypt(self, call, data: bytes) -> bytes:
        out = ctypes.create_string_buffer(1024)
        size = ctypes.c_ulong()
        _check(call(self._key, data, len(data), None, out, len(out),
                    ctypes.byref(size), _PKCS1), "key use")
        return out.raw[:size.value]

    def encrypt(self, data):
        return self._crypt(self._n.NCryptEncrypt, data)

    def decrypt(self, data):
        return self._crypt(self._n.NCryptDecrypt, data)


def _wrap(key: bytes) -> bytes:
    """To the Hello key; asks nothing."""
    with _Key(silent=True) as hello:
        return hello.encrypt(key)


def _unwrap(wrapped: bytes, window: int, text: str) -> bytes:
    """Windows asks for the gesture."""
    for left in reversed(range(_TRIES)):
        try:
            with _Key(silent=False) as hello:
                hello.ask(window, text)
                return hello.decrypt(wrapped)
        except Failed as e:
            if not left or getattr(e, "status", 0) not in _AGAIN:
                raise
            time.sleep(_PAUSE)


def available() -> bool:
    """Is Windows Hello set up for this Windows user?"""
    if sys.platform != "win32":
        return False
    try:
        _key_name()
        return True
    except (Failed, OSError):
        return False


def window_of(widget) -> int:
    """The Windows handle of the window a widget is in."""
    if sys.platform != "win32":
        return 0
    user32 = ctypes.WinDLL("user32", winmode=_SYSTEM32)
    user32.GetAncestor.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    user32.GetAncestor.restype = ctypes.c_void_p
    return user32.GetAncestor(widget.winfo_id(), 2) or 0      # GA_ROOT


# ---------------------------------------------------------------------------
# The setting (account.json: this device only)
# ---------------------------------------------------------------------------
def is_enabled(account) -> bool:
    return account is not None and account.info.get(SETTING) is True


def set_enabled(account, on: bool) -> None:
    info = dict(account.info)
    info.pop(SETTING, None)
    if on:
        info[SETTING] = True
    accounts._write_info(account.username, info)
    account.info = info
    if not on:
        forget(account.username)


# ---------------------------------------------------------------------------
# What is kept while locked, in memory only
# ---------------------------------------------------------------------------
_kept = {}                      # username -> (wrapped key, nonce, sealed)


def _seal(username: str, password: str) -> tuple:
    key, nonce = AESGCM.generate_key(256), os.urandom(12)
    return _wrap(key), nonce, AESGCM(key).encrypt(
        nonce, password.encode("utf-8"), _CONTEXT + username.encode("utf-8"))


def _open(username: str, sealed: tuple, window: int, text: str) -> str:
    wrapped, nonce, data = sealed
    try:
        return AESGCM(_unwrap(wrapped, window, text)).decrypt(
            nonce, data, _CONTEXT + username.encode("utf-8")).decode("utf-8")
    except (InvalidTag, ValueError):
        raise Failed("Windows Hello returned something else.") from None


def keep(account, password: str) -> bool:
    """At a lock. Whether Hello can open the account again."""
    forget(account.username)
    if not is_enabled(account):
        return False
    try:
        _kept[account.username] = _seal(account.username, password)
    except Exception:           # whatever it is, locking goes on:
        return False            # then it takes the master password
    return True


def can_unlock(username: str) -> bool:
    return username in _kept


def forget(username: str) -> None:
    _kept.pop(username, None)


def password_for(username: str, window: int) -> str:
    """Ask for the Hello gesture. Raises Cancelled or Failed."""
    sealed = _kept.get(username)
    if sealed is None:
        raise Failed("Windows Hello cannot open it now.")
    return _open(username, sealed, window,
                 f"Unlock “{username}” in SecretSpace")


def prove(window: int) -> None:
    """Before it is turned on: one full round, so it is known to work here."""
    sealed = _seal("", "proof")
    if _open("", sealed, window,
             "Use Windows Hello to unlock SecretSpace") != "proof":
        raise Failed("Windows Hello returned something else.")
