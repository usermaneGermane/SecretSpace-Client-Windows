"""
The Windows version resource for SecretSpace.exe -- what Explorer shows under
Properties > Details. Used by both .spec files at build time only; the app
never imports it, so PyInstaller does not bundle it.

It reads version.py, so the exe, the in-app label and the installer
(the builder passes the same version to Inno Setup) can never disagree.
"""

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo,
    VarStruct, VSVersionInfo)

from version import __version__, file_version


def version_info(description="SecretSpace password manager",
                 filename="SecretSpace.exe") -> VSVersionInfo:
    numbers = file_version()
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=numbers, prodvers=numbers),
        kids=[
            StringFileInfo([StringTable("040904B0", [
                StringStruct("FileDescription", description),
                StringStruct("FileVersion", __version__),
                StringStruct("InternalName", filename[:-4]),
                StringStruct("OriginalFilename", filename),
                StringStruct("ProductName", "SecretSpace"),
                StringStruct("ProductVersion", __version__),
            ])]),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    )
