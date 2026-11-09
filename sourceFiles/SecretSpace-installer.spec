# -*- mode: python ; coding: utf-8 -*-
#
# The build the installer ships: a folder (SecretSpace.exe + _internal\), not a
# single self-extracting file. A single-file exe unpacks ~45 MB to %TEMP% on
# every launch - about a second of start-up, and a leftover _MEI folder
# whenever it is killed - which is why the portable one was retired. UPX is off for the same reason: every DLL would otherwise be
# decompressed at start-up, and UPX-packed files trip antivirus heuristics.
import os
import sys

from PyInstaller.utils.hooks import collect_all

SRC = SPECPATH
sys.path.insert(0, SRC)
from build_version import version_info   # Properties > Details

datas = [(os.path.join(SRC, 'SecretSpace-logo.png'), '.'),
         (os.path.join(SRC, 'SecretSpace-logo.ico'), '.')]
binaries = []
# PIL.ImageTk pulls in PIL._tkinter_finder at runtime, and PyInstaller's
# Pillow hook does not always detect it. Without it the frozen app crashes
# while drawing the login logo with "No module named 'PIL._tkinter_finder'".
# Listing it here is a no-op when the hook already found it.
hiddenimports = ['PIL._tkinter_finder']
tmp_ret = collect_all('customtkinter')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    [os.path.join(SRC, 'gui.py')],
    pathex=[SRC],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SecretSpace',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[os.path.join(SRC, 'SecretSpace-logo.ico')],
    version=version_info(),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='SecretSpace',
)
