# -*- mode: python ; coding: utf-8 -*-
#
# PassMan-Builder.exe: build.py + builder_gui.py frozen into one file that
# checks the prerequisites and builds PassMan. Built with:
#     py builder\build.py --builder
# It borrows PassMan's theme and widgets from sourceFiles/ for its look.
import os
import sys

from PyInstaller.utils.hooks import collect_all

HERE = SPECPATH
SRC = os.path.join(os.path.dirname(HERE), 'sourceFiles')
sys.path.insert(0, SRC)
from build_version import version_info   # Properties > Details

datas = [(os.path.join(SRC, 'PassMan-logo.png'), '.'),
         (os.path.join(SRC, 'PassMan-logo.ico'), '.')]
binaries = []
hiddenimports = []
tmp_ret = collect_all('customtkinter')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

a = Analysis(
    [os.path.join(HERE, 'builder_gui.py')],
    pathex=[HERE, SRC],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # The builder never touches a vault: keep the app's crypto out of it.
    excludes=['cryptography', 'pyperclip'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PassMan-Builder',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[os.path.join(SRC, 'PassMan-logo.ico')],
    version=version_info("PassMan Builder", "PassMan-Builder.exe"),
)
