# SecretSpace for Windows

A desktop password manager for Windows that you run entirely yourself. Your
passwords are in encrypted vaults on your own PC (AES-256-GCM; the key comes
from your master password and a Secret Key, through Argon2id). There is no
online service behind it: it works offline, and if you want several devices
in step, or a vault shared with other people, you run the sync server
yourself, on your own hardware.

**This README describes SecretSpace 3** (3.0.0 and later). The 2.x line —
one vault file per user, last release
[2.13.0](https://github.com/usermaneGermane/SecretSpace-Client-Windows/releases/tag/v2.13.0) —
has its own README on the branch
[`release-2.x`](https://github.com/usermaneGermane/SecretSpace-Client-Windows/tree/release-2.x).
Coming from 2.x? Read [Upgrading from 2.x](#upgrading-from-2x) first.

**Formerly PassMan.** The project was renamed to SecretSpace in November
2026, because another password manager already uses the name PassMan.
Releases up to 2.11.0 and 3.0.0-alpha.1 still carry the old name: their
installer is `PassMan-Client-Installer.exe`, the program `PassMan.exe`, and
the data folder `%APPDATA%\PassMan`. Upgrading from them is an ordinary
upgrade: the installer replaces the PassMan program and shortcuts with
SecretSpace's, and your vaults stay in `%APPDATA%\PassMan`, which
SecretSpace keeps using (nothing is moved or renamed). The vault files are
the same.

SecretSpace lives in four repositories:

| Repository | What it holds |
|---|---|
| **SecretSpace-Client-Windows** (this one) | the app for Windows, and its installer |
| [SecretSpace-Client-Linux](https://github.com/usermaneGermane/SecretSpace-Client-Linux) | the app for Linux — from source or a .deb package |
| [SecretSpace-Server-Windows](https://github.com/usermaneGermane/SecretSpace-Server-Windows) | the sync server for Windows, and its installer |
| [SecretSpace-Server-Linux](https://github.com/usermaneGermane/SecretSpace-Server-Linux) | the sync server for Linux (systemd) |

![SecretSpace](sourceFiles/SecretSpace-logo.png)

## What SecretSpace 3 is

SecretSpace 3 replaces "one vault file per user" with **accounts**. An
account has a master password, a Secret Key and a recovery phrase, and holds
one or more vaults.

- **Accounts.** *Create an account* asks for a name and a master password,
  then shows your **Emergency Kit** (a *Secret Key*, `A3-XXXXX-…`) and a
  **12-word recovery phrase**, which you type three words of back. Nothing
  is written until that last step.
- **A stronger lock.** The key comes from your master password *and* the
  Secret Key, through Argon2id (64 MiB, memory-hard) instead of PBKDF2. A
  stolen copy of the account folder cannot be opened by guessing the
  password alone on another PC.
- **The Secret Key is typed once per PC.** This PC keeps it, protected by
  Windows (DPAPI) for your Windows user. Copy the account folder to another
  PC and that PC asks for the Secret Key once, from the Emergency Kit.
- **Several vaults in one account.** Besides the *Personal* vault an account
  can have more — *Home*, *Work*, a project — made, renamed and deleted in
  the **Vaults** window. The menu above the list picks which vault is shown
  (*All vaults* shows them together, each row naming its vault, and search
  covers them all); a new entry goes to the vault picked there, or to the
  one chosen in the *Add an entry* window. Every vault has its own key. A
  vault deleted on one device is **kept** on the others, marked and no
  longer synced, until you delete it there too or put it back.
- **Sync through your own server.** *Settings → Sync → Set up…* puts the
  account on a SecretSpace Server **2.0.0** or newer, with the server's token
  as the sign-up code; after that the **Sync** button keeps every vault in
  step, each with its own merge and conflict questions. On another device,
  *Sign in from a server* on the login screen asks for the address, your
  username and master password and — once per device — the Secret Key. The
  server stores only what it cannot open: no master password, no Secret
  Key, no vault key. More under [Syncing your devices](#syncing-your-devices).
- **Sharing a vault.** An owner adds other accounts of the same server to a
  vault in **Vaults → Members**, as *owner*, *editor* or *reader* (the
  server refuses a reader's upload, and the app shows a reader no Edit or
  Archive). Before the first share the app shows the other person's
  **fingerprint**: they read theirs to you (it is at the top of their
  Members window) and the two must match — that is what keeps a dishonest
  server from slipping in its own key. The vault's key reaches a member only
  wrapped to their public key; the server never holds it. **Remove** takes
  a member out *and* gives the vault a new key in the same step, so they can
  open nothing written afterwards (what they had already seen they may have
  kept — and any member can export what they can read). A member can
  **leave**; an owner can change the key on its own.
- **Vault keys are signed.** Every vault key carries a signature of the
  account that made it. The app takes a key only when it is signed by your
  own account, by whoever gave you the key you hold, or by someone whose
  fingerprint you checked, and never an older key. So a dishonest sync
  server, or someone who broke into it, cannot hand the app a key of its
  own making. *Remove* and *Change key* name the members whose fingerprint
  was never checked on this PC, and an unencrypted `http://` address of
  another machine asks before it is used.
- **Who changed what.** Every save adds lines to the vault's own change log
  — *user1 changed the password of “Mail”* — signed with the author's
  account key, encrypted with the vault and synced with it. **Vaults →
  Activity** shows it to every member; a line whose signature does not
  match its author is marked. In a shared vault an entry and each of its
  earlier versions say who changed them. Owners can also read the **server
  log** there: uploads, members added and removed, key changes, with the
  address they came from. Values are never recorded, and neither is who
  looked at an entry or copied a password.
- **Recovering an account.** *Forgot your master password?* on the login
  screen takes the account name and the 12-word recovery phrase, then a new
  master password. The same keys open again, so every vault and every share
  is still there. You get a **new phrase** (the old one stops working) and,
  when this PC could not keep the old Secret Key (a new PC), a new Emergency
  Kit. On a PC that does not have the account, the account comes from its
  server. An account on a server is changed there first; other devices then
  sign in again with the new password. *Settings → Recovery phrase → New
  phrase…* replaces a phrase that was lost or seen.
- **Importing a 2.x vault.** *Import* lists the 2.x vaults on this PC (or
  takes a `.vault.enc` file) and copies every entry with its history and
  archive state. The 2.x file is only read; its sync settings stay with it.
- Everything else in the window — entries, archive, history, 2FA codes,
  generator, plain export — works as in 2.x.

**Not in 3.0:** adding someone to a vault before they have an account (they
make the account first, then you share), a company setup (an admin console,
invites, recovery with an admin's approval), moving an entry from one vault
to another, and *Sync when I unlock* (2.x has it; in 3.0 you press **Sync**).
[SecretSpace for Linux](https://github.com/usermaneGermane/SecretSpace-Client-Linux)
1.0.0 is the same release for Linux.

## Upgrading from 2.x

SecretSpace 3 does not open 2.x vaults directly: you make an account and
**import** them. **Your 2.x vaults are never converted, changed or
deleted**, so the way back stays open.

1. **Back up first.** Close SecretSpace and copy the folder
   `%APPDATA%\SecretSpace` (or `%APPDATA%\PassMan`, if that is the one you
   have) somewhere safe.
2. **Install 3.0.0.** The installer upgrades the installed 2.x program in
   place; the data folder is left as it is.
3. **Create an account.** The login screen is empty at first — your 2.x
   vaults are not shown there. Save the Emergency Kit and write down the
   12-word phrase.
4. **Import.** Press *Import*, pick a 2.x vault from the list and enter its
   master password. Its entries arrive whole, with history and archive, in
   the vault that is shown — make a vault for each 2.x vault first if you
   want to keep them apart.
5. **Sync.** A 2.x vault's sync settings are not carried over. Update your
   server to **2.0.0** (it keeps serving 2.x apps exactly as before, with
   the same store and token), then use *Settings → Sync → Set up…*. Your
   other devices install 3.0.0 and use *Sign in from a server*.

**Going back.** Install
[2.13.0](https://github.com/usermaneGermane/SecretSpace-Client-Windows/releases/tag/v2.13.0)
again. It opens your 2.x vaults as you left them. What you added or changed
in SecretSpace 3 stays in the account, not in the 2.x vaults: there is no
sync between a 2.x vault and an account, so do not keep working in both.

## Running it

The repository does not contain the app itself. Download
`SecretSpace-Client-Installer.exe` from the release marked **Latest** on the
[Releases](https://github.com/usermaneGermane/SecretSpace-Client-Windows/releases) page (a
*Pre-release* is a test version and has the same file name; the last 2.x
installer is on the release
[2.13.0](https://github.com/usermaneGermane/SecretSpace-Client-Windows/releases/tag/v2.13.0)), or build it
yourself with the [SecretSpace Builder](#building-it-yourself-windows). The
installer is all you need: it brings Python and every library with it, so
installing needs no source code and no Python.

**`SecretSpace-Client-Installer.exe`** installs it. Run it and choose a folder
(by default `%LOCALAPPDATA%\Programs\SecretSpace`) and whether you want a
desktop shortcut. It needs Windows 10 or 11 (64-bit) and installs for your
Windows user only, so it needs no admin rights. You get a Start Menu entry
and an uninstaller under Settings → Apps; the program it installs is
`SecretSpace.exe`. The vault lives in **`%APPDATA%\SecretSpace`**, not in the
program folder, so upgrading or uninstalling never touches it. A copy first
installed as PassMan keeps `%APPDATA%\PassMan` instead.

If you used the portable `PassMan.exe` of 2.2 or earlier, the installer can
move your vaults across. They are moved, not copied, and a vault already in
`%APPDATA%\SecretSpace` is never overwritten. The portable single-file exe is
no longer made: it unpacked itself to a temporary folder on every launch,
which made it slow to start.

The optional sync server is a separate download from its own repository:
**`SecretSpace-Server-Installer.exe`** from [SecretSpace-Server-Windows](https://github.com/usermaneGermane/SecretSpace-Server-Windows), or a Python script and a
systemd unit from [SecretSpace-Server-Linux](https://github.com/usermaneGermane/SecretSpace-Server-Linux). The app never needs it, and it never needs the
app.

To run from source:

```
pip install -r requirements.txt
python sourceFiles/gui.py
```

## Building it yourself (Windows)

Building needs a checkout of this repository: the builder looks for the
source next to itself and builds from it. Run **`SecretSpace-Builder.exe`**
from the project folder. It is not on the Releases page (it is only useful
inside a checkout); make it once with
`py builder\build.py --builder`, see below. It shows a checklist of what
the build needs:

- the SecretSpace source files
- Python 3 and its `tkinter`
- SecretSpace's libraries (`requirements.txt`)
- PyInstaller
- that the app imports cleanly
- Inno Setup 6, for the installer

**Install missing** installs whatever is missing, asking before each one:

- **pip** installs the Python packages.
- **winget** installs Python 3.13 and Inno Setup 6, for your Windows user
  only.

`tkinter` is the one thing it cannot install. It ships with Python, so if
it is reported missing, re-run the Python installer, choose **Modify**,
and tick **tcl/tk and IDLE**.

When every line is ✓, press **Build**. About a minute later the project
folder holds the installer, `SecretSpace-Client-Installer.exe`. The version
comes from `sourceFiles/version.py`.

The builder does not compile anything itself. It drives the Python
installed on the PC, which is why Python is on the checklist. It prefers
the `py` launcher's newest Python 3 over a bare `python` on `PATH`, which
is often a virtualenv or the Microsoft Store placeholder. It never touches
an installed or running SecretSpace: everything it writes is in the project
folder.

The same steps run in a terminal, without the window:

```
py builder\build.py                      check, then build
py builder\build.py --install-missing    install what is missing first
py builder\build.py --builder            build SecretSpace-Builder.exe itself
```

The last line is how the builder is made in the first place, so a fresh
checkout needs Python with PyInstaller once.

### Which files the build needs

PyInstaller compiles the source; the builder only checks and drives it.
Copy the **whole project folder** to the other PC. The build needs:

```
requirements.txt
sourceFiles\    (all of it)
installer\      (for SecretSpace-Client-Installer.exe)
```

`README.md` is not needed to build, and neither are the `tests` folders.

Watch out: if one of the `.py` files is missing, **PyInstaller still
reports a successful build** and produces an exe that crashes on launch
with `ModuleNotFoundError`. The builder imports the app first, to catch
that while the error is still readable.

### After the build

The installer is self-contained: what it installs bundles Python and
every library, so the target PC does not need Python installed to *run*
SecretSpace. Python is only needed to *build* it.

The exe is not code-signed, so Windows SmartScreen will likely warn the first
time — "More info" then "Run anyway".

Your passwords do **not** travel with the installer. The account lives in
`%APPDATA%\SecretSpace`, so a fresh install on a new PC starts empty. To bring
your logins across, use *Sign in from a server* if you sync, or copy the
account's folder (`accounts\<name>`) into `%APPDATA%\SecretSpace\accounts` on
the new PC. Either way the new PC asks once for the Secret Key from your
Emergency Kit.

## A lab copy for testing

The installed copy is your production SecretSpace: its vaults are in
`%APPDATA%\SecretSpace`. Only one copy can be installed — a second run of the
installer upgrades the first — so a copy for trying things out runs
*without* the installer, and keeps its vaults and `config.json` in its own
folder instead:

1. Build (`py builder\build.py`, or SecretSpace Builder).
2. Copy the folder `build\installer\SecretSpace` somewhere of its own, e.g.
   `D:\SecretSpace-Lab`, and run `SecretSpace.exe` from there.

That folder has no `installed` file, so it never touches
`%APPDATA%\SecretSpace`. Its window title says
`[LAB - <its vault folder>]`; the installed copy's title never does. Do not
copy the `installed` file into it.

To update the lab copy after a new build, close it and copy the new program
files over the old ones, leaving its `vault` folder and `config.json` alone:

```
robocopy build\installer\SecretSpace D:\SecretSpace-Lab /E /XD vault /XF config.json
```

(`/E` adds and replaces files but deletes nothing.)

**Syncing a lab copy.** A lab copy can use the same server as production.
Give lab accounts **names your real accounts do not use** (e.g. `test`,
`lab-alice`): the server has one account per name.

**Moving 2.x test vaults out of production.** Uninstalling keeps the vaults, so
`%APPDATA%\SecretSpace\vault` may still hold 2.x vaults you made while testing. With
SecretSpace closed, move each `<user>.vault.enc` together with its `.bak` and
`.base` into the lab copy's `vault` folder (and `config.json` too, if it
names a test vault as the last user).

### The SecretSpace 3 files

```
keyset.pmk:  base64( "PMK3" || ver(1) || kdf(1) || memory_kib(4) || passes(1) || lanes(1) || salt(16) || nonce(12) || ciphertext )
vault .pmv3: base64( "PMV3" || ver(1) || vault_id(16) || key_generation(4) || nonce(12) || ciphertext )
```

Both headers are AES-GCM associated data. The keyset key is HKDF over
Argon2id(master password), with the Secret Key as its salt; the keyset holds the
account's X25519 key and its vault's key, and the vault's entries are the
same JSON as in 2.x. A vault file is bound to its id, so one account's file
cannot be swapped in for another's.

## Project layout

```
SecretSpace-Client-Windows/
├── builder/            SecretSpace Builder: build.py, its window, its spec
├── SecretSpace-Builder.exe  the builder (built, not committed)
├── SecretSpace-Client-Installer.exe  installs the app (built, not committed)
├── vault/               vaults when running from source - never committed
├── installer/           the Inno Setup script for the installer
└── sourceFiles/         the program itself
    ├── gui.py           app shell: login, account list + details, lifecycle
    ├── dialogs.py       the modal dialogs
    ├── sync.py          three-way merge; pure functions, no I/O
    ├── sync_client.py   talking to the sync server
    ├── sync_ui.py       the sync, conflict and archive screens
    ├── history_ui.py    the revision history section of the entry details
    ├── widgets.py       reusable widgets and modal plumbing
    ├── theme.py         palette, fonts, asset lookup
    ├── vault.py         atomic file handling, schema validation, export
    ├── crypto_utils.py  the 2.x container (PMV2), key derivation, encrypt/decrypt
    ├── account_crypto.py  3.0: Argon2id, Secret Key, keyset, PMV3, recovery phrase
    ├── accounts.py      3.0: account folders, unlock, password change, Emergency Kit
    ├── account_sync.py  3.0: the account on a server (API v2): connect, sync, sign in
    ├── account_sync_ui.py  3.0: its screens (Set up, Sync, Sign in from a server)
    ├── secret_store.py  3.0: how this PC keeps the Secret Key (DPAPI)
    ├── bip39_words.py   the BIP39 word list for the recovery phrase
    ├── importers.py     CSV/JSON parsing from other password managers
    ├── appconfig.py     non-secret preferences
    ├── lockout.py       rate limiting of master-password attempts
    ├── password_generator.py
    ├── version.py       the version shown in the UI
    ├── SecretSpace-installer.spec  the PyInstaller build the installer ships
    ├── build_version.py the exe's version resource, read from version.py
    └── tests/
        └── sync_server/ a copy of the server, for the end-to-end sync tests
```

## Upgrading a 2.x vault from an earlier build

*(About 2.x vault files, for the 2.x line. For moving to SecretSpace 3 see [Upgrading from 2.x](#upgrading-from-2x).)*

**Back up your vault before you upgrade.** Copy your `vault` folder (called
`data` in earlier versions) somewhere safe, or open the old app and use Settings → *Save encrypted
backup* if it has one.

The upgrade is one-way. This version reads vaults written by older builds and
transparently re-encrypts them at the stronger settings on first unlock —
but once that has happened, **an older SecretSpace.exe can no longer open the
vault**. It reports "Decryption failed. Wrong password or corrupted data.",
which looks alarmingly like a lost password even though the data is fine.

So: upgrade, confirm your accounts are all there, and only then delete the
old executable. Do not keep both versions pointing at the same vault folder.

### To 2.0 (sync, archive, revision history)

2.0 adds fields to every entry — an id, the archive flag, revision history.
The container is unchanged, so **a 1.x build still opens a 2.0 vault, but
silently drops those fields when it saves**: archived entries come back as
live ones, revision history is lost, and the lost ids confuse the next sync.
So once any PC runs 2.0:

- update **every** PC to 2.0 before using it, and keep no 1.x executable
  pointing at that vault folder;
- update the sync server too (see "Updating" in [SecretSpace-Server-Windows](https://github.com/usermaneGermane/SecretSpace-Server-Windows) or [SecretSpace-Server-Linux](https://github.com/usermaneGermane/SecretSpace-Server-Linux)).

## Syncing your devices

Run a server — [SecretSpace-Server-Windows](https://github.com/usermaneGermane/SecretSpace-Server-Windows) or [SecretSpace-Server-Linux](https://github.com/usermaneGermane/SecretSpace-Server-Linux) says how to set one
up, version **2.0.0** or newer — then put your account on it. Everything is
encrypted before it leaves your machine, so the server stores what it has no
key for and never sees your master password, your Secret Key or a vault key.

- **First device:** *Settings → Sync → Set up…*, enter the server's address
  and its token as the sign-up code. The account and all its vaults are
  uploaded.
- **Every other device:** *Sign in from a server* on the login screen:
  the address, your username and master password, and — once per device —
  the Secret Key from your Emergency Kit. After that, **Sync** on any
  device.

Sync is by hand: press **Sync**. It covers every vault of the account.

**Offline.** The account and its vaults are files on this PC. You can open
them, read and copy passwords and make changes with no network at all; the
changes go up at the next Sync.

Sync merges per entry. A change made on only one device is taken
silently — there is nothing to decide. Only when the **same entry changed on
both** since they last synced do you get a dialog showing both versions
side by side, and **whichever side you do not keep is saved in that entry's
history** — every outcome is reversible with one click on *Revert*.
Cancelling it changes nothing on either side.

**A live entry that is missing from the server** is never removed without
asking. Deleting goes through the Archive (below), so an entry that is still
in use here but gone from the server means the server holds an older or
different copy. The conflict dialog shows it; keeping it (the default)
uploads it again, and choosing the server's side moves it to the Archive.

**An unencrypted address.** A plain `http://` address of another machine
asks before it is used. On such a connection someone on the network could
take over the account *on the server* (not read a vault). Use it on a
network you trust or through a VPN, or give the server a certificate.

### Changing the master password of an account you sync

Change it as usual in *Settings → Master password → Change…*. The server
must be reachable: the account is changed there in the same step, and if it
cannot be reached nothing changes. Your other devices then sign in again
with the new password. The Secret Key and the recovery phrase stay the same.

### Deleting is archiving

**Archive** on the selected entry moves it to the **Archive** (the button
next to the *All* count, above the list) instead of destroying it. Archived entries keep their passwords and can be restored
with one click. *Delete permanently*, inside the archive, is the only action
that really destroys a password — apart from the optional clean-up below.

**Deleting archived entries automatically.** Settings → *Archive* → *Delete
archived entries*: Never (the default), or after 30, 90, 180 or 365 days,
counted from when each entry was archived. It is checked every time you
unlock, and choosing a limit that some entries already exceed asks first and
says how many will go. The setting belongs to the vault, not the PC: another
vault on the same PC keeps its own, and so does your other PC. A deleted
entry also disappears from the other PC at its next sync, unless it was
edited there meanwhile, or that PC still has it live because it never synced
the archiving -- both show up as a sync conflict.

This is not only an undo. A removal has to be distinguishable from an
addition when two vaults merge, or every entry you delete on one PC comes
back from the other on the next sync.

### Revision history

Every edit keeps the version it replaces. The **History** section of the
selected entry lists its earlier versions, newest first, with the date and
what changed:

- **Show** / **Copy** an earlier password — handy when a site still has the
  old one. Copies clear from the clipboard after 30 seconds, as usual.
- **Revert** makes that version current again. The version you leave is kept
  in history too, so a revert can itself be undone.
- **Clear history** forgets them, here and on your other PCs at their next
  sync.

All fields are tracked — site, username, password, notes and 2FA — and the
last **10** versions of each entry are kept. Saving without changing anything
records nothing.

History syncs, and never causes a conflict: each PC ends up with the
combined history from both sides. When you settle a sync conflict, the
version you do not keep becomes the entry's newest revision.

**Update every PC** before relying on it: an older SecretSpace does not know the
field, drops it when it saves, and that loss would then sync. The server
needs no update for this.

## Features

- AES-256-GCM encryption; the key from your master password and a Secret
  Key, through Argon2id
- Accounts with several vaults, each with its own key
- Sync between devices through a server you host, with per-entry merging
- Shared vaults with roles (owner, editor, reader) and a signed record of
  who changed what
- Recovery with a 12-word phrase when the master password is forgotten
- A black-and-green two-pane window: the entry list on the left, the
  selected entry's details (copy buttons, strength, notes, history) on the
  right; the login screen shows one tile per account on this PC. Every dialog
  shares the look: a header band (with the site's tile when it is about an
  entry), settings grouped in cards, and the buttons in a bar at the bottom
- Light and dark: follows Windows, or choose one in Settings → *Appearance*
  *(3.1)*
- Search with Ctrl+F
- Sort the list by date modified or by name (the *Sort* menu above the
  list); the choice is remembered
- Archive with restore, so a deletion is recoverable
- 2FA codes: paste the secret (or the `otpauth://` link) a site gives you,
  and the entry shows its 6-digit code with a countdown. Every look at a
  code asks for your master password; leaving the entry or locking hides it
- Revision history per entry: the last 10 versions, with show, copy and revert
- Password generator with adjustable length and character classes
- Strength meter that accounts for repetition, sequences and common passwords
- Import from Chrome, KeePass, LastPass, Bitwarden and other CSV/JSON exports,
  carrying notes and TOTP secrets across
- Backups by copying the account folder, plus a plaintext export for
  migrating away
- Clipboard auto-clear, idle auto-lock, and a delay after repeated wrong
  master passwords

## If you forget your master password

Nobody — including whoever wrote this app — can open your account for you,
and there is no backdoor. What opens it without the master password is the
**12-word recovery phrase** you wrote down when you made the account:
*Forgot your master password?* on the login screen. If you have lost the
master password **and** the phrase, the passwords are gone.

A new PC also needs the **Secret Key** from your Emergency Kit (or the
recovery phrase, which then makes a new one). Keep the kit and the phrase
somewhere that is not this PC.

**Make backups.** *Settings → Backup → Open folder* shows the account's
folder; copy it to another drive. The copy opens only with your master
password and the Secret Key.

## Where your data lives

The files below are in `%APPDATA%\SecretSpace` (in `%APPDATA%\PassMan` if
that folder was there first, from before the rename). An installed copy is
recognised by the `installed` file that the installer puts next to its exe;
without it — running from source, or a portable exe from 2.2 or earlier —
they are next to the program instead.

| File | What it is |
| --- | --- |
| `accounts/<name>/account.json` | nothing secret: the account's public key, its vaults' ids and names, the Secret Key as this PC keeps it (DPAPI) |
| `accounts/<name>/keyset.pmk` | the account's keys, under your master password + Secret Key (Argon2id, AES-256-GCM) |
| `accounts/<name>/recovery.pmk` | the same keys, under the 12-word recovery phrase |
| `accounts/<name>/vaults/<id>.pmv3` | one vault's entries (+ `.bak`, the previous save) |
| `config.json` | non-secret preferences (last username, auto-lock delay) |

To back an account up, copy its folder (Settings → *Backup* → *Open
folder*); the copy opens only with the master password and the Secret Key.

A `vault` folder beside `accounts` holds 2.x vaults, if you had any.
SecretSpace 3 only reads it, for *Import*:

| File | What it is |
| --- | --- |
| `vault/<user>.vault.enc` | a 2.x vault |
| `vault/<user>.vault.enc.bak` | its previous version |
| `vault/<user>.vault.enc.base` | its sync state with a 1.x server |

The `.base` file is how merging tells a deletion apart from an addition. It
is encrypted with the same master password as the vault. Deleting it is safe
— the next sync just asks more questions than it needs to. Changing your
master password deletes it automatically, since it cannot be re-encrypted
without the old one.

This folder used to be called `data`. If you already have one, SecretSpace keeps
using it as-is and creates nothing new — rename it to `vault` yourself when
convenient, while the app is closed.

Vault writes go to a temporary file and are then atomically renamed into
place, so an interrupted save (full disk, power cut) cannot corrupt the vault.
If the main file is ever damaged, SecretSpace falls back to the `.bak` copy.

## Vault format

*(The 2.x vault file, which Import reads. The SecretSpace 3 files are described under [The SecretSpace 3 files](#the-secretspace-3-files).)*

```
base64( "PMV2" || kdf_id(1) || iterations(4) || salt(16) || nonce(12) || ciphertext )
```

The 9-byte header is passed to AES-GCM as additional authenticated data, so the
stored KDF parameters are covered by the authentication tag and cannot be
tampered with. New vaults use 600,000 PBKDF2 iterations; because the count
travels in the header, it can be raised later without breaking existing
vaults. Vaults written before this header existed are still read, and are
transparently re-encrypted at the current cost the next time you unlock.

## Security notes and limits

Worth knowing about, in the interest of not overselling this:

- **The server is trusted to be there, not to be honest.** It cannot read
  a vault, and the app refuses a vault key it cannot trace to you or to
  someone you checked. But it can refuse to serve, hand back an older copy
  of a vault, or drop one, and it sees who is a member of what and when
  they sync. Comparing fingerprints before the first share is what the
  protection against a dishonest server rests on.
- **Anyone who can read a shared vault can keep a copy.** Removing a member
  changes the key for what is written afterwards; it cannot take back what
  they already saw or exported.
- **The unlocked vault lives in memory in the clear**, and Python strings
  cannot be reliably wiped. Auto-lock limits the window; it does not close it.
- **Locking does not clear a copied password.** It stays pasteable until
  the 30-second auto-clear, so you can lock and then paste. Closing SecretSpace
  still clears it at once, since nothing would be left to clear it later.
- **Clipboard auto-clear only clears the live clipboard.** Windows clipboard
  history (Win+V) and cloud clipboard sync keep copies no application can
  reach. Turn them off if that matters to you.
- **A 2FA code next to its password is one factor, not two.** Anyone who
  opens your vault has both. That is the trade-off for convenience; keep
  your most important accounts (email, bank) on a phone authenticator. The
  codes are made on this PC (RFC 6238); scanning a QR code is not supported
  yet, so paste the secret shown under it.
- **Card details, custom fields and attachments** in an export are not
  imported; SecretSpace warns when it sees them.
- **The unlock delay is a speed bump, not a boundary.** It slows guessing at
  the login screen and survives a restart, but anyone who can copy the vault
  file can attack it offline with no limit at all. Deleting `config.json`
  clears a penalty.
- **Archived entries still hold live passwords.** If you retire a login
  because the password leaked, archiving is not enough — use *Delete
  permanently* in the archive view.
- **Revision history keeps old passwords.** Up to 10 per entry, encrypted
  with the rest of the vault. Old passwords are often reused elsewhere or
  hint at your patterns, so if one leaked, use *Clear history* on that entry
  — it reaches your other PCs too. *Delete permanently* removes an entry's
  history with it.
- **The server's token is the sign-up code.** Anyone holding it can make an
  account on your server (and, for 2.x vaults kept there, read and
  overwrite those blobs). It does not open anyone's SecretSpace 3 account.
- **The sync server is not a backup.** It holds one copy of a file your PCs
  also hold, and it will happily store a vault you damaged. It does keep the
  last 20 revisions, which is a safety net, not a backup strategy.
- **Changing the master password does not re-lock existing copies.** A copy
  of the account folder you saved, or one on a lost USB stick, still opens
  with the password it was written under (and the Secret Key). If you
  change it because the old one leaked, change the passwords *inside* the
  vault too — starting with email and banking.
- **This has not been independently audited.** The 3.0 cryptography is new;
  it was reviewed by its author only.

## Versioning

The version shown in the UI lives in `version.py`. Bump `__version__` there on
release; `VAULT_FORMAT` tracks the on-disk container (`crypto_utils.MAGIC`) and
a test fails if the two drift apart.

Bump the **major** version when an older build can no longer safely use what
this one writes — as in 3.0, which keeps accounts instead of vault files. New features that older builds
handle harmlessly are a minor bump; fixes are a patch.

## Development

```
pip install -r requirements-dev.txt
python -m pytest -q
```

See the project layout above for what each module does. `gui.py` is
presentation only and never touches the cipher.

Tests point `PASSMAN_DATA_DIR` at a temporary directory, so running them
never touches a real vault.

`test_sync_server.py` syncs two simulated PCs through a real server on a
free port. The server is a copy in `sourceFiles/tests/sync_server/`; refresh
it from the server repository when the server changes (its README says
how).

GitHub Actions runs the same tests on Windows with Python 3.12 and 3.13 for
every pull request and every push to `main`
(`.github/workflows/tests.yml`).

## License

The app's typeface, Manrope, is bundled under the SIL Open Font License
(`sourceFiles/Manrope-OFL.txt`).

SecretSpace (this client) is free software under the **GNU General Public
License v3.0 only** (GPL-3.0-only) — see [LICENSE](LICENSE). You may use,
study, change and share it; if you distribute a changed version, it must stay
under the same licence, with its source.

The other SecretSpace repositories (the Windows and Linux clients and sync servers)
are free software under the same licence.

The 12-word recovery phrase uses the BIP39 English word list from
[bitcoin/bips](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt).

Security issues: please report them privately, see [SECURITY.md](SECURITY.md).
