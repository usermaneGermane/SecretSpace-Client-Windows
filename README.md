# SecretSpace for Windows

A local desktop password manager for Windows. Your vault is a single
AES-256-GCM encrypted file. There is no online account and no service behind it: it
works entirely offline, and if you want two PCs in step you run the sync
server yourself, on your own hardware.

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

## SecretSpace 3 — a test version, not for real passwords yet

`main` is now **3.0.0-alpha.4**, a test step of SecretSpace 3. **For your real
passwords keep using [2.13.0](https://github.com/usermaneGermane/SecretSpace-Client-Windows/releases/tag/v2.13.0)**,
which the rest of this README describes. Do not install the test version
over it: it opens SecretSpace 3 accounts only, so your 2.x vaults would not
show up (they are not changed or deleted — 2.13.0 opens them again).

What the test version has:

- **Accounts instead of vault files.** *Create an account* asks for a name
  and a master password, then shows your **Emergency Kit** (a *Secret Key*,
  `A3-XXXXX-…`) and a **12-word recovery phrase**, which you type three
  words of back. Nothing is written until that last step.
- **A stronger lock.** The key comes from your master password *and* the
  Secret Key, through Argon2id (64 MiB, memory-hard) instead of PBKDF2. A
  stolen copy of the account folder cannot be opened by guessing the
  password alone on another PC.
- **The Secret Key is typed once per PC.** This PC keeps it, protected by
  Windows (DPAPI) for your Windows user. Copy the account folder to another
  PC and that PC asks for the Secret Key once, from the Emergency Kit.
- **Importing a 2.x vault.** *Import* lists the 2.x vaults on this PC (or
  takes a `.vault.enc` file) and copies every entry with its history and
  archive state. The 2.x file is only read; its sync settings stay with it.
- **A smoother look** (new in alpha.4). Rounded corners are drawn smoothed
  instead of in pixel steps, the sign-in screen's padlock and key are
  redrawn, and an entry's coloured header has room around its tile.
- **Sync through your own server** (new in alpha.3). *Settings → Sync →
  Set up…* puts the account on a SecretSpace Server **2.0** (a test version
  too) with the server's token as the sign-up code; after that the **Sync**
  button keeps the vault in step, with the same merge and conflict choices
  as 2.x. On another device, *Sign in from a server* on the login screen
  asks for the address, your username and master password and — once per
  device — the Secret Key. The server stores only what it cannot open: no
  master password, no Secret Key, no vault key. A master password changed
  on one device is changed on the server at the same time (it needs the
  server to be reachable); other devices then sign in again with it.
- Everything else in the window — entries, archive, history, 2FA codes,
  generator, plain export — works as in 2.12.

Not in this test version yet: more than one vault per account,
recovering an account with the 12-word phrase (the phrase is made and
checked now; the screen that uses it comes later), sharing a vault with
other people, and *Sync when I unlock* for accounts. SecretSpace for Linux
has the same test version, 1.0.0-alpha.4. Coming next, in this order:
several vaults per account, sharing a vault with family or colleagues, and
recovering an account with the 12-word phrase.

## Running it

The repository does not contain the app itself. Download
`SecretSpace-Client-Installer.exe` from the release marked **Latest** on the
[Releases](https://github.com/usermaneGermane/SecretSpace-Client-Windows/releases) page (a
*Pre-release* is a test version and has the same file name), or build it
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

Your passwords do **not** travel with the installer. The vault lives in
`%APPDATA%\SecretSpace`, so a fresh install on a new PC starts empty. To bring
your logins across, use *Restore from server* if you sync, or copy
`vault\<user>.vault.enc` into `%APPDATA%\SecretSpace\vault` on the new PC, or
use Settings → *Encrypted backup* → *Save backup…* and copy that file over. The backup is still protected by
your master password.

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
The server keeps one vault per username, so lab vaults must have **names
your real vaults do not use** (e.g. `test`, `lab-alice`): a lab vault with
the same name as a real one would sync into it.

**Moving test vaults out of production.** Uninstalling keeps the vaults, so
`%APPDATA%\SecretSpace\vault` may still hold vaults you made while testing. With
SecretSpace closed, move each `<user>.vault.enc` together with its `.bak` and
`.base` into the lab copy's `vault` folder (and `config.json` too, if it
names a test vault as the last user).

### SecretSpace 3 (test version)

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

## Upgrading from an earlier build

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

## Syncing two PCs

Point both PCs at a server you run — [SecretSpace-Server-Windows](https://github.com/usermaneGermane/SecretSpace-Server-Windows) or [SecretSpace-Server-Linux](https://github.com/usermaneGermane/SecretSpace-Server-Linux) says how to set one
up — then press **Sync**. The vault is encrypted before it leaves
your machine, so the server stores ciphertext it has no key for and never sees
your master password.

- **First PC:** Settings → Sync, enter the address and token, press **Save &
  sync**. It checks the connection first and only stores the settings once
  the server has answered, so a typo in the address cannot leave you thinking
  sync is set up when it is not. *Save only* stores them without contacting
  anything, for when the server cannot be reached right now; *Test
  connection* checks without syncing and tells you whether the next sync will
  upload or merge.
- **Second PC:** *Restore from server* on the login screen pulls the vault
  down. After that, Sync on either machine.

**Sync when I unlock.** Sync is manual unless you switch this on, in
Settings → Sync once sync is set up (off by default). With it on, SecretSpace
syncs right after you unlock; a conflict still waits for your choice, and a
server that cannot be reached only shows a warning — the vault opens either
way. The switch is per vault and per PC: a merge keeps this PC's choice,
and a vault restored onto a new PC starts with it off.

Sync merges per entry. A change made on only one PC is taken
silently — there is nothing to decide. Only when the **same entry changed on
both** PCs since they last synced do you get a dialog showing both versions
side by side, and **whichever side you do not keep is saved in that entry's
history** — every outcome is reversible with one click on *Revert*.
Cancelling it changes nothing on either side.

**More than one vault.** Each SecretSpace user syncs as its own, independent vault
on the server, matched across PCs by username (exactly, including case). Set
up sync once per vault, while that vault is unlocked; Sync only ever syncs
the vault that is open.

**If the server's address changes**, update it in Settings → Sync on every
PC — once per vault, because the address is stored inside each vault. Keep
the token as it is. A DHCP reservation for the server in your router stops
this happening by surprise.

**Syncing one vault with more than one server** (say a Windows and a Linux
server) works, but the two hold separate copies. From 2.5.0, the first sync
after you switch the address is treated like a first sync: nothing on this PC
is deleted or reverted because the other server has an older copy. Anything
it lacks is uploaded to it, and an entry that differs between the two comes
up in the conflict dialog for you to choose. The same happens if a server is
restored from an older backup. (Up to 2.4.0, such a switch could silently
remove entries the other server never had, and bring back older passwords.)

**A live entry that is missing from the server** is never removed without
asking. Deleting goes through the Archive (below), so an entry that is still
in use here but gone from the server means the server holds an older or
different copy. The conflict dialog shows it; keeping it (the default)
uploads it again, and choosing the server's side moves it to the Archive.

### Changing the master password of a vault you sync

Change it as usual in Settings → *Master password* → *Change…*. On that PC:

- the vault, its backup and its sync state are re-encrypted, and
- **the server is updated straight away**, merging anything your other PCs
  sent first. The option to delete the server's older copies is ticked by
  default, because those copies still open with the old password.

On each **other PC**, the next Sync says the password was changed on another
PC and asks for the new one. Enter it and that PC switches over: from then
on you unlock the vault there with the new password too. Anything it had not
synced yet is merged, not lost.

**Changed it while the server was unreachable?** Nothing is lost. The next
Sync on that PC asks once for your *previous* password, reads the server's
copy with it, and uploads everything under the new one.

**Changed it on two PCs before either synced?** Whichever reached the server
first wins. The other PC is asked for that password and switches to it.

This needs the server to be up to date — update it (see "Updating" in its
README) before changing a password.

To do it without a server at all, Syncthing or a USB stick work: both PCs
just need to see the same `vault` folder, and `PASSMAN_DATA_DIR` can point
the app at a network share.

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

- AES-256-GCM encryption with a PBKDF2-HMAC-SHA256 derived key
- Sync between machines through a server you host, with per-entry merging;
  by hand, or each time you unlock if you switch that on
- A black-and-green two-pane window: the entry list on the left, the
  selected entry's details (copy buttons, strength, notes, history) on the
  right; the login screen shows one tile per vault on this PC. Every dialog
  shares the look: a header band (with the site's tile when it is about an
  entry), settings grouped in cards, and the buttons in a bar at the bottom
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
- Encrypted backups, plus a plaintext export for migrating away
- Clipboard auto-clear, idle auto-lock, and a delay after repeated wrong
  master passwords

## Important: your master password cannot be recovered

*(2.11.)* In the 3.0 test version, the 12-word recovery phrase opens an
account without its master password — the screen for that arrives in a
later test version.

The master password *is* the encryption key. Nobody — including whoever wrote
this app — can decrypt your vault without it, and there is no reset, no
recovery code and no backdoor. If you forget it, the passwords are gone.

**Make backups.** Settings → *Encrypted backup* → *Save backup…* writes a copy that is
still protected by your master password, so it is safe to keep on another
drive or in cloud storage.

## Where your data lives

The files below are in `%APPDATA%\SecretSpace` (in `%APPDATA%\PassMan` if
that folder was there first, from before the rename). An installed copy is
recognised by the `installed` file that the installer puts next to its exe;
without it — running from source, or a portable exe from 2.2 or earlier —
they are next to the program instead.

| File | What it is |
| --- | --- |
| `vault/<user>.vault.enc` | your encrypted vault |
| `vault/<user>.vault.enc.bak` | the previous version, kept automatically |
| `vault/<user>.vault.enc.base` | what the server held at the last sync, and which server that was; only if you sync |
| `config.json` | non-secret preferences (last username, auto-lock delay) |

The 3.0 test version adds an `accounts` folder beside `vault`, and only
reads `vault`:

| File | What it is |
| --- | --- |
| `accounts/<name>/account.json` | nothing secret: the account's public key, its vault's id, the Secret Key as this PC keeps it (DPAPI) |
| `accounts/<name>/keyset.pmk` | the account's keys, under your master password + Secret Key (Argon2id, AES-256-GCM) |
| `accounts/<name>/recovery.pmk` | the same keys, under the 12-word recovery phrase |
| `accounts/<name>/vaults/<id>.pmv3` | your entries (+ `.bak`, the previous save) |

To back an account up, copy its folder (Settings → *Backup* → *Open
folder*); the copy opens only with the master password and the Secret Key.

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

*(2.x; the 3.0 container is below.)*

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

- **PBKDF2 is not memory-hard.** A memory-hard KDF (Argon2id, scrypt) resists
  GPU cracking better. The format header exists so that migration is possible
  without breaking anyone's vault.
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
- **The sync token is a single trust boundary.** Anyone holding it can read
  and overwrite every blob on your server. It is stored inside the vault,
  which is encrypted, rather than in `config.json`, which is not — but it is
  one shared secret, not per-user access control.
- **The sync server is not a backup.** It holds one copy of a file your PCs
  also hold, and it will happily store a vault you damaged. It does keep the
  last 20 revisions, which is a safety net, not a backup strategy.
- **Changing the master password does not re-lock existing copies.** Encrypted
  backups you saved and a vault on a lost USB stick still open with the
  password they were written under, and so does the server's history unless
  you leave *delete the older copies* ticked when you change it. If you
  change it because the old one leaked, change the passwords *inside* the
  vault too — starting with email and banking.
- **This has not been independently audited.**

## Versioning

The version shown in the UI lives in `version.py`. Bump `__version__` there on
release; `VAULT_FORMAT` tracks the on-disk container (`crypto_utils.MAGIC`) and
a test fails if the two drift apart.

Bump the **major** version when an older build can no longer safely use what
this one writes — even if the container stays `PMV2`, as in 2.0, where 1.x
would silently drop the new entry fields. New features that older builds
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

SecretSpace (this client) is free software under the **GNU General Public
License v3.0 only** (GPL-3.0-only) — see [LICENSE](LICENSE). You may use,
study, change and share it; if you distribute a changed version, it must stay
under the same licence, with its source.

The other SecretSpace repositories (the Windows and Linux clients and sync servers)
are free software under the same licence.

The 12-word recovery phrase uses the BIP39 English word list from
[bitcoin/bips](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt).

Security issues: please report them privately, see [SECURITY.md](SECURITY.md).
