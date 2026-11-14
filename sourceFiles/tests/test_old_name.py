"""
The project was called PassMan until November 2026. In the program the old
name may stay in exactly these places:

* ``legacy_names.py`` -- the one module that holds the names an older
  version wrote, so they can be read and converted;
* the sentences that say why (listed below, one per place);
* the installer's clean-up of an older install.

Anything else is a leftover of the rename, and this test names the line. It
also checks the other half of the rule: the old names are read, and written
only where the format requires it.
"""

import os
import re

import account_crypto
import legacy_names

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.dirname(HERE)
REPO = os.path.dirname(SOURCE)
OLD = re.compile(r"passman|PMV[23]|PMK3|\.pmk|\.pmv3", re.IGNORECASE)

#: (file, text the line contains): prose and clean-up, nothing a key or a
#: file of the current format is made with.
ALLOWED = [
    ("account_crypto.py", "when the project was still called PassMan"),
    ("crypto_utils.py", "from when the project was called PassMan"),
    ("version.py", 'OLDER_VAULT_FORMATS = ("PMV3", "PMV2")'),
    ("SecretSpace.iss", "rename (as PassMan) has them in %APPDATA%\\PassMan"),
    ("SecretSpace.iss", 'Name: "{app}\\PassMan.exe"'),
    ("SecretSpace.iss", 'Name: "{autoprograms}\\PassMan.lnk"'),
    ("SecretSpace.iss", 'Name: "{autodesktop}\\PassMan.lnk"'),
    ("SecretSpace.iss", "OldHome := ExpandConstant('{userappdata}\\PassMan');"),
    ("SecretSpace.iss", "called PassMan then), Setup can move"),
]


def program_files():
    """Every text file the program is built from (not tests, not docs)."""
    found = []
    for folder in (SOURCE, os.path.join(REPO, "builder"),
                   os.path.join(REPO, "installer")):
        if not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            path = os.path.join(folder, name)
            if os.path.isfile(path) and name.endswith(
                    (".py", ".iss", ".spec", ".desktop", ".txt", ".toml")) \
                    or name == "installed":
                found.append(path)
    return found


def test_the_old_name_is_only_where_it_is_allowed():
    leftovers = []
    for path in program_files():
        name = os.path.basename(path)
        if name == "legacy_names.py":
            continue
        if OLD.search(name):
            leftovers.append(f"{name}: the file's own name")
        with open(path, encoding="utf-8") as f:
            for number, line in enumerate(f, 1):
                if OLD.search(line) and not any(
                        name == allowed and text in line
                        for allowed, text in ALLOWED):
                    leftovers.append(f"{name}:{number}: {line.strip()}")
    assert leftovers == []


def test_every_allowed_line_is_still_there():
    """An allowance for a line that is gone is a hole in the rule."""
    for name, text in ALLOWED:
        path = next(p for p in program_files() if os.path.basename(p) == name)
        with open(path, encoding="utf-8") as f:
            assert text in f.read(), (name, text)


def test_legacy_names_is_only_names():
    """Strings and bytes, no code and no imports: nothing can be done with
    the old names by accident."""
    with open(os.path.join(SOURCE, "legacy_names.py"), encoding="utf-8") as f:
        text = f.read()
    assert "import " not in text.split('"""', 2)[2]
    assert "def " not in text and "class " not in text
    for name, value in vars(legacy_names).items():
        if not name.startswith("_"):
            assert isinstance(value, (str, bytes)), name


def test_nothing_else_spells_the_old_labels():
    """The old format's labels come from legacy_names through
    account_crypto.OLD and from nowhere else."""
    assert account_crypto.OLD.prefix == legacy_names.LABEL_PREFIX
    assert account_crypto.OLD.keyset_magic == legacy_names.KEYSET_MAGIC
    assert account_crypto.OLD.vault_magic == legacy_names.VAULT_MAGIC
    assert account_crypto.OLD.secret_prefix == legacy_names.SECRET_KEY_PREFIX
    assert legacy_names.LABEL_PREFIX not in account_crypto.NOW.prefix


def test_the_current_format_is_the_default_everywhere():
    """A call that does not say which format gets the current one: writing
    the old format is always a decision made at the call."""
    import inspect
    for function in (account_crypto.derive_account_keys,
                     account_crypto.wrap_key, account_crypto.encrypt_vault,
                     account_crypto.seal_vault_name,
                     account_crypto.recovery_key):
        default = inspect.signature(function).parameters["fmt"].default
        assert default is account_crypto.NOW, function.__name__


def test_the_old_format_is_written_only_for_a_vault_someone_else_still_reads():
    """Which lines of the program can choose a format at all: each is about
    a vault's own format (``.fmt``, ``fmt`` from the members list), never a
    bare OLD -- except reading, converting, and the one place that picks the
    format for a key change."""
    allowed = {
        # reading and converting
        "account_crypto.py", "accounts.py",
        # the format of a key change, decided from the members' accounts
        "account_sync.py",
    }
    bad = []
    for path in program_files():
        name = os.path.basename(path)
        if name in allowed or not name.endswith(".py"):
            continue
        with open(path, encoding="utf-8") as f:
            for number, line in enumerate(f, 1):
                if re.search(r"account_crypto\.OLD\b|\bOLD\.label|"
                             r"legacy_names\.(LABEL_PREFIX|KEYSET_MAGIC|"
                             r"VAULT_MAGIC)\b", line):
                    bad.append(f"{name}:{number}: {line.strip()}")
    assert bad == []
