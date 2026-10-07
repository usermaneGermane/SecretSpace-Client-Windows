import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    """Point every test at a throwaway vault directory."""
    monkeypatch.setenv("PASSMAN_DATA_DIR", str(tmp_path / "data"))
    return tmp_path / "data"
