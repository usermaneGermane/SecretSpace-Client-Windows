# A copy of the sync server, for the tests

`passman_server.py` here is an unchanged copy of `server/passman_server.py`
from the server repositories (SecretSpace-Server-Windows and SecretSpace-Server-Linux
hold the same file). `test_sync_server.py` runs it on a free port and syncs
two simulated PCs through it over a real socket, so the client is tested
against the real server rather than a mock.

The app never imports it, and the builder does not ship it.

When the server changes, copy the new file over this one, so that these
tests show whether the client still works with it.
