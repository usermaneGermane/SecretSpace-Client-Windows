"""The small display helpers behind the redesigned list and login tiles."""

from datetime import datetime, timezone

import gui
import history_ui
import theme


def test_short_when_today_shows_the_time():
    now = datetime(2026, 10, 28, 15, 0, tzinfo=timezone.utc)
    stamp = "2026-10-28T09:41:00Z"
    local = datetime(2026, 10, 28, 9, 41, tzinfo=timezone.utc).astimezone()
    assert history_ui.short_when(stamp, now=now) == local.strftime("%H:%M")


def test_short_when_this_year_shows_day_and_month():
    now = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
    assert history_ui.short_when("2026-03-05T12:00:00Z", now=now) == "5 Mar"


def test_short_when_older_shows_month_and_year():
    now = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
    assert history_ui.short_when("2024-07-14T12:00:00.123456Z",
                                 now=now) == "Jul 2024"


def test_short_when_bad_stamp_is_blank():
    assert history_ui.short_when("") == ""
    assert history_ui.short_when(None) == ""
    assert history_ui.short_when("yesterday") == ""


def test_initials():
    assert gui._initials("alex.morgan") == "AM"
    assert gui._initials("studio_work") == "SW"
    assert gui._initials("test") == "TE"
    assert gui._initials("x") == "X"


def test_clip():
    assert gui._clip("github.com", 30) == "github.com"
    assert gui._clip("a" * 40, 10) == "a" * 9 + "…"
    assert gui._clip(None, 5) == ""


def test_tile_colors_are_stable_and_from_the_palette():
    assert theme.tile_colors("github.com") == theme.tile_colors("github.com")
    assert theme.tile_colors("github.com") in theme.TILE_PALETTE
    assert theme.tile_colors("") == theme.TILE_PALETTE[0]
