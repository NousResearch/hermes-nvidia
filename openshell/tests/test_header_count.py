"""The Sandbox page's header counts every destination the page lists: the user's own and the ones the launcher
keeps open by itself (launcher/usage_data.py). The launcher's status carries the built-in list for it, the same
list the page's rows come from."""
import asyncio

import test_openshell_driver as LD
from openshell.launcher.settings_view import config_payload
from openshell.launcher.spec import load_spec
from test_usage_data import ON, ROW, answers

PYPI = {"host": "pypi.org", "port": 443}


def _rows(sup, layout):
    return config_payload(layout, load_spec(layout), sup.driver.capabilities(), sandboxed=True,
                          restart_required=False, resolve=lambda host: [])["builtin"]


def test_the_status_names_the_built_in_destinations_the_page_lists(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch, network={"egress": "deny", "allow": [PYPI]})
    answers(layout.home, **ON)

    async def scenario():
        assert sup.status()["builtin"] == []  # no sandbox runs: the header shows no summary
        await sup.start()
        try:
            status = sup.status()
            assert status["builtin"] == [ROW] == _rows(sup, layout)
            assert status["applied"]["network"]["allow"] == [PYPI]  # the user's own list is not touched by it
            assert not status["restart_required"] and status["pending"] == {"folders": False, "network": False,
                                                                           "keys": False}
            answers(layout.home, enabled=False, send=False)  # sharing turned off: the row and the count go together
            assert sup.status()["builtin"] == [] == _rows(sup, layout)
        finally:
            await sup.stop()
        assert sup.status()["builtin"] == []

    asyncio.run(scenario())


def test_a_profile_that_shares_nothing_has_no_built_in_destination_in_its_status(tmp_path, monkeypatch):
    sup, api, rec, layout = LD._supervisor(tmp_path, monkeypatch, network={"egress": "deny", "allow": [PYPI]})

    async def scenario():
        await sup.start()
        try:
            assert sup.status()["builtin"] == [] == _rows(sup, layout)
        finally:
            await sup.stop()

    asyncio.run(scenario())
