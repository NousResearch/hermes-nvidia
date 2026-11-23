"""The sign-in schedule's thread and the launcher's event loop on Windows (launcher_cli.py, supervisor.py).

A launcher on Windows once ended with ``InvalidStateError`` out of its event loop: a pending connection handler
was collected as garbage on a worker thread, its ``finally`` closed its streams there, and the cancel of the
pending read raced the loop. The proxy has held its connection tasks since, so a pending handler is never garbage.

The sign-in schedule runs in one more thread. What that thread does towards the loop is ask one question through
``call_soon_threadsafe`` and hand over notes the same way; it touches no stream, future or task of the loop. This
test runs exactly that beside a forwarded request whose client has gone, with a collection on the schedule's
thread after every round and the fatal order forced whenever a pending read is cancelled off the loop's thread
(``loop_thread_probe.py``). The control is the shape from before the proxy held its tasks: there the same thread's
collection does end the loop, which shows the probe can produce the failure.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="the proactor event loop is Windows's")

PROBE = Path(__file__).resolve().parent / "loop_thread_probe.py"


def _probe(mode: str) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys([str(PROBE.parent.parent.parent), *[p for p in sys.path if p]]))
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    done = subprocess.run([sys.executable, "-B", str(PROBE), mode], env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_schedules_thread_never_closes_a_stream_of_the_loop():
    out = _probe("held")
    assert out["loop"] == "survived" and out["cancels_off_the_loop"] == 0 and out["by"] == []
    assert out["schedule"] == {"rounds": 40, "quiet": True}
    assert out["asked_on"] == ["MainThread"], "the question was answered on another thread than the loop's"


def test_the_probe_ends_the_loop_when_a_pending_handler_is_garbage():
    """The control: without the proxy's rule the same thread's collection closes the handler's streams, and the
    forced order ends the loop the way the launcher ended."""
    out = _probe("unheld")
    assert out["cancels_off_the_loop"] >= 1 and out["by"] == ["sign-ins"]
    assert out["loop"] == "died: InvalidStateError"
