"""A test run starts no browser and no other program of the user's (``no_real_apps``, wired in ``conftest.py``).

Nothing here may reach a real opener: every call goes through ``guarded``, which first checks that the entry point is
a replaced one, and the second pytest run below checks the same before each of its calls.
"""
import inspect
import os
import subprocess
import sys
import webbrowser
from pathlib import Path

import pytest

import no_real_apps

TESTS = Path(__file__).resolve().parent
ADDRESS = "https://sign-in.example.invalid/authorize?state=not-to-be-recorded"


def entry_points() -> list:
    points = [(f"webbrowser.{name}", webbrowser, name) for name in no_real_apps.BROWSER_ENTRIES]
    if hasattr(os, "startfile"):  # Windows
        points.append(("os.startfile", os, "startfile"))
    return points


def guarded(holder, name):
    """The entry point, once it is known to be a replaced one."""
    function = getattr(holder, name)
    assert getattr(function, "refuses_real_apps", False), f"{holder.__name__}.{name} is not replaced"
    return function


def test_every_test_runs_with_the_entry_points_replaced():
    for _label, holder, name in entry_points():
        guarded(holder, name)


@pytest.mark.parametrize("label, holder, name", entry_points(), ids=[point[0] for point in entry_points()])
def test_a_call_stops_the_test_and_is_recorded_without_the_address(real_apps_guard, label, holder, name):
    with pytest.raises(no_real_apps.StartedRealApp, match=label.replace(".", r"\.") + " was called"):
        guarded(holder, name)(ADDRESS)
    assert real_apps_guard.calls == [(label, "host sign-in.example.invalid")]
    assert "not-to-be-recorded" not in real_apps_guard.report()
    real_apps_guard.calls.clear()  # this test made the call on purpose


def test_a_file_is_recorded_by_its_name_only(real_apps_guard):
    with pytest.raises(no_real_apps.StartedRealApp):
        guarded(webbrowser, "open")(os.path.join("some", "folder", "report.html"))
    assert real_apps_guard.calls == [("webbrowser.open", "name report.html")]
    real_apps_guard.calls.clear()


def test_the_real_openers_are_refused_whoever_calls_them():
    """The audit events the real openers raise before they start anything: a test that put the real function back,
    or kept a browser object from before the run, still starts nothing."""
    assert no_real_apps.hooked()
    for event in no_real_apps.AUDITED:
        with pytest.raises(no_real_apps.StartedRealApp, match="reached the real opener"):
            no_real_apps.refuse_event(event, (ADDRESS, "open"))
        with pytest.raises(BaseException):  # this hook, or one the machine running the tests added before it
            sys.audit(event, ADDRESS)
    no_real_apps.refuse_event("subprocess.Popen", ("python", ["python"], None, None))  # other events pass


INNER = '''
import webbrowser


def replaced(function):
    assert getattr(function, "refuses_real_apps", False)
    return function


def test_calls_the_browser():
    replaced(webbrowser.open)("https://sign-in.example.invalid/authorize")


def test_swallows_what_the_browser_call_raised():
    try:
        replaced(webbrowser.open_new_tab)("https://sign-in.example.invalid/authorize")
    except BaseException:
        pass


def test_starts_nothing():
    assert True
'''


def test_a_test_that_calls_the_browser_fails_in_a_real_run(tmp_path):
    """A second pytest run under this folder's conftest: the test that calls the browser fails, the test that
    swallows the stop fails at its end, and the test that starts nothing passes."""
    (tmp_path / "test_inner.py").write_text(INNER, encoding="utf-8")
    # The second run finds this folder's conftest, the plugin and Hermes where this run found them.
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(dict.fromkeys([str(TESTS), *[entry for entry in sys.path if entry]])))
    done = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "test_inner.py", "-p", "conftest", "-p", "no:cacheprovider", "-q", "-rfE",
         f"--basetemp={tmp_path / 'base'}", f"--rootdir={tmp_path}"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=600)
    out = done.stdout + done.stderr
    assert done.returncode == 1, out
    assert "1 failed, 2 passed, 1 error" in out, out
    assert "FAILED test_inner.py::test_calls_the_browser" in out and "webbrowser.open was called" in out, out
    assert "ERROR test_inner.py::test_swallows_what_the_browser_call_raised" in out, out
    assert "the test called webbrowser.open_new_tab (host sign-in.example.invalid)" in out, out


def test_a_helper_in_a_python_of_its_own_is_guarded_by_install():
    code = ("import no_real_apps, webbrowser\n"
            "no_real_apps.install()\n"
            "assert webbrowser.open.refuses_real_apps\n"
            "webbrowser.open('https://sign-in.example.invalid/authorize')\n")
    done = subprocess.run([sys.executable, "-B", "-c", code], cwd=TESTS, capture_output=True, text=True, timeout=300)
    assert done.returncode != 0, done.stdout + done.stderr
    assert "StartedRealApp" in done.stderr and "webbrowser.open was called" in done.stderr, done.stderr


def test_the_sign_in_helper_process_installs_the_guard_before_anything_else():
    import signin_home

    body = inspect.getsource(signin_home.main)
    assert body.index("no_real_apps.install()") < body.index("signin_issuers.redirect(")
