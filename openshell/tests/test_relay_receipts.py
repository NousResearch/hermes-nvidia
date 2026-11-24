"""The plugin selects receipt metadata without owning a model HTTP client."""

from __future__ import annotations

import asyncio
import builtins
import sys
from types import SimpleNamespace

import pytest

from openshell import relay_receipts

RECEIPT = "7d2ef4cb-fcae-45fd-9880-deef74880df5"


class Context:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.hooks = {}

    def get_config(self, key, default=None):
        return self.enabled if key == "relay_receipts" else default

    def register_hook(self, name, callback):
        self.hooks[name] = callback


@pytest.mark.parametrize("inside,enabled", [(False, True), (True, False), (True, "true")])
def test_disabled_receipts_do_not_import_relay(monkeypatch, inside, enabled):
    monkeypatch.setattr(relay_receipts, "active", lambda: inside)
    original = builtins.__import__

    def importing(name, *args, **kwargs):
        assert name != "nemo_relay", "disabled receipts must not import Relay"
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", importing)
    ctx = Context(enabled)
    relay_receipts.register(ctx)
    assert not ctx.hooks


@pytest.mark.parametrize("module", [None, SimpleNamespace(scope=SimpleNamespace(event=lambda: None))])
def test_missing_or_incompatible_relay_warns_without_registering(monkeypatch, caplog, module):
    monkeypatch.setattr(relay_receipts, "active", lambda: True)
    monkeypatch.setitem(sys.modules, "nemo_relay", module)
    ctx = Context()
    relay_receipts.register(ctx)
    assert not ctx.hooks
    assert "require NeMo Relay with active-scope and mark APIs" in caplog.text


@pytest.fixture
def observer(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    import nemo_relay

    monkeypatch.setitem(sys.modules, "nemo_relay.integrations.openshell", None)
    monkeypatch.setattr(relay_receipts, "active", lambda: True)
    ctx, events = Context(), []
    relay_receipts.register(ctx)
    nemo_relay.subscribers.register("openshell.receipt-test", events.append)
    try:
        yield nemo_relay, ctx.hooks["llm_http_response"], events
    finally:
        nemo_relay.subscribers.flush()
        nemo_relay.subscribers.deregister("openshell.receipt-test")


def run_model(relay, callback):
    def provider(request):
        callback()
        return {"ok": True}

    async def execute():
        return await relay.llm.execute("model", relay.LLMRequest({}, {}), provider)

    with relay.use_scope_stack(relay.create_scope_stack()):
        with relay.scope.scope("agent", relay.ScopeType.Agent):
            return asyncio.run(execute())


def test_receipt_uses_real_model_parent_and_only_requests_one_header(observer):
    relay, observe, events = observer
    requested = []

    def header(name):
        requested.append(name)
        return RECEIPT

    run_model(relay, lambda: observe(status_code=403, get_header=header))
    relay.subscribers.flush()
    mark, = [event for event in events if event.name == "openshell.request.receipt"]
    model = next(event for event in events if event.name == "model" and event.scope_category == "start")
    assert mark.parent_uuid == model.uuid
    assert mark.data == {"request_id": RECEIPT, "http_status": 403}
    assert requested == ["x-openshell-request-id"]


def test_invalid_receipts_and_observation_failures_do_not_change_model_result(observer, monkeypatch):
    relay, observe, events = observer

    def response():
        for value, status in [(None, 200), ("bad-id", 200), (RECEIPT.upper(), 200),
                              (RECEIPT, 99), (RECEIPT, True)]:
            observe(status_code=status, get_header=lambda name: value)
        with monkeypatch.context() as patch:
            def unavailable(*args, **kwargs):
                raise RuntimeError("observer unavailable")
            patch.setattr(relay.scope, "event", unavailable)
            observe(status_code=200, get_header=lambda name: RECEIPT)

    assert run_model(relay, response) == {"ok": True}
    relay.subscribers.flush()
    assert not [event for event in events if event.name == "openshell.request.receipt"]
    assert any(event.name == "model" and event.scope_category == "end" for event in events)


def test_no_active_context_does_not_create_a_relay_trace(observer):
    relay, observe, events = observer
    assert not relay.scope_stack_active()
    observe(status_code=200, get_header=lambda name: RECEIPT)
    relay.subscribers.flush()
    assert not events
