"""Optional OpenShell receipts under the active Relay model call."""

from __future__ import annotations

from functools import partial
import logging
from uuid import UUID

from .sandbox_hook import active

log = logging.getLogger("openshell.relay_receipts")


def register(ctx) -> None:
    if not active() or ctx.get_config("relay_receipts", False) is not True:
        return
    try:
        import nemo_relay
    except ImportError:
        log.warning("OpenShell Relay receipts require NeMo Relay with active-scope and mark APIs")
        return
    required = ("scope_stack_active", "capture_propagation_context", "fork_scope_stack", "use_scope_stack")
    if not all(callable(getattr(nemo_relay, name, None)) for name in required) or not callable(
        getattr(getattr(nemo_relay, "scope", None), "event", None)
    ):
        log.warning("OpenShell Relay receipts require NeMo Relay with active-scope and mark APIs")
        return
    ctx.register_hook("llm_http_response", partial(_record_receipt, nemo_relay))


def _record_receipt(relay, *, status_code: int, get_header, **_) -> None:
    try:
        request_id = get_header("x-openshell-request-id")
        if type(status_code) is not int or not 100 <= status_code <= 599:
            return
        if not isinstance(request_id, str) or len(request_id) != 36 or str(UUID(request_id)) != request_id:
            return
        if not relay.scope_stack_active() or not relay.capture_propagation_context().traceparent:
            return
        # Managed calls carry an active event outside the lexical scope stack.
        with relay.use_scope_stack(relay.fork_scope_stack()):
            relay.scope.event("openshell.request.receipt", data={"request_id": request_id, "http_status": status_code})
    except Exception:
        # Observability must not change the model request's outcome.
        return
