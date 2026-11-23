"""Windows only. A second process for ``test_schedule_thread_and_the_loop.py``: the launcher's event loop with one
forwarded request whose client has gone, beside a thread that does what the sign-in schedule's thread does towards
the loop, with a garbage collection on that thread after every round.

What ends a launcher's loop on Windows is a stream closed from a thread that is not the loop's while its read is
pending: the cancel of the pending read on one thread races the loop taking the aborted completion on the other.
Here that order is forced, not waited for: the two functions of asyncio's Windows loop that take part are wrapped
so that an off-loop cancel always lands between the loop's check and its ``set_exception``. Every cancel of a
pending read made off the loop's thread is counted.

``held``: the handler's task is held while it runs, as the launcher's proxy holds every connection's task.
``unheld``: nothing holds it, the shape that let a collection on another thread close its streams.

Prints one JSON line. Usage: loop_thread_probe.py held|unheld
"""
import asyncio
import gc
import json
import socket
import sys
import threading

ROUNDS = 40


def main(mode: str) -> int:
    import asyncio.windows_events as we

    from openshell import launcher_cli

    loop_thread = threading.current_thread()
    in_callback, cancelled = threading.Event(), threading.Event()
    seen = {"armed": False, "off_loop": 0, "by": set()}
    plain_cancel, plain_register = we._OverlappedFuture.cancel, we.IocpProactor._register

    def cancel(self, msg=None):
        off_loop = threading.current_thread() is not loop_thread and seen["armed"] and self._ov is not None
        self._cancel_overlapped()
        if off_loop:
            seen["off_loop"] += 1
            seen["by"].add(threading.current_thread().name)
            in_callback.wait(5)  # the loop's thread is now between its check and its set_exception
        result = asyncio.Future.cancel(self, msg=msg)
        if off_loop:
            cancelled.set()
        return result

    def register(self, ov, obj, callback):
        def waiting(trans, key, ov_):
            try:
                return callback(trans, key, ov_)
            except OSError:
                if seen["armed"] and threading.current_thread() is loop_thread:
                    in_callback.set()
                    cancelled.wait(5)
                raise
        return plain_register(self, ov, obj, waiting)

    we._OverlappedFuture.cancel = cancel
    we.IocpProactor._register = register
    sys.unraisablehook = lambda unraisable: None
    held, notes, asked_on = set(), set(), set()

    async def backend(reader, writer):
        """The sandboxed backend: takes the request and does not answer yet."""
        await reader.read(100)
        await asyncio.sleep(60)

    async def handler(reader, writer):
        """Shaped like the launcher's connection handler: forward, then close and wait in ``finally``."""
        if mode == "held":
            task = asyncio.current_task()
            held.add(task)
            task.add_done_callback(held.discard)
        up_writer = None
        try:
            await reader.readuntil(b"\n")
            up_reader, up_writer = await asyncio.open_connection("127.0.0.1", handler.backend_port)
            up_writer.write(b"x\n")
            await up_reader.read(100)  # the backend has not answered: this read is pending
        finally:
            if up_writer is not None:
                up_writer.close()
            writer.close()
            await writer.wait_closed()

    async def scenario() -> dict:
        loop = asyncio.get_running_loop()
        up = await asyncio.start_server(backend, "127.0.0.1", 0)
        handler.backend_port = up.sockets[0].getsockname()[1]
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        client = socket.create_connection(("127.0.0.1", server.sockets[0].getsockname()[1]))
        client.sendall(b"go\n")
        client.close()  # the client leaves while its request waits for the backend
        await asyncio.sleep(0.5)

        def question() -> bool:
            asked_on.add(threading.current_thread().name)
            return True

        ask = launcher_cli._asked_on_loop(loop, question)  # how the schedule asks whether a reply is streaming

        async def note() -> None:
            await asyncio.sleep(0.01)

        def say() -> None:  # how the schedule hands the launcher a note for the chat
            def start() -> None:
                task = asyncio.ensure_future(note())
                notes.add(task)
                task.add_done_callback(notes.discard)
            loop.call_soon_threadsafe(start)

        done, out = threading.Event(), {"rounds": 0}

        def schedule() -> None:
            try:
                for _ in range(ROUNDS):
                    out["quiet"] = ask()
                    say()
                    gc.collect()  # a collection on this thread, where the schedule's own allocations would cause one
                    out["rounds"] += 1
            except BaseException as exc:
                out["error"] = type(exc).__name__
            finally:
                done.set()

        seen["armed"] = True
        threading.Thread(target=schedule, name="sign-ins", daemon=True).start()
        while not done.is_set():
            await asyncio.sleep(0.02)
        await asyncio.sleep(0.3)
        return out

    result = {"mode": mode}
    try:
        result["schedule"] = asyncio.run(scenario())
        result["loop"] = "survived"
    except BaseException as exc:
        result["loop"] = "died: " + type(exc).__name__
    result.update(cancels_off_the_loop=seen["off_loop"], by=sorted(seen["by"]), asked_on=sorted(asked_on))
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
