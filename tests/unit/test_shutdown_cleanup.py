"""ARCHITECTURE.md §4.8: a subprocess that's already gone must not abort cleanup of the
rest of the registry — that's the exact failure mode the shutdown handler exists to prevent."""

from typing import Any, cast

from services.gateway.session_manager import Session, SessionManager


class FakeProcess:
    def __init__(self, raise_on_terminate: bool = False) -> None:
        self.raise_on_terminate = raise_on_terminate
        self.terminated = False
        self.killed = False
        self.returncode: int | None = None

    def terminate(self) -> None:
        if self.raise_on_terminate:
            raise ProcessLookupError
        self.terminated = True
        self.returncode = 0

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    async def wait(self) -> int:
        return self.returncode if self.returncode is not None else 0


def make_manager_with(processes: list[FakeProcess]) -> SessionManager:
    manager = SessionManager(  # redis/policy/writer/cache unused by shutdown_all
        cast(Any, None), cast(Any, None), cast(Any, None), cast(Any, None)
    )
    for i, process in enumerate(processes):
        session = Session(
            id=f"s{i}",
            transport=cast(Any, None),
            process=cast(Any, process),
            interceptor=cast(Any, None),
        )
        manager._sessions[session.id] = session
    return manager


async def test_dead_subprocess_does_not_abort_cleanup_of_the_rest() -> None:
    dead = FakeProcess(raise_on_terminate=True)
    alive_after = [FakeProcess(), FakeProcess()]
    manager = make_manager_with([dead, *alive_after])

    await manager.shutdown_all()

    assert all(p.terminated for p in alive_after)


async def test_survivor_of_grace_period_is_killed() -> None:
    stubborn = FakeProcess()
    stubborn.terminate = lambda: None  # type: ignore[method-assign]  # ignores SIGTERM
    manager = make_manager_with([stubborn])

    await manager.shutdown_all()

    assert stubborn.killed
