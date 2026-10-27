import contextlib
import copy
import signal
from types import SimpleNamespace

import pytest


class FakeAnthropic:
    """Offline stand-in for the anthropic client whose `beta.messages.create` returns or raises scripted items in order.

    Each call's keyword arguments are deep-copied into `requests`, so later appends to a conversation cannot
    rewrite them.
    """

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(copy.deepcopy(kwargs))
        if not self.script:
            # pytest.fail raises a BaseException, so an `except Exception` in the code under test cannot swallow it.
            pytest.fail(f"request {len(self.requests)} has no scripted response")
        item = self.script.pop(0)
        if isinstance(item, type) and issubclass(item, BaseException):
            pytest.fail(f"script an exception instance, not the class {item.__name__}")
        if isinstance(item, BaseException):
            raise item
        return item


@pytest.fixture
def fake_anthropic():
    return FakeAnthropic


@pytest.fixture(autouse=True)
def tmp_runs_dir(tmp_path, monkeypatch):
    # Code that falls back to the default runs dir writes here, never into the repository's ./runs.
    monkeypatch.setenv("ASSESSOR_RUNS_DIR", str(tmp_path / "runs"))
    return tmp_path / "runs"


@pytest.fixture
def deadline():
    """Return a context manager that raises TimeoutError in its block once the given seconds have passed.

    A regex that turns super-linear then fails its test instead of hanging the suite; set the limit far above the run
    time of a linear scan, so that only a super-linear one can reach it.
    """

    @contextlib.contextmanager
    def within(seconds):
        def expire(signum, frame):
            raise TimeoutError(f"still running after {seconds} s")

        previous = signal.signal(signal.SIGALRM, expire)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    return within
