import copy
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
