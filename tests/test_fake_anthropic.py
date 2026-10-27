import pytest


def test_fake_anthropic_returns_scripted_responses_in_order_and_records_requests(fake_anthropic):
    script = ["first", "second"]
    fake = fake_anthropic(script)
    assert fake.beta.messages.create(model="claude-sonnet-5-5", max_tokens=10) == "first"
    assert fake.beta.messages.create(model="claude-sonnet-5-5", max_tokens=20) == "second"
    assert script == ["first", "second"]
    assert fake.requests == [
        {"model": "claude-sonnet-5-5", "max_tokens": 10},
        {"model": "claude-sonnet-5-5", "max_tokens": 20},
    ]


def test_fake_anthropic_raises_scripted_exceptions(fake_anthropic):
    fake = fake_anthropic([TimeoutError("scripted"), "after"])
    with pytest.raises(TimeoutError, match="scripted"):
        fake.beta.messages.create(model="m")
    assert fake.beta.messages.create(model="m") == "after"
    assert len(fake.requests) == 2


def test_fake_anthropic_refuses_a_scripted_exception_class(fake_anthropic):
    fake = fake_anthropic([TimeoutError])
    with pytest.raises(pytest.fail.Exception, match="script an exception instance, not the class TimeoutError"):
        fake.beta.messages.create(model="m")


def test_fake_anthropic_records_a_snapshot_of_each_request(fake_anthropic):
    fake = fake_anthropic(["reply"])
    messages = [{"role": "user", "content": "task"}]
    fake.beta.messages.create(model="m", messages=messages)
    messages.append({"role": "assistant", "content": "reply"})
    assert fake.requests[0]["messages"] == [{"role": "user", "content": "task"}]


def test_fake_anthropic_fails_the_test_on_an_unscripted_request(fake_anthropic):
    fake = fake_anthropic([])

    def swallowing_caller():
        try:
            fake.beta.messages.create(model="m")
        except Exception:
            return "swallowed"

    with pytest.raises(pytest.fail.Exception, match="request 1 has no scripted response"):
        swallowing_caller()
