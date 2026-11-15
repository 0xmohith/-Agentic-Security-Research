from types import SimpleNamespace

import groq
import httpx
import pytest

import experiments.groq_provider as groq_provider
from experiments.groq_provider import (
    DEFAULT_GROQ_MODEL,
    GROQ_API_BASE_URL,
    GroqAPIError,
    GroqAttackerProvider,
    GroqAuthenticationError,
    GroqModelUnavailableError,
    GroqNetworkError,
    GroqProviderConfig,
    GroqRateLimitError,
    GroqResponseError,
    GroqTimeoutError,
    MissingGroqAPIKeyError,
)


def _response(
    *,
    content="Harmless connectivity response.",
    choices=None,
):
    if choices is None:
        choices = [SimpleNamespace(message=SimpleNamespace(content=content))]
    return SimpleNamespace(
        choices=choices,
        id="response-fixture",
        model=DEFAULT_GROQ_MODEL,
        created=123456,
        system_fingerprint="fingerprint-fixture",
        usage=SimpleNamespace(
            prompt_tokens=8,
            completion_tokens=4,
            total_tokens=12,
            queue_time=0.01,
        ),
    )


class _FakeCompletions:
    def __init__(self, *, response=None, error=None):
        self.response = response
        self.error = error
        self.request = None

    def create(self, **kwargs):
        self.request = kwargs
        if self.error is not None:
            raise self.error
        return self.response


class _FakeGroq:
    def __init__(self, *, completions, **kwargs):
        self.constructor = kwargs
        self.chat = SimpleNamespace(completions=completions)


def _install_fake_client(monkeypatch, *, response=None, error=None):
    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-a-secret")
    completions = _FakeCompletions(response=response, error=error)
    clients = []

    def fake_groq(**kwargs):
        client = _FakeGroq(completions=completions, **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(groq_provider, "Groq", fake_groq)
    return completions, clients


def _status_error(error_type, status_code):
    request = httpx.Request("POST", GROQ_API_BASE_URL)
    response = httpx.Response(status_code, request=request)
    return error_type(
        "mock provider error",
        response=response,
        body={"error": {"message": "mock provider error"}},
    )


def test_groq_provider_sends_configured_request_and_returns_safe_metadata(
    monkeypatch,
):
    completions, clients = _install_fake_client(
        monkeypatch,
        response=_response(),
    )
    config = GroqProviderConfig(
        model_id="openai/gpt-oss-20b",
        temperature=0.7,
        timeout_seconds=12.5,
        max_tokens=256,
    )
    result = GroqAttackerProvider(config).complete(
        "Reply with a short greeting.",
        system_prompt="You are a benign connectivity test.",
    )

    assert result.text == "Harmless connectivity response."
    assert clients[0].constructor == {
        "api_key": "test-key-not-a-secret",
        "base_url": GROQ_API_BASE_URL,
        "timeout": 12.5,
        "max_retries": 0,
    }
    assert completions.request == {
        "model": "openai/gpt-oss-20b",
        "messages": [
            {"role": "system", "content": "You are a benign connectivity test."},
            {"role": "user", "content": "Reply with a short greeting."},
        ],
        "temperature": 0.7,
        "max_completion_tokens": 256,
    }
    assert result.metadata["provider"] == "groq"
    assert result.metadata["request_model"] == "openai/gpt-oss-20b"
    assert result.metadata["temperature"] == 0.7
    assert result.metadata["request_timestamp"]
    assert result.metadata["response"] == {
        "id": "response-fixture",
        "model": DEFAULT_GROQ_MODEL,
        "created": 123456,
        "system_fingerprint": "fingerprint-fixture",
    }
    assert result.metadata["usage"] == {
        "prompt_tokens": 8,
        "completion_tokens": 4,
        "total_tokens": 12,
        "queue_time": 0.01,
    }
    assert "test-key-not-a-secret" not in repr(result.metadata)


def test_groq_provider_requires_only_groq_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-used")

    with pytest.raises(MissingGroqAPIKeyError, match="GROQ_API_KEY"):
        GroqAttackerProvider()


def test_groq_provider_defaults_match_selected_attacker_configuration():
    config = GroqProviderConfig()

    assert config.model_id == "openai/gpt-oss-20b"
    assert config.temperature == 0.7
    assert config.timeout_seconds == 30.0
    assert config.max_tokens == 1024


@pytest.mark.parametrize(
    ("error", "expected_error"),
    [
        (
            _status_error(groq.AuthenticationError, 401),
            GroqAuthenticationError,
        ),
        (
            _status_error(groq.PermissionDeniedError, 403),
            GroqAuthenticationError,
        ),
        (
            _status_error(groq.NotFoundError, 404),
            GroqModelUnavailableError,
        ),
        (
            groq.BadRequestError(
                "mock model error",
                response=httpx.Response(
                    400,
                    request=httpx.Request("POST", GROQ_API_BASE_URL),
                ),
                body={
                    "error": {
                        "code": "model_decommissioned",
                        "message": "mock model error",
                    },
                },
            ),
            GroqModelUnavailableError,
        ),
        (
            _status_error(groq.RateLimitError, 429),
            GroqRateLimitError,
        ),
        (
            _status_error(groq.BadRequestError, 400),
            GroqAPIError,
        ),
        (
            _status_error(groq.APIStatusError, 503),
            GroqAPIError,
        ),
        (
            groq.APITimeoutError(
                httpx.Request("POST", GROQ_API_BASE_URL)
            ),
            GroqTimeoutError,
        ),
        (
            groq.APIConnectionError(
                request=httpx.Request("POST", GROQ_API_BASE_URL)
            ),
            GroqNetworkError,
        ),
    ],
)
def test_groq_provider_maps_sdk_failures_without_exposing_error_details(
    monkeypatch,
    error,
    expected_error,
):
    _install_fake_client(monkeypatch, error=error)
    provider = GroqAttackerProvider()

    with pytest.raises(expected_error) as raised:
        provider.complete("Harmless prompt.")

    assert "mock provider error" not in str(raised.value)
    assert "test-key-not-a-secret" not in str(raised.value)


@pytest.mark.parametrize(
    "response",
    [
        SimpleNamespace(choices=[]),
        SimpleNamespace(choices=None),
        SimpleNamespace(choices=[SimpleNamespace(message=None)]),
        SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=None))]
        ),
        SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="  "))]
        ),
    ],
)
def test_groq_provider_rejects_empty_or_malformed_responses(monkeypatch, response):
    _install_fake_client(monkeypatch, response=response)

    with pytest.raises(GroqResponseError):
        GroqAttackerProvider().complete("Harmless prompt.")


@pytest.mark.parametrize(
    "override",
    [
        {"model_id": ""},
        {"temperature": -0.1},
        {"temperature": float("nan")},
        {"timeout_seconds": 0},
        {"max_tokens": 0},
        {"max_tokens": True},
    ],
)
def test_groq_provider_configuration_rejects_invalid_values(override):
    with pytest.raises(ValueError):
        GroqProviderConfig(**override)
